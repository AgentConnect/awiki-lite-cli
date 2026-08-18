import { URL } from 'node:url';

import WebSocket from 'ws';

import { CLIENT_IDENTIFIER } from '../version.js';

export const SYNC_SUBPROTOCOL = 'awiki.sync.changed.v2';
export const PING_INTERVAL_SECONDS = 60;
export const PING_TIMEOUT_SECONDS = 15;
export const HANDSHAKE_TIMEOUT_SECONDS = 15;
export const CLOSE_TIMEOUT_SECONDS = 10;
export const MAX_MESSAGE_BYTES = 1024 * 1024;
export const MAX_QUEUE_FRAMES = 128;
export const LISTENER_WS_OPTIONS = {
  pingIntervalMs: PING_INTERVAL_SECONDS * 1000,
  pingTimeoutMs: PING_TIMEOUT_SECONDS * 1000,
  handshakeTimeoutMs: HANDSHAKE_TIMEOUT_SECONDS * 1000,
  closeTimeoutMs: CLOSE_TIMEOUT_SECONDS * 1000,
  maxPayloadBytes: MAX_MESSAGE_BYTES,
  maxQueue: MAX_QUEUE_FRAMES,
  proxy: null,
} as const;
const SYNC_TOKEN = /^[a-z][a-z0-9._-]{0,63}$/;

export class ListenerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ListenerError';
  }
}

export class ListenerAuthenticationError extends ListenerError {
  constructor(message: string) {
    super(message);
    this.name = 'ListenerAuthenticationError';
  }
}

export interface SyncChanged {
  readonly domains: readonly string[];
  readonly reason: string;
  readonly accountScanSeqHint: string | null;
  readonly domainVersions: Readonly<Record<string, string>>;
}

export function syncChangedToJson(event: SyncChanged): string {
  return JSON.stringify({
    account_scan_seq_hint: event.accountScanSeqHint,
    domain_versions: event.domainVersions,
    domains: [...event.domains],
    event: 'sync.changed',
    reason: event.reason,
  });
}

export function websocketUrl(serviceBaseUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(serviceBaseUrl);
  } catch {
    throw new ListenerError('message service URL is not a safe HTTP(S) endpoint');
  }
  const scheme = parsed.protocol === 'https:' ? 'wss:' : parsed.protocol === 'http:' ? 'ws:' : null;
  if (scheme === null || !parsed.host || parsed.username || parsed.password) {
    throw new ListenerError('message service URL is not a safe HTTP(S) endpoint');
  }
  return `${scheme}//${parsed.host}/im/ws`;
}

export function parseSyncChanged(raw: string | Buffer): SyncChanged {
  let value: unknown;
  try {
    value = JSON.parse(raw.toString());
  } catch {
    throw new ListenerError('websocket notification is not valid JSON');
  }
  if (typeof value !== 'object' || value === null || (value as Record<string, unknown>).method !== 'sync.changed') {
    throw new ListenerError('websocket sent an unsupported notification');
  }
  const record = value as Record<string, unknown>;
  const hasPayload = 'payload' in record;
  const hasParams = 'params' in record;
  if (hasPayload === hasParams) {
    throw new ListenerError('sync.changed notification has an invalid shape');
  }
  const payload = hasPayload ? record.payload : record.params;
  const sync = record.sync;
  if (typeof payload !== 'object' || payload === null || typeof sync !== 'object' || sync === null) {
    throw new ListenerError('sync.changed notification has an invalid shape');
  }
  const body = payload as Record<string, unknown>;
  const meta = sync as Record<string, unknown>;
  const domains = body.domains;
  const reason = body.reason;
  const versions = meta.domain_versions;
  if (
    !Array.isArray(domains) ||
    domains.length === 0 ||
    domains.some((item) => typeof item !== 'string' || !SYNC_TOKEN.test(item)) ||
    typeof reason !== 'string' ||
    !SYNC_TOKEN.test(reason) ||
    meta.schema_version !== 2 ||
    (meta.account_scan_seq_hint !== undefined &&
      meta.account_scan_seq_hint !== null &&
      !canonicalDecimal(meta.account_scan_seq_hint)) ||
    typeof versions !== 'object' ||
    versions === null ||
    Object.entries(versions as Record<string, unknown>).some(
      ([key, version]) => !key || !canonicalDecimal(version),
    )
  ) {
    throw new ListenerError('sync.changed notification has invalid fields');
  }
  return {
    domains: domains as string[],
    reason,
    accountScanSeqHint:
      meta.account_scan_seq_hint === undefined || meta.account_scan_seq_hint === null
        ? null
        : String(meta.account_scan_seq_hint),
    domainVersions: versions as Record<string, string>,
  };
}

export interface ListenOptions {
  once?: boolean;
  connectFactory?: typeof connectWebSocket;
  onReconnect?: (delay: number) => void;
}

export async function listen(
  serviceBaseUrl: string,
  accessToken: string,
  onEvent: (event: SyncChanged) => void,
  options: ListenOptions = {},
): Promise<void> {
  const endpoint = websocketUrl(serviceBaseUrl);
  const connect = options.connectFactory ?? connectWebSocket;
  let delay = 1;
  while (true) {
    try {
      const socket = connect(endpoint, accessToken);
      await new Promise<void>((resolve, reject) => {
        const queue: Array<string | Buffer> = [];
        let draining = false;
        let settled = false;

        const fail = (error: unknown): void => {
          if (settled) {
            return;
          }
          settled = true;
          reject(error);
        };

        const succeed = (): void => {
          if (settled) {
            return;
          }
          settled = true;
          resolve();
        };

        const drain = (): void => {
          if (draining) {
            return;
          }
          draining = true;
          try {
            while (queue.length > 0) {
              const raw = queue.shift();
              if (raw === undefined) {
                break;
              }
              onEvent(parseSyncChanged(raw));
              delay = 1;
              if (options.once) {
                void closeSocket(socket).then(succeed, fail);
                return;
              }
            }
          } catch (error) {
            fail(error);
            return;
          } finally {
            draining = false;
          }
        };

        const onOpen = (): void => {
          if (socket.protocol !== SYNC_SUBPROTOCOL) {
            void closeSocket(socket);
            fail(new ListenerError('websocket server did not select awiki.sync.changed.v2'));
          }
        };

        socket.on('message', (data) => {
          if (queue.length >= LISTENER_WS_OPTIONS.maxQueue) {
            socket.terminate();
            fail(new ListenerError('websocket receive queue is full'));
            return;
          }
          queue.push(data.toString());
          drain();
        });
        socket.on('unexpected-response', (_req, res) => {
          if (res.statusCode === 401 || res.statusCode === 403) {
            fail(new ListenerAuthenticationError('websocket session is unauthorized'));
            return;
          }
          fail(new ListenerError('websocket handshake failed'));
        });
        socket.on('error', (error) => fail(error));
        socket.on('close', () => succeed());
        socket.on('open', onOpen);
        if (socket.readyState === WebSocket.OPEN) {
          onOpen();
        }
      });
      if (options.once) {
        return;
      }
    } catch (error) {
      if (error instanceof ListenerAuthenticationError) {
        throw error;
      }
    }
    options.onReconnect?.(delay);
    await new Promise((resolve) => setTimeout(resolve, delay * 1000));
    delay = Math.min(delay * 2, 30);
  }
}

export function connectWebSocket(endpoint: string, accessToken: string): WebSocket {
  const socket = new WebSocket(endpoint, SYNC_SUBPROTOCOL, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'X-AWiki-Client-Version': CLIENT_IDENTIFIER,
    },
    handshakeTimeout: LISTENER_WS_OPTIONS.handshakeTimeoutMs,
    maxPayload: LISTENER_WS_OPTIONS.maxPayloadBytes,
    followRedirects: false,
    agent: LISTENER_WS_OPTIONS.proxy ?? undefined,
  });
  let pongWatch: NodeJS.Timeout | undefined;
  const pingTimer = setInterval(() => {
    if (socket.readyState !== WebSocket.OPEN) {
      return;
    }
    socket.ping();
    if (pongWatch !== undefined) {
      clearTimeout(pongWatch);
    }
    pongWatch = setTimeout(() => {
      socket.terminate();
    }, LISTENER_WS_OPTIONS.pingTimeoutMs);
  }, LISTENER_WS_OPTIONS.pingIntervalMs);
  socket.on('pong', () => {
    if (pongWatch !== undefined) {
      clearTimeout(pongWatch);
      pongWatch = undefined;
    }
  });
  const cleanup = (): void => {
    clearInterval(pingTimer);
    if (pongWatch !== undefined) {
      clearTimeout(pongWatch);
    }
  };
  socket.once('error', () => cleanup());
  socket.once('close', () => cleanup());
  return socket;
}

export function closeSocket(socket: WebSocket): Promise<void> {
  if (socket.readyState === WebSocket.CLOSED) {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      socket.terminate();
      resolve();
    }, LISTENER_WS_OPTIONS.closeTimeoutMs);
    socket.once('close', () => {
      clearTimeout(timer);
      resolve();
    });
    socket.close();
  });
}

function canonicalDecimal(value: unknown): boolean {
  return typeof value === 'string' && /^0$|^[1-9][0-9]*$/.test(value);
}
