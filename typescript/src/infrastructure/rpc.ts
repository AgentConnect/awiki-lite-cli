import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import type { LookupFunction } from "node:net";
import { Agent, fetch as undiciFetch, type Dispatcher } from "undici";

import {
  InvalidInputError,
  JsonRpcFailure,
  ProtocolResponseError,
  StateError,
} from "../application/errors.js";
import { CLIENT_IDENTIFIER } from "../version.js";

export interface HttpResponse {
  readonly status: number;
  readonly ok: boolean;
  readonly headers: Record<string, string>;
  json(): Promise<unknown>;
  bytes(): Promise<Uint8Array>;
}

export interface HttpStreamResponse {
  readonly status: number;
  readonly ok: boolean;
  readonly headers: Record<string, string>;
  chunks(): AsyncIterable<Uint8Array>;
}

export interface HttpClient {
  post(
    url: string,
    init: HttpRequestInit & { body: string | Uint8Array },
  ): Promise<HttpResponse>;
  put(
    url: string,
    init: HttpRequestInit & { body: NodeJS.ReadableStream },
  ): Promise<HttpResponse>;
  get(url: string, init: HttpRequestInit): Promise<HttpResponse>;
  getStream(url: string, init: HttpRequestInit): Promise<HttpStreamResponse>;
}

export interface HttpRequestInit {
  readonly headers: Record<string, string>;
  readonly pinnedAddress?: string;
  readonly pinnedFamily?: 4 | 6;
  readonly serverHostname?: string;
}

export function isRetryableTransportError(error: unknown): boolean {
  if (
    error instanceof JsonRpcFailure ||
    error instanceof ProtocolResponseError ||
    error instanceof InvalidInputError ||
    error instanceof StateError
  ) {
    return false;
  }
  if (!(error instanceof Error)) {
    return false;
  }
  const tokens = collectErrorTokens(error);
  if (
    tokens.some((token) =>
      /^(ECONNRESET|ETIMEDOUT|ECONNREFUSED|ENOTFOUND|EPIPE|EHOSTUNREACH|UND_ERR_|HeadersTimeoutError|BodyTimeoutError|ConnectTimeoutError|SocketError)$/i.test(
        token,
      ),
    )
  ) {
    return true;
  }
  return (
    error.name === "TypeError" && /fetch|network|socket/i.test(error.message)
  );
}

function collectErrorTokens(error: Error): string[] {
  const tokens: string[] = [error.name];
  let current: unknown = error;
  for (let index = 0; index < 4 && current && typeof current === "object";) {
    const record = current as {
      code?: unknown;
      cause?: unknown;
      name?: unknown;
    };
    if (typeof record.code === "string") {
      tokens.push(record.code);
    }
    if (typeof record.name === "string") {
      tokens.push(record.name);
    }
    current = record.cause;
    index += 1;
  }
  return tokens;
}

export function fixedAddressLookup(
  address: string,
  family: 4 | 6,
): LookupFunction {
  return (_hostname, options, callback) => {
    if (options.all) {
      callback(null, [{ address, family }]);
      return;
    }
    callback(null, address, family);
  };
}

export function createHttpClient(
  options: { caBundle?: string | null; timeoutMs?: number } = {},
): {
  client: HttpClient;
  close(): void;
} {
  const ca = options.caBundle ? readFileSync(options.caBundle) : undefined;
  const timeout = options.timeoutMs ?? 20_000;
  const dispatchers = new Set<Dispatcher>();
  const pinnedDispatchers = new Map<string, Dispatcher>();
  const dispatcher: Dispatcher = new Agent({
    connect: { timeout, ...(ca ? { ca } : {}) },
    bodyTimeout: options.timeoutMs ?? 20_000,
    headersTimeout: options.timeoutMs ?? 20_000,
  });
  dispatchers.add(dispatcher);

  function requestDispatcher(init: HttpRequestInit): Dispatcher {
    if (!init.pinnedAddress || !init.pinnedFamily || !init.serverHostname) {
      return dispatcher;
    }
    const address = init.pinnedAddress;
    const family = init.pinnedFamily;
    const key = `${init.serverHostname}\0${address}\0${family}`;
    const existing = pinnedDispatchers.get(key);
    if (existing) {
      return existing;
    }
    const pinned = new Agent({
      connect: {
        timeout,
        ...(ca ? { ca } : {}),
        servername: init.serverHostname,
        lookup: fixedAddressLookup(address, family),
      },
      bodyTimeout: timeout,
      headersTimeout: timeout,
    });
    pinnedDispatchers.set(key, pinned);
    dispatchers.add(pinned);
    return pinned;
  }
  const client: HttpClient = {
    async post(url, init) {
      const response = await undiciFetch(url, {
        method: "POST",
        headers: init.headers,
        body: init.body,
        dispatcher: requestDispatcher(init),
        redirect: "error",
      });
      return wrap(response);
    },
    async put(url, init) {
      const response = await undiciFetch(url, {
        method: "PUT",
        headers: init.headers,
        body: init.body as never,
        dispatcher: requestDispatcher(init),
        redirect: "error",
        duplex: "half",
      } as never);
      return wrap(response);
    },
    async get(url, init) {
      const response = await undiciFetch(url, {
        method: "GET",
        headers: init.headers,
        dispatcher: requestDispatcher(init),
        redirect: "error",
      });
      return wrap(response);
    },
    async getStream(url, init) {
      const response = await undiciFetch(url, {
        method: "GET",
        headers: init.headers,
        dispatcher: requestDispatcher(init),
        redirect: "error",
      });
      return wrapStream(response);
    },
  };
  return {
    client,
    close() {
      for (const active of dispatchers) {
        void active.close();
      }
    },
  };
}

function headerMap(response: Response): Record<string, string> {
  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });
  return headers;
}

function wrap(response: Response): HttpResponse {
  return {
    status: response.status,
    ok: response.ok,
    headers: headerMap(response),
    json: async () => response.json(),
    bytes: async () => new Uint8Array(await response.arrayBuffer()),
  };
}

function wrapStream(response: Response): HttpStreamResponse {
  return {
    status: response.status,
    ok: response.ok,
    headers: headerMap(response),
    async *chunks() {
      if (!response.body) {
        return;
      }
      const reader = response.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          return;
        }
        if (value) {
          yield value;
        }
      }
    },
  };
}

export async function callJsonRpc(
  client: HttpClient,
  endpoint: string,
  method: string,
  params: Record<string, unknown>,
  options: { accessToken?: string; clientVersion?: string } = {},
): Promise<unknown> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-AWiki-Client-Version": options.clientVersion ?? CLIENT_IDENTIFIER,
  };
  if (options.accessToken) {
    headers.Authorization = `Bearer ${options.accessToken}`;
  }
  const requestId = randomUUID();
  const response = await client.post(endpoint, {
    headers,
    body: encodeJsonRpcRequest(requestId, method, params).toString("utf8"),
  });
  return decodeJsonRpcResponse(response, requestId);
}

export function encodeJsonRpcRequest(
  requestId: string,
  method: string,
  params: Record<string, unknown>,
): Buffer {
  return Buffer.from(
    JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params }),
  );
}

export async function decodeJsonRpcResponse(
  response: HttpResponse,
  requestId: string,
): Promise<unknown> {
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    if (!response.ok) {
      throw new Error(`service returned HTTP ${response.status}`);
    }
    throw new Error("service returned a non-JSON response");
  }
  if (
    typeof payload !== "object" ||
    payload === null ||
    Array.isArray(payload)
  ) {
    throw new ProtocolResponseError(
      "service returned an invalid JSON-RPC response",
    );
  }
  const record = payload as Record<string, unknown>;
  if (record.jsonrpc !== "2.0" || record.id !== requestId) {
    throw new ProtocolResponseError(
      "service returned an invalid JSON-RPC envelope",
    );
  }
  const errorValue = record.error;
  const hasError = errorValue !== undefined && errorValue !== null;
  const hasResult = "result" in record;
  if (hasError && hasResult && record.result !== null) {
    throw new ProtocolResponseError(
      "service returned an ambiguous JSON-RPC response",
    );
  }
  if (!hasError && !hasResult) {
    throw new ProtocolResponseError(
      "service returned an ambiguous JSON-RPC response",
    );
  }
  if (hasError) {
    const error = errorValue;
    if (typeof error !== "object" || error === null || Array.isArray(error)) {
      throw new ProtocolResponseError(
        "service returned an invalid JSON-RPC error",
      );
    }
    const item = error as Record<string, unknown>;
    if (typeof item.code !== "number" || typeof item.message !== "string") {
      throw new ProtocolResponseError(
        "service returned an invalid JSON-RPC error",
      );
    }
    throw new JsonRpcFailure(item.code, item.message, item.data);
  }
  if (!response.ok) {
    throw new Error(`service returned HTTP ${response.status}`);
  }
  return record.result;
}
