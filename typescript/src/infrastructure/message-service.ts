import { randomUUID } from "node:crypto";

import type {
  AttachmentRef,
  AuthenticatedIdentity,
  ChatMessage,
  PendingOperation,
  UnlockedIdentity,
} from "../domain/models.js";
import { validateWbaDid } from "../domain/validation.js";
import { generateOriginProof } from "./anp-sdk.js";
import {
  MANIFEST_CONTENT_TYPE,
  buildManifest,
  parseManifest,
} from "./attachment-manifest.js";
import { callJsonRpc, type HttpClient } from "./rpc.js";

export const ORIGIN_SCHEME = "anp-rfc9421-origin-proof-v1";

export function validateDid(value: string, field = "recipient"): string {
  return validateWbaDid(value, field);
}

export function buildDirectSend(
  identity: UnlockedIdentity,
  recipientDid: string,
  text: string,
  ids: {
    operationId?: string;
    messageId?: string;
    createdAt?: string;
    proofCreated?: number;
    proofNonce?: string;
  } = {},
): Record<string, unknown> {
  const recipient = validateDid(recipientDid);
  if (!text || !text.trim()) {
    throw new Error("message text must not be empty");
  }
  if (Buffer.byteLength(text) > 64 * 1024) {
    throw new Error("message text is too large");
  }
  const meta = {
    profile: "anp.direct.base.v1",
    security_profile: "transport-protected",
    sender_did: identity.identity.did,
    target: { kind: "agent", did: recipient },
    operation_id: ids.operationId ?? randomUUID(),
    message_id: ids.messageId ?? randomUUID(),
    created_at:
      ids.createdAt ?? new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    content_type: "text/plain",
  };
  const body = { text };
  const proof = generateOriginProof(
    "direct.send",
    meta,
    body,
    identity.deviceSigningPrivateKeyPem,
    identity.identity.verificationMethod,
    {
      ...(ids.proofCreated !== undefined ? { created: ids.proofCreated } : {}),
      ...(ids.proofNonce !== undefined ? { nonce: ids.proofNonce } : {}),
    },
  );
  return { meta, auth: { scheme: ORIGIN_SCHEME, origin_proof: proof }, body };
}

export function buildDirectAttachmentSend(
  identity: UnlockedIdentity,
  recipientDid: string,
  attachment: AttachmentRef,
  caption: string | null,
  pending: PendingOperation,
): Record<string, unknown> {
  const recipient = validateDid(recipientDid);
  if (
    pending.kind !== "direct.attachment.send" ||
    pending.targetDid !== recipient ||
    pending.messageId === null
  ) {
    throw new Error(
      "pending operation does not match the Direct attachment request",
    );
  }
  const meta = {
    profile: "anp.direct.base.v1",
    security_profile: "transport-protected",
    sender_did: identity.identity.did,
    target: { kind: "agent", did: recipient },
    operation_id: pending.operationId,
    message_id: pending.messageId,
    created_at: pending.createdAt,
    content_type: MANIFEST_CONTENT_TYPE,
  };
  const body = { payload: buildManifest(attachment, caption) };
  const proof = generateOriginProof(
    "direct.send",
    meta,
    body,
    identity.deviceSigningPrivateKeyPem,
    identity.identity.verificationMethod,
    { created: pending.proofCreated, nonce: pending.proofNonce },
  );
  return { meta, auth: { scheme: ORIGIN_SCHEME, origin_proof: proof }, body };
}

export function buildMarkRead(
  did: string,
  messageIds: string[],
): Record<string, unknown> {
  if (!messageIds.length || messageIds.some((value) => !value)) {
    throw new Error("message_ids must not be empty");
  }
  return localParams("anp.inbox.local.v1", did, {
    user_did: did,
    message_ids: messageIds,
  });
}

export function buildSyncDelta(
  did: string,
  sinceEventSeq: string,
  limit = 100,
): Record<string, unknown> {
  validateDecimalCursor(sinceEventSeq, "since_event_seq");
  return syncParams(did, {
    user_did: did,
    since_event_seq: sinceEventSeq,
    limit,
  });
}

export function buildSyncThreadAfter(
  did: string,
  peerDid: string,
  afterServerSeq: string,
  limit = 100,
): Record<string, unknown> {
  validateDecimalCursor(afterServerSeq, "after_server_seq");
  return syncParams(did, {
    user_did: did,
    thread: { kind: "direct", peer_did: validateDid(peerDid) },
    after_server_seq: afterServerSeq,
    limit,
  });
}

export function buildCapabilities(did: string): Record<string, unknown> {
  return {
    meta: {
      profile: "anp.core.binding.v1",
      security_profile: "transport-protected",
      sender_did: did,
      operation_id: randomUUID(),
      created_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    },
    body: {},
  };
}

function localParams(
  profile: string,
  did: string,
  body: Record<string, unknown>,
): Record<string, unknown> {
  const limit = Number(body.limit ?? 1);
  const skip = Number(body.skip ?? 0);
  if (limit < 1 || limit > 100) {
    throw new Error("limit must be between 1 and 100");
  }
  if (!Number.isInteger(skip) || skip < 0) {
    throw new Error("skip must be a non-negative integer");
  }
  return {
    meta: { profile, security_profile: "transport-protected", sender_did: did },
    body,
  };
}

function syncParams(
  did: string,
  body: Record<string, unknown>,
): Record<string, unknown> {
  const limit = body.limit;
  if (!Number.isInteger(limit) || Number(limit) < 1 || Number(limit) > 100) {
    throw new Error("limit must be between 1 and 100");
  }
  return {
    meta: {
      profile: "anp.sync.local.v1",
      security_profile: "transport-protected",
      sender_did: did,
      operation_id: `op-${randomUUID()}`,
      created_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    },
    body,
  };
}

function validateDecimalCursor(value: string, field: string): void {
  if (!/^\d+$/.test(value)) {
    throw new Error(`${field} must be a non-negative decimal string`);
  }
}

export class MessageService {
  readonly endpoint: string;

  constructor(
    private readonly client: HttpClient,
    baseUrl: string,
  ) {
    this.endpoint = `${baseUrl.replace(/\/+$/, "")}/im/rpc`;
  }

  async ensureDirectBase(
    identity: AuthenticatedIdentity | UnlockedIdentity,
  ): Promise<void> {
    const result = asObject(
      await callJsonRpc(
        this.client,
        this.endpoint,
        "anp.get_capabilities",
        buildCapabilities(identity.identity.did),
        {
          accessToken: identity.session.accessToken,
        },
      ),
    );
    const requirements: Record<string, string> = {
      supported_profiles: "anp.direct.base.v1",
      supported_security_profiles: "transport-protected",
      supported_content_types: "text/plain",
    };
    for (const [field, required] of Object.entries(requirements)) {
      const advertised = result[field];
      if (!Array.isArray(advertised) || !advertised.includes(required)) {
        throw new Error(
          `message service does not advertise required ${required}`,
        );
      }
    }
    const policies = result.proof_policies;
    if (
      typeof policies !== "object" ||
      policies === null ||
      (policies as Record<string, unknown>).direct_base_origin_proof !==
        "required"
    ) {
      throw new Error(
        "message service does not advertise the required Direct Base proof",
      );
    }
  }

  async send(
    identity: UnlockedIdentity,
    recipient: string,
    text: string,
    ids: Parameters<typeof buildDirectSend>[3] = {},
    preflight = true,
  ): Promise<ChatMessage> {
    if (preflight) {
      await this.ensureDirectBase(identity);
    }
    const params = buildDirectSend(identity, recipient, text, ids);
    let lastError: unknown;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const value = asObject(
          await callJsonRpc(this.client, this.endpoint, "direct.send", params, {
            accessToken: identity.session.accessToken,
          }),
        );
        const meta = params.meta as Record<string, unknown>;
        if (
          value.accepted !== true ||
          value.message_id !== meta.message_id ||
          value.operation_id !== meta.operation_id
        ) {
          throw new Error("service returned an invalid direct.send result");
        }
        return {
          messageId: String(value.message_id),
          senderDid: identity.identity.did,
          targetDid: recipient,
          text,
          createdAt: String(value.accepted_at),
          isRead: null,
          attachments: [],
          caption: null,
        };
      } catch (error) {
        lastError = error;
        if (attempt === 1) {
          throw error;
        }
      }
    }
    throw lastError instanceof Error
      ? lastError
      : new Error("direct.send retry loop ended unexpectedly");
  }

  async sendAttachment(
    identity: UnlockedIdentity,
    recipient: string,
    attachment: AttachmentRef,
    caption: string | null,
    pending: PendingOperation,
  ): Promise<ChatMessage> {
    const params = buildDirectAttachmentSend(
      identity,
      recipient,
      attachment,
      caption,
      pending,
    );
    const value = asObject(
      await callJsonRpc(this.client, this.endpoint, "direct.send", params, {
        accessToken: identity.session.accessToken,
      }),
    );
    return {
      messageId: String(value.message_id),
      senderDid: identity.identity.did,
      targetDid: recipient,
      text: "",
      createdAt: String(value.accepted_at ?? pending.createdAt),
      isRead: null,
      attachments: [attachment],
      caption,
    };
  }

  async inbox(
    identity: AuthenticatedIdentity,
    limit: number,
    skip: number,
  ): Promise<[ChatMessage[], boolean]> {
    const peers = await this.directPeers(identity);
    const messages: ChatMessage[] = [];
    for (const peer of peers) {
      const [threadMessages] = await this.threadMessages(identity, peer, null);
      messages.push(
        ...threadMessages.filter(
          (message) => message.targetDid === identity.identity.did,
        ),
      );
    }
    const unique = [
      ...new Map(
        messages.map((message) => [message.messageId, message]),
      ).values(),
    ];
    unique.sort((left, right) => {
      const leftKey = `${left.createdAt ?? ""}\u0000${left.messageId}`;
      const rightKey = `${right.createdAt ?? ""}\u0000${right.messageId}`;
      return leftKey < rightKey ? 1 : leftKey > rightKey ? -1 : 0;
    });
    const end = skip + limit;
    return [unique.slice(skip, end), unique.length > end];
  }

  async history(
    identity: AuthenticatedIdentity,
    peerDid: string,
    limit: number,
    skip: number,
  ): Promise<[ChatMessage[], boolean]> {
    const [messages, remoteHasMore] = await this.threadMessages(
      identity,
      peerDid,
      skip + limit + 1,
    );
    const end = skip + limit;
    return [messages.slice(skip, end), remoteHasMore || messages.length > end];
  }

  async markRead(
    identity: AuthenticatedIdentity,
    messageIds: string[],
  ): Promise<number> {
    const result = asObject(
      await callJsonRpc(
        this.client,
        this.endpoint,
        "inbox.mark_read",
        buildMarkRead(identity.identity.did, messageIds),
        { accessToken: identity.session.accessToken },
      ),
    );
    return Number(result.updated ?? messageIds.length);
  }

  private async directPeers(
    identity: AuthenticatedIdentity,
  ): Promise<string[]> {
    let cursor = "0";
    const peers = new Set<string>();
    while (true) {
      const page = asObject(
        await callJsonRpc(
          this.client,
          this.endpoint,
          "sync.delta",
          buildSyncDelta(identity.identity.did, cursor),
          {
            accessToken: identity.session.accessToken,
          },
        ),
      );
      if (page.snapshot_required === true) {
        throw new Error(
          "message sync history is no longer available from the beginning",
        );
      }
      if (!Array.isArray(page.events)) {
        throw new Error("service returned an invalid sync event page");
      }
      for (const value of page.events) {
        const event = asObject(value, "sync event");
        if (
          typeof event.payload !== "object" ||
          event.payload === null ||
          Array.isArray(event.payload)
        ) {
          continue;
        }
        const payload = event.payload as Record<string, unknown>;
        if (
          typeof payload.thread !== "object" ||
          payload.thread === null ||
          Array.isArray(payload.thread)
        ) {
          continue;
        }
        const thread = payload.thread as Record<string, unknown>;
        if (thread.kind !== "direct") {
          continue;
        }
        if (typeof thread.peer_did !== "string") {
          throw new Error("service returned an invalid direct thread");
        }
        peers.add(validateDid(thread.peer_did, "direct thread"));
      }
      if (page.has_more !== true) {
        return [...peers].sort();
      }
      const next = requiredString(page, ["next_event_seq"], "next_event_seq");
      validateRemoteCursor(next, "next_event_seq");
      if (BigInt(next) <= BigInt(cursor)) {
        throw new Error("sync.delta did not advance its cursor");
      }
      cursor = next;
    }
  }

  private async threadMessages(
    identity: AuthenticatedIdentity,
    peerDid: string,
    requested: number | null,
  ): Promise<[ChatMessage[], boolean]> {
    let cursor = "0";
    const messages: ChatMessage[] = [];
    let hasMore = false;
    while (requested === null || messages.length < requested) {
      const page = asObject(
        await callJsonRpc(
          this.client,
          this.endpoint,
          "sync.thread_after",
          buildSyncThreadAfter(identity.identity.did, peerDid, cursor),
          { accessToken: identity.session.accessToken },
        ),
      );
      if (!Array.isArray(page.messages)) {
        throw new Error("service returned an invalid message page");
      }
      for (const item of page.messages) {
        const message = parseChat(item, identity.identity.did);
        if (message !== null) {
          messages.push(message);
        }
      }
      hasMore = page.has_more === true;
      if (!hasMore) {
        break;
      }
      const next = requiredString(
        page,
        ["next_after_server_seq"],
        "next_after_server_seq",
      );
      validateRemoteCursor(next, "next_after_server_seq");
      if (BigInt(next) <= BigInt(cursor)) {
        throw new Error("sync.thread_after did not advance its cursor");
      }
      cursor = next;
    }
    return [messages, hasMore];
  }
}

function parseChat(value: unknown, fallbackTarget: string): ChatMessage | null {
  const record = asObject(value);
  if (
    record.content_type !== "text/plain" &&
    record.content_type !== MANIFEST_CONTENT_TYPE
  ) {
    return null;
  }
  const attachments: AttachmentRef[] = [];
  let caption: string | null = null;
  if (record.content_type === MANIFEST_CONTENT_TYPE) {
    const parsed = parseManifest(record.payload ?? record.content);
    attachments.push(parsed[0]);
    caption = parsed[1];
  }
  return {
    messageId: requiredString(record, ["id", "message_id"], "message id"),
    senderDid: validateDid(
      requiredString(record, ["sender_did"], "sender_did"),
      "sender_did",
    ),
    targetDid: validateDid(
      requiredString(
        record,
        ["receiver_did", "target_did"],
        "receiver_did",
        fallbackTarget,
      ),
      "receiver_did",
    ),
    text:
      record.content_type === "text/plain"
        ? requiredString(record, ["content", "text"], "message content", "")
        : "",
    createdAt:
      record.sent_at === undefined && record.created_at === undefined
        ? null
        : String(record.sent_at ?? record.created_at),
    isRead: typeof record.is_read === "boolean" ? record.is_read : null,
    attachments,
    caption,
  };
}

function requiredString(
  value: Record<string, unknown>,
  fields: string[],
  label: string,
  fallback?: string,
): string {
  for (const field of fields) {
    const result = value[field];
    if (typeof result === "string") {
      return result;
    }
  }
  if (fallback !== undefined) {
    return fallback;
  }
  throw new Error(`service returned an invalid ${label}`);
}

function validateRemoteCursor(value: string, field: string): void {
  try {
    validateDecimalCursor(value, field);
  } catch {
    throw new Error(`service returned an invalid ${field}`);
  }
}

function asObject(value: unknown, field = "result"): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`service returned an invalid ${field}`);
  }
  return value as Record<string, unknown>;
}
