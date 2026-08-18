import { randomUUID } from 'node:crypto';

import type {
  AttachmentRef,
  AuthenticatedIdentity,
  ChatMessage,
  PendingOperation,
  UnlockedIdentity,
} from '../domain/models.js';
import { validateWbaDid } from '../domain/validation.js';
import { generateOriginProof } from './anp-sdk.js';
import { MANIFEST_CONTENT_TYPE, buildManifest, parseManifest } from './attachment-manifest.js';
import { callJsonRpc, type HttpClient } from './rpc.js';

export const ORIGIN_SCHEME = 'anp-rfc9421-origin-proof-v1';

export function validateDid(value: string, field = 'recipient'): string {
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
    throw new Error('message text must not be empty');
  }
  if (Buffer.byteLength(text) > 64 * 1024) {
    throw new Error('message text is too large');
  }
  const meta = {
    profile: 'anp.direct.base.v1',
    security_profile: 'transport-protected',
    sender_did: identity.identity.did,
    target: { kind: 'agent', did: recipient },
    operation_id: ids.operationId ?? randomUUID(),
    message_id: ids.messageId ?? randomUUID(),
    created_at: ids.createdAt ?? new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    content_type: 'text/plain',
  };
  const body = { text };
  const proof = generateOriginProof(
    'direct.send',
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
  if (pending.kind !== 'direct.attachment.send' || pending.targetDid !== recipient || pending.messageId === null) {
    throw new Error('pending operation does not match the Direct attachment request');
  }
  const meta = {
    profile: 'anp.direct.base.v1',
    security_profile: 'transport-protected',
    sender_did: identity.identity.did,
    target: { kind: 'agent', did: recipient },
    operation_id: pending.operationId,
    message_id: pending.messageId,
    created_at: pending.createdAt,
    content_type: MANIFEST_CONTENT_TYPE,
  };
  const body = { payload: buildManifest(attachment, caption) };
  const proof = generateOriginProof(
    'direct.send',
    meta,
    body,
    identity.deviceSigningPrivateKeyPem,
    identity.identity.verificationMethod,
    { created: pending.proofCreated, nonce: pending.proofNonce },
  );
  return { meta, auth: { scheme: ORIGIN_SCHEME, origin_proof: proof }, body };
}

export function buildInbox(did: string, limit: number, skip = 0): Record<string, unknown> {
  return localParams('anp.inbox.local.v1', did, { user_did: did, limit, skip });
}

export function buildMarkRead(did: string, messageIds: string[]): Record<string, unknown> {
  if (!messageIds.length || messageIds.some((value) => !value)) {
    throw new Error('message_ids must not be empty');
  }
  return localParams('anp.inbox.local.v1', did, { user_did: did, message_ids: messageIds });
}

export function buildHistory(did: string, peerDid: string, limit: number, skip = 0): Record<string, unknown> {
  return localParams('anp.direct.local.v1', did, {
    user_did: did,
    peer_did: validateDid(peerDid),
    limit,
    skip,
  });
}

export function buildCapabilities(did: string): Record<string, unknown> {
  return {
    meta: {
      profile: 'anp.core.binding.v1',
      security_profile: 'transport-protected',
      sender_did: did,
      operation_id: randomUUID(),
      created_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    },
    body: {},
  };
}

function localParams(profile: string, did: string, body: Record<string, unknown>): Record<string, unknown> {
  const limit = Number(body.limit ?? 1);
  const skip = Number(body.skip ?? 0);
  if (limit < 1 || limit > 100) {
    throw new Error('limit must be between 1 and 100');
  }
  if (!Number.isInteger(skip) || skip < 0) {
    throw new Error('skip must be a non-negative integer');
  }
  return {
    meta: { profile, security_profile: 'transport-protected', sender_did: did },
    body,
  };
}

export class MessageService {
  readonly endpoint: string;

  constructor(
    private readonly client: HttpClient,
    baseUrl: string,
  ) {
    this.endpoint = `${baseUrl.replace(/\/+$/, '')}/im/rpc`;
  }

  async ensureDirectBase(identity: AuthenticatedIdentity | UnlockedIdentity): Promise<void> {
    const result = asObject(
      await callJsonRpc(this.client, this.endpoint, 'anp.get_capabilities', buildCapabilities(identity.identity.did), {
        accessToken: identity.session.accessToken,
      }),
    );
    const requirements: Record<string, string> = {
      supported_profiles: 'anp.direct.base.v1',
      supported_security_profiles: 'transport-protected',
      supported_content_types: 'text/plain',
    };
    for (const [field, required] of Object.entries(requirements)) {
      const advertised = result[field];
      if (!Array.isArray(advertised) || !advertised.includes(required)) {
        throw new Error(`message service does not advertise required ${required}`);
      }
    }
    const policies = result.proof_policies;
    if (typeof policies !== 'object' || policies === null || (policies as Record<string, unknown>).direct_base_origin_proof !== 'required') {
      throw new Error('message service does not advertise the required Direct Base proof');
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
          await callJsonRpc(this.client, this.endpoint, 'direct.send', params, {
            accessToken: identity.session.accessToken,
          }),
        );
        const meta = params.meta as Record<string, unknown>;
        if (value.accepted !== true || value.message_id !== meta.message_id || value.operation_id !== meta.operation_id) {
          throw new Error('service returned an invalid direct.send result');
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
    throw lastError instanceof Error ? lastError : new Error('direct.send retry loop ended unexpectedly');
  }

  async sendAttachment(
    identity: UnlockedIdentity,
    recipient: string,
    attachment: AttachmentRef,
    caption: string | null,
    pending: PendingOperation,
  ): Promise<ChatMessage> {
    const params = buildDirectAttachmentSend(identity, recipient, attachment, caption, pending);
    const value = asObject(
      await callJsonRpc(this.client, this.endpoint, 'direct.send', params, {
        accessToken: identity.session.accessToken,
      }),
    );
    return {
      messageId: String(value.message_id),
      senderDid: identity.identity.did,
      targetDid: recipient,
      text: '',
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
    const result = asObject(
      await callJsonRpc(
        this.client,
        this.endpoint,
        'inbox.get',
        buildInbox(identity.identity.did, limit, skip),
        { accessToken: identity.session.accessToken },
      ),
    );
    const items = Array.isArray(result.messages) ? result.messages : [];
    return [items.map((item) => parseChat(item, identity.identity.did)), Boolean(result.has_more)];
  }

  async history(
    identity: AuthenticatedIdentity,
    peerDid: string,
    limit: number,
    skip: number,
  ): Promise<[ChatMessage[], boolean]> {
    const result = asObject(
      await callJsonRpc(
        this.client,
        this.endpoint,
        'direct.get_history',
        buildHistory(identity.identity.did, peerDid, limit, skip),
        { accessToken: identity.session.accessToken },
      ),
    );
    const items = Array.isArray(result.messages) ? result.messages : [];
    return [items.map((item) => parseChat(item, identity.identity.did)), Boolean(result.has_more)];
  }

  async markRead(identity: AuthenticatedIdentity, messageIds: string[]): Promise<number> {
    const result = asObject(
      await callJsonRpc(
        this.client,
        this.endpoint,
        'inbox.mark_read',
        buildMarkRead(identity.identity.did, messageIds),
        { accessToken: identity.session.accessToken },
      ),
    );
    return Number(result.updated ?? messageIds.length);
  }
}

function parseChat(value: unknown, fallbackTarget: string): ChatMessage {
  const record = asObject(value);
  const attachments: AttachmentRef[] = [];
  let caption: string | null = null;
  if (record.content_type === MANIFEST_CONTENT_TYPE) {
    const parsed = parseManifest(record.payload ?? record.content);
    attachments.push(parsed[0]);
    caption = parsed[1];
  }
  return {
    messageId: String(record.message_id),
    senderDid: String(record.sender_did ?? ''),
    targetDid: String(record.target_did ?? fallbackTarget),
    text: typeof record.text === 'string' ? record.text : '',
    createdAt: record.created_at === undefined ? null : String(record.created_at),
    isRead: typeof record.is_read === 'boolean' ? record.is_read : null,
    attachments,
    caption,
  };
}

function asObject(value: unknown, field = 'result'): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`service returned an invalid ${field}`);
  }
  return value as Record<string, unknown>;
}
