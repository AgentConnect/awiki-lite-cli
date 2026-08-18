import { createHash, randomUUID } from 'node:crypto';
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readSync,
  renameSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { Readable } from 'node:stream';

import type { AttachmentContext, AttachmentRef, AuthenticatedIdentity, UnlockedIdentity } from '../domain/models.js';
import { ATTACHMENT_PROFILE } from './anp-sdk.js';
import { pinHttpsUrl } from './safe-network.js';
import { buildCapabilities, validateDid } from './message-service.js';
import { callJsonRpc, type HttpClient } from './rpc.js';

export const CHUNK_SIZE = 64 * 1024;
export const UPLOAD_HEADER_ALLOWLIST = new Set(['x-anp-upload-token']);

export interface AttachmentCapabilities {
  readonly serviceDid: string;
  readonly maxObjectBytes: number;
}

export interface AttachmentSlot {
  readonly attachmentId: string;
  readonly slotId: string;
  readonly uploadUri: string;
  readonly uploadHeaders: Record<string, string>;
  readonly objectUri: string;
  readonly commitToken: string;
}

export interface PreparedFile {
  readonly fd: number;
  readonly filename: string;
  readonly mimeType: string;
  readonly size: number;
  readonly sha256B64u: string;
  rewind(): void;
  read(size: number): Buffer;
  close(): void;
  assertUnchanged(): void;
}

export function prepareFile(path: string, maxBytes: number): PreparedFile {
  if (maxBytes < 0) {
    throw new Error('attachment size limit is invalid');
  }
  const before = lstatSync(path);
  if (!before.isFile()) {
    throw new Error('attachment path must be a regular file, not a symlink or special file');
  }
  const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
  const fd = openSync(path, flags);
  try {
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino) {
      throw new Error('attachment file changed while it was opened');
    }
    if (opened.size > maxBytes) {
      throw new Error('attachment exceeds the service object-size limit');
    }
    const digest = createHash('sha256');
    let total = 0;
    const buffer = Buffer.alloc(CHUNK_SIZE);
    let read = readSync(fd, buffer, 0, CHUNK_SIZE, null);
    while (read > 0) {
      total += read;
      if (total > maxBytes) {
        throw new Error('attachment exceeds the service object-size limit');
      }
      digest.update(buffer.subarray(0, read));
      read = readSync(fd, buffer, 0, CHUNK_SIZE, null);
    }
    const filename = basename(path);
    const sha256B64u = digest.digest('base64url');
    let offset = 0;
    return {
      fd,
      filename,
      mimeType: guessMime(filename),
      size: total,
      sha256B64u,
      rewind() {
        offset = 0;
      },
      read(size: number) {
        const chunk = Buffer.alloc(size);
        const n = readSync(fd, chunk, 0, size, offset);
        offset += n;
        return chunk.subarray(0, n);
      },
      close() {
        closeSync(fd);
      },
      assertUnchanged() {
        const now = fstatSync(fd);
        if (now.size !== opened.size || now.mtimeMs !== opened.mtimeMs) {
          throw new Error('attachment file changed during processing');
        }
      },
    };
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

export class AttachmentService {
  readonly endpoint: string;

  constructor(
    private readonly client: HttpClient,
    baseUrl: string,
  ) {
    this.endpoint = `${baseUrl.replace(/\/+$/, '')}/im/rpc`;
  }

  async capabilities(identity: AuthenticatedIdentity | UnlockedIdentity): Promise<AttachmentCapabilities> {
    const result = asObject(
      await callJsonRpc(this.client, this.endpoint, 'anp.get_capabilities', buildCapabilities(identity.identity.did), {
        accessToken: identity.session.accessToken,
      }),
    );
    const advertised = result.supported_profiles;
    if (!Array.isArray(advertised) || !advertised.includes(ATTACHMENT_PROFILE)) {
      throw new Error(`message service does not advertise required ${ATTACHMENT_PROFILE}`);
    }
    const limits = asObject(result.limits ?? {});
    return {
      serviceDid: validateDid(String(result.service_did ?? '')),
      maxObjectBytes: Number(limits.max_object_bytes ?? 1073741824),
    };
  }

  async createSlot(
    identity: UnlockedIdentity,
    serviceDid: string,
    attachmentId: string,
    prepared: PreparedFile,
    targetKind: string,
    targetDid: string,
    operationId: string,
    createdAt: string,
  ): Promise<AttachmentSlot> {
    const result = asObject(
      await callJsonRpc(
        this.client,
        this.endpoint,
        'attachment.create_slot',
        {
          meta: controlMeta(identity.identity.did, serviceDid, operationId, createdAt),
          body: {
            attachment_id: attachmentId,
            expected_size: String(prepared.size),
            expected_digest: { alg: 'sha-256', value_b64u: prepared.sha256B64u },
            mime_type: prepared.mimeType,
            filename: prepared.filename,
            intended_message_security_profile: 'transport-protected',
            intended_target: { kind: targetKind, did: validateDid(targetDid) },
            object_encryption_mode: 'none',
          },
        },
        { accessToken: identity.session.accessToken },
      ),
    );
    const headers = filterUploadHeaders(asObject(result.upload_headers ?? {}));
    return {
      attachmentId,
      slotId: String(result.slot_id),
      uploadUri: String(result.upload_uri),
      uploadHeaders: headers,
      objectUri: String(result.object_uri ?? ''),
      commitToken: String(result.commit_token ?? ''),
    };
  }

  async upload(slot: AttachmentSlot, prepared: PreparedFile): Promise<void> {
    prepared.assertUnchanged();
    await pinHttpsUrl(slot.uploadUri, { field: 'attachment upload URI' });
    prepared.rewind();
    const stream = readableFromPrepared(prepared);
    const response = await this.client.put(slot.uploadUri, {
      headers: { ...slot.uploadHeaders, 'Content-Type': prepared.mimeType },
      body: stream,
    });
    if (!response.ok) {
      throw new Error(`attachment upload failed with HTTP ${response.status}`);
    }
    if (stream.bytesRead !== prepared.size) {
      throw new Error('attachment file changed during processing');
    }
    prepared.assertUnchanged();
  }

  async commit(
    identity: UnlockedIdentity,
    serviceDid: string,
    slot: AttachmentSlot,
    prepared: PreparedFile,
    operationId: string,
    createdAt: string,
  ): Promise<{ attachment: AttachmentRef; committedAt: string }> {
    const result = asObject(
      await callJsonRpc(
        this.client,
        this.endpoint,
        'attachment.commit_object',
        {
          meta: controlMeta(identity.identity.did, serviceDid, operationId, createdAt),
          body: {
            attachment_id: slot.attachmentId,
            slot_id: slot.slotId,
            commit_token: slot.commitToken,
            size: String(prepared.size),
            digest: { alg: 'sha-256', value_b64u: prepared.sha256B64u },
            object_encryption_mode: 'none',
          },
        },
        { accessToken: identity.session.accessToken },
      ),
    );
    return {
      attachment: {
        attachmentId: slot.attachmentId,
        objectUri: String(result.object_uri ?? slot.objectUri),
        filename: prepared.filename,
        mimeType: prepared.mimeType,
        size: prepared.size,
        sha256B64u: prepared.sha256B64u,
      },
      committedAt: String(result.committed_at ?? createdAt),
    };
  }

  async bestEffortAbort(
    identity: UnlockedIdentity,
    serviceDid: string,
    slot: AttachmentSlot,
    operationId: string,
    createdAt: string,
  ): Promise<void> {
    try {
      await callJsonRpc(
        this.client,
        this.endpoint,
        'attachment.abort_object',
        {
          meta: controlMeta(identity.identity.did, serviceDid, operationId, createdAt),
          body: { attachment_id: slot.attachmentId, slot_id: slot.slotId },
        },
        { accessToken: identity.session.accessToken },
      );
    } catch {
      // best effort
    }
  }

  async getDownloadTicket(identity: AuthenticatedIdentity, context: AttachmentContext): Promise<{ value: string }> {
    await pinHttpsUrl(context.attachment.objectUri, { field: 'attachment object URI' });
    const capabilities = await this.capabilities(identity);
    const result = asObject(
      await callJsonRpc(
        this.client,
        this.endpoint,
        'attachment.get_download_ticket',
        {
          meta: controlMeta(
            identity.identity.did,
            capabilities.serviceDid,
            randomUUID(),
            new Date().toISOString(),
          ),
          body: {
            attachment_id: context.attachment.attachmentId,
            object_uri: context.attachment.objectUri,
            requester_did: identity.identity.did,
            message_security_profile: 'transport-protected',
            message_id: context.messageId,
            one_time: true,
            ...(context.messageTargetDid
              ? { message_target_did: context.messageTargetDid }
              : { group_did: context.groupDid }),
          },
        },
        { accessToken: identity.session.accessToken },
      ),
    );
    return { value: String(result.download_ticket_b64u ?? '') };
  }

  async download(
    ticket: { value: string },
    attachment: AttachmentRef,
    destination: string,
  ): Promise<string> {
    if (existsSync(destination)) {
      throw new Error('download destination already exists');
    }
    await pinHttpsUrl(attachment.objectUri, { field: 'attachment object URI' });
    const response = await this.client.getStream(attachment.objectUri, {
      headers: { Authorization: `Bearer ${ticket.value}`, 'Accept-Encoding': 'identity' },
    });
    if (!response.ok) {
      throw new Error(`attachment download failed with HTTP ${response.status}`);
    }
    const length = response.headers['content-length'];
    if (length !== undefined && Number(length) !== attachment.size) {
      throw new Error('attachment download size does not match the Manifest');
    }
    const temporary = join(dirname(destination), `.awiki-lite-${randomUUID()}.part`);
    const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    const digest = createHash('sha256');
    let total = 0;
    try {
      for await (const piece of response.chunks()) {
        let offset = 0;
        while (offset < piece.length) {
          const end = Math.min(offset + CHUNK_SIZE, piece.length);
          const chunk = piece.subarray(offset, end);
          total += chunk.length;
          if (total > attachment.size) {
            throw new Error('attachment download exceeds the Manifest size');
          }
          digest.update(chunk);
          writeSync(fd, chunk);
          offset = end;
        }
      }
      const encoded = digest.digest('base64url');
      if (total !== attachment.size || encoded !== attachment.sha256B64u) {
        throw new Error('attachment download failed integrity verification');
      }
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    try {
      renameSync(temporary, destination);
    } catch {
      unlinkSync(temporary);
      throw new Error('attachment output file already exists');
    }
    return destination;
  }
}

export function readableFromPrepared(prepared: PreparedFile): Readable & { bytesRead: number } {
  let bytesRead = 0;
  const stream = new Readable({
    read() {
      const chunk = prepared.read(CHUNK_SIZE);
      if (chunk.length === 0) {
        this.push(null);
        return;
      }
      bytesRead += chunk.length;
      this.push(chunk);
    },
  }) as Readable & { bytesRead: number };
  Object.defineProperty(stream, 'bytesRead', {
    get() {
      return bytesRead;
    },
  });
  return stream;
}

function controlMeta(senderDid: string, serviceDid: string, operationId: string, createdAt: string): Record<string, unknown> {
  return {
    profile: ATTACHMENT_PROFILE,
    security_profile: 'transport-protected',
    sender_did: senderDid,
    target: { kind: 'service', did: serviceDid },
    operation_id: operationId,
    created_at: createdAt,
  };
}

function filterUploadHeaders(value: Record<string, unknown>): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [key, item] of Object.entries(value)) {
    if (UPLOAD_HEADER_ALLOWLIST.has(key.toLowerCase()) && typeof item === 'string') {
      headers[key] = item;
    }
  }
  return headers;
}

function guessMime(filename: string): string {
  if (filename.endsWith('.png')) return 'image/png';
  if (filename.endsWith('.jpg') || filename.endsWith('.jpeg')) return 'image/jpeg';
  if (filename.endsWith('.txt')) return 'text/plain';
  if (filename.endsWith('.pdf')) return 'application/pdf';
  return 'application/octet-stream';
}

function asObject(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('service returned an invalid result');
  }
  return value as Record<string, unknown>;
}
