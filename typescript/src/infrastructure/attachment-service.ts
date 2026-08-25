import { createHash, randomUUID } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  openSync,
  readSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { Readable } from "node:stream";

import type {
  AttachmentContext,
  AttachmentRef,
  AuthenticatedIdentity,
  UnlockedIdentity,
} from "../domain/models.js";
import { InvalidInputError } from "../application/errors.js";
import { ATTACHMENT_PROFILE, resolveAttachmentServiceDid } from "./anp-sdk.js";
import { MANIFEST_CONTENT_TYPE } from "./attachment-manifest.js";
import { pinHttpsUrl, pinnedHeaders } from "./safe-network.js";
import { buildCapabilities, validateDid } from "./message-service.js";
import { callJsonRpc, type HttpClient } from "./rpc.js";

export const CHUNK_SIZE = 64 * 1024;
export const UPLOAD_HEADER_ALLOWLIST = new Set(["x-anp-upload-token"]);

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
  readonly expiresAt: string;
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
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new InvalidInputError("attachment size limit is invalid");
  }
  let before;
  try {
    before = lstatSync(path);
  } catch {
    throw new InvalidInputError("attachment file is unavailable");
  }
  if (!before.isFile()) {
    throw new InvalidInputError(
      "attachment path must be a regular file, not a symlink or special file",
    );
  }
  const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
  let fd: number;
  try {
    fd = openSync(path, flags);
  } catch {
    throw new InvalidInputError("attachment file cannot be opened safely");
  }
  try {
    const opened = fstatSync(fd);
    if (
      !opened.isFile() ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino
    ) {
      throw new Error("attachment file changed while it was opened");
    }
    if (opened.size > maxBytes) {
      throw new InvalidInputError(
        "attachment exceeds the service object-size limit",
      );
    }
    const digest = createHash("sha256");
    let total = 0;
    const buffer = Buffer.alloc(CHUNK_SIZE);
    let read = readSync(fd, buffer, 0, CHUNK_SIZE, null);
    while (read > 0) {
      total += read;
      if (total > maxBytes) {
        throw new InvalidInputError(
          "attachment exceeds the service object-size limit",
        );
      }
      digest.update(buffer.subarray(0, read));
      read = readSync(fd, buffer, 0, CHUNK_SIZE, null);
    }
    const filename = basename(path);
    const sha256B64u = digest.digest("base64url");
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
          throw new Error("attachment file changed during processing");
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
    private readonly allowPrivateNetwork = false,
    private readonly serviceResolver?: (senderDid: string) => Promise<string>,
  ) {
    this.endpoint = `${baseUrl.replace(/\/+$/, "")}/im/rpc`;
  }

  async capabilities(
    identity: AuthenticatedIdentity | UnlockedIdentity,
  ): Promise<AttachmentCapabilities> {
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
    requireAdvertised(result, "supported_profiles", ATTACHMENT_PROFILE);
    requireAdvertised(
      result,
      "supported_security_profiles",
      "transport-protected",
    );
    requireAdvertised(result, "supported_content_types", MANIFEST_CONTENT_TYPE);
    const serviceDid = result.service_did;
    const limits = result.limits;
    if (
      typeof serviceDid !== "string" ||
      typeof limits !== "object" ||
      limits === null ||
      Array.isArray(limits)
    ) {
      throw new Error("attachment capability response is incomplete");
    }
    return {
      serviceDid: validateDid(serviceDid),
      maxObjectBytes: objectByteLimit(limits as Record<string, unknown>),
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
        "attachment.create_slot",
        {
          meta: controlMeta(
            identity.identity.did,
            serviceDid,
            operationId,
            createdAt,
          ),
          body: {
            attachment_id: attachmentId,
            expected_size: String(prepared.size),
            expected_digest: {
              alg: "sha-256",
              value_b64u: prepared.sha256B64u,
            },
            mime_type: prepared.mimeType,
            filename: prepared.filename,
            intended_message_security_profile: "transport-protected",
            intended_target: { kind: targetKind, did: validateDid(targetDid) },
            object_encryption_mode: "none",
          },
        },
        { accessToken: identity.session.accessToken },
      ),
    );
    return parseSlot(result, attachmentId, prepared);
  }

  async upload(slot: AttachmentSlot, prepared: PreparedFile): Promise<void> {
    requireUnexpired(slot.expiresAt);
    prepared.assertUnchanged();
    const target = await pinHttpsUrl(slot.uploadUri, {
      field: "attachment upload URI",
      allowPrivateNetwork: this.allowPrivateNetwork,
    });
    prepared.rewind();
    const stream = readableFromPrepared(prepared);
    const response = await this.client.put(target.url, {
      headers: pinnedHeaders(target, {
        ...slot.uploadHeaders,
        "Content-Type": prepared.mimeType,
      }),
      body: stream,
      pinnedAddress: target.address,
      pinnedFamily: target.family,
      serverHostname: target.serverHostname,
    });
    if (!response.ok) {
      throw new Error(`attachment upload failed with HTTP ${response.status}`);
    }
    if (stream.bytesRead !== prepared.size) {
      throw new Error("attachment file changed during processing");
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
        "attachment.commit_object",
        {
          meta: controlMeta(
            identity.identity.did,
            serviceDid,
            operationId,
            createdAt,
          ),
          body: {
            attachment_id: slot.attachmentId,
            slot_id: slot.slotId,
            commit_token: slot.commitToken,
            size: String(prepared.size),
            digest: { alg: "sha-256", value_b64u: prepared.sha256B64u },
            object_encryption_mode: "none",
          },
        },
        { accessToken: identity.session.accessToken },
      ),
    );
    return parseCommit(result, slot, prepared);
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
        "attachment.abort_object",
        {
          meta: controlMeta(
            identity.identity.did,
            serviceDid,
            operationId,
            createdAt,
          ),
          body: { attachment_id: slot.attachmentId, slot_id: slot.slotId },
        },
        { accessToken: identity.session.accessToken },
      );
    } catch {
      // best effort
    }
  }

  async getDownloadTicket(
    identity: AuthenticatedIdentity,
    context: AttachmentContext,
  ): Promise<{ value: string; expiresAt: string }> {
    await pinHttpsUrl(context.attachment.objectUri, {
      field: "attachment object URI",
      allowPrivateNetwork: this.allowPrivateNetwork,
    });
    const resolver =
      this.serviceResolver ??
      ((senderDid: string) =>
        resolveAttachmentServiceDid(senderDid, this.client, {
          allowPrivateNetwork: this.allowPrivateNetwork,
        }));
    let serviceDid: string;
    try {
      serviceDid = validateDid(await resolver(context.senderDid));
    } catch {
      throw new Error("resolved attachment service DID is invalid");
    }
    const body: Record<string, unknown> = {
      attachment_id: context.attachment.attachmentId,
      object_uri: context.attachment.objectUri,
      requester_did: identity.identity.did,
      message_security_profile: "transport-protected",
      message_id: context.messageId,
      one_time: true,
      ...(context.messageTargetDid
        ? { message_target_did: context.messageTargetDid }
        : { group_did: context.groupDid }),
    };
    const result = asObject(
      await callJsonRpc(
        this.client,
        this.endpoint,
        "attachment.get_download_ticket",
        {
          meta: controlMeta(
            identity.identity.did,
            serviceDid,
            randomUUID(),
            new Date().toISOString(),
          ),
          body,
        },
        { accessToken: identity.session.accessToken },
      ),
    );
    return parseDownloadTicket(result, body, context.senderDid);
  }

  async download(
    ticket: { value: string; expiresAt?: string },
    attachment: AttachmentRef,
    destination: string,
  ): Promise<string> {
    if (ticket.expiresAt) {
      requireUnexpired(ticket.expiresAt, "attachment download ticket");
    }
    if (existsSync(destination)) {
      throw new InvalidInputError("download destination already exists");
    }
    const target = await pinHttpsUrl(attachment.objectUri, {
      field: "attachment object URI",
      allowPrivateNetwork: this.allowPrivateNetwork,
    });
    const response = await this.client.getStream(target.url, {
      headers: pinnedHeaders(target, {
        Authorization: `Bearer ${ticket.value}`,
        "Accept-Encoding": "identity",
      }),
      pinnedAddress: target.address,
      pinnedFamily: target.family,
      serverHostname: target.serverHostname,
    });
    if (!response.ok) {
      throw new Error(
        `attachment download failed with HTTP ${response.status}`,
      );
    }
    const length = response.headers["content-length"];
    if (
      length !== undefined &&
      decimalSize(length, "Content-Length") !== attachment.size
    ) {
      throw new Error("attachment download size does not match the Manifest");
    }
    const temporary = join(
      dirname(destination),
      `.awiki-lite-${randomUUID()}.part`,
    );
    const fd = openSync(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
      0o600,
    );
    const digest = createHash("sha256");
    let total = 0;
    try {
      for await (const piece of response.chunks()) {
        let offset = 0;
        while (offset < piece.length) {
          const end = Math.min(offset + CHUNK_SIZE, piece.length);
          const chunk = piece.subarray(offset, end);
          total += chunk.length;
          if (total > attachment.size) {
            throw new Error("attachment download exceeds the Manifest size");
          }
          digest.update(chunk);
          let written = 0;
          while (written < chunk.length) {
            written += writeSync(fd, chunk, written);
          }
          offset = end;
        }
      }
      const encoded = digest.digest("base64url");
      if (total !== attachment.size || encoded !== attachment.sha256B64u) {
        throw new Error("attachment download failed integrity verification");
      }
      fsyncSync(fd);
    } catch (error) {
      closeSync(fd);
      unlinkSync(temporary);
      throw error;
    }
    closeSync(fd);
    try {
      linkSync(temporary, destination);
    } catch {
      unlinkSync(temporary);
      throw new InvalidInputError("attachment output file already exists");
    }
    unlinkSync(temporary);
    return destination;
  }
}

export function readableFromPrepared(
  prepared: PreparedFile,
): Readable & { bytesRead: number } {
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
  Object.defineProperty(stream, "bytesRead", {
    get() {
      return bytesRead;
    },
  });
  return stream;
}

function controlMeta(
  senderDid: string,
  serviceDid: string,
  operationId: string,
  createdAt: string,
): Record<string, unknown> {
  return {
    profile: ATTACHMENT_PROFILE,
    security_profile: "transport-protected",
    sender_did: senderDid,
    target: { kind: "service", did: serviceDid },
    operation_id: operationId,
    created_at: createdAt,
  };
}

function filterUploadHeaders(
  value: Record<string, unknown>,
): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [key, item] of Object.entries(value)) {
    const name = key.trim().toLowerCase();
    if (!UPLOAD_HEADER_ALLOWLIST.has(name)) {
      throw new Error("attachment service returned a forbidden upload header");
    }
    if (
      typeof item !== "string" ||
      !item ||
      item.includes("\r") ||
      item.includes("\n")
    ) {
      throw new Error("attachment service returned an invalid upload header");
    }
    headers[name] = item;
  }
  return headers;
}

function guessMime(filename: string): string {
  if (filename.endsWith(".png")) return "image/png";
  if (filename.endsWith(".jpg") || filename.endsWith(".jpeg"))
    return "image/jpeg";
  if (filename.endsWith(".txt")) return "text/plain";
  if (filename.endsWith(".pdf")) return "application/pdf";
  return "application/octet-stream";
}

function requireAdvertised(
  result: Record<string, unknown>,
  field: string,
  required: string,
): void {
  const advertised = result[field];
  if (!Array.isArray(advertised) || !advertised.includes(required)) {
    throw new Error(`message service does not advertise required ${required}`);
  }
}

function objectByteLimit(limits: Record<string, unknown>): number {
  if (
    limits.max_object_bytes !== undefined &&
    limits.max_object_bytes !== null
  ) {
    return decimalSize(limits.max_object_bytes, "max_object_bytes");
  }
  if (
    limits.max_attachment_bytes !== undefined &&
    limits.max_attachment_bytes !== null
  ) {
    return decimalSize(limits.max_attachment_bytes, "max_attachment_bytes");
  }
  throw new Error("attachment capability response is incomplete");
}

function nonempty(value: unknown, field: string): string {
  if (typeof value !== "string" || !value) {
    throw new Error(`attachment service returned an invalid ${field}`);
  }
  return value;
}

function httpsUri(value: unknown, field: string): string {
  const uri = nonempty(value, field);
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    throw new Error(`attachment service returned an unsafe ${field}`);
  }
  if (
    parsed.protocol !== "https:" ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error(`attachment service returned an unsafe ${field}`);
  }
  return uri;
}

function parseSlot(
  value: Record<string, unknown>,
  attachmentId: string,
  prepared: PreparedFile,
): AttachmentSlot {
  const required = new Set([
    "attachment_id",
    "slot_id",
    "upload_uri",
    "object_uri",
    "commit_token",
    "expires_at",
  ]);
  const extensions = new Set([
    "upload_headers",
    "object_id",
    "upload_token",
    "upload_url",
    "expected_size",
    "expected_digest",
    "content_type",
  ]);
  if (!hasRequiredAndKnownFields(value, required, extensions)) {
    throw new Error(
      "attachment service returned an invalid create-slot result",
    );
  }
  if (value.attachment_id !== attachmentId) {
    throw new Error(
      "attachment service returned a mismatched attachment identifier",
    );
  }
  const headers =
    value.upload_headers === undefined ? {} : asObject(value.upload_headers);
  const slot = {
    attachmentId,
    slotId: nonempty(value.slot_id, "slot_id"),
    uploadUri: httpsUri(value.upload_uri, "upload_uri"),
    uploadHeaders: filterUploadHeaders(headers),
    objectUri: httpsUri(value.object_uri, "object_uri"),
    commitToken: nonempty(value.commit_token, "commit_token"),
    expiresAt: nonempty(value.expires_at, "expires_at"),
  };
  validateSlotExtensions(value, slot, prepared);
  return slot;
}

function parseCommit(
  value: Record<string, unknown>,
  slot: AttachmentSlot,
  prepared: PreparedFile,
): { attachment: AttachmentRef; committedAt: string } {
  const required = new Set([
    "committed",
    "attachment_id",
    "object_uri",
    "committed_at",
  ]);
  const extensions = new Set([
    "slot_id",
    "object_id",
    "size",
    "sha256",
    "digest",
    "content_type",
  ]);
  if (!hasRequiredAndKnownFields(value, required, extensions)) {
    throw new Error("attachment service returned an invalid commit result");
  }
  if (
    value.committed !== true ||
    value.attachment_id !== slot.attachmentId ||
    value.object_uri !== slot.objectUri
  ) {
    throw new Error("attachment service returned a mismatched commit result");
  }
  validateCommitExtensions(value, slot, prepared);
  return {
    attachment: {
      attachmentId: slot.attachmentId,
      objectUri: slot.objectUri,
      filename: prepared.filename,
      mimeType: prepared.mimeType,
      size: prepared.size,
      sha256B64u: prepared.sha256B64u,
    },
    committedAt: nonempty(value.committed_at, "committed_at"),
  };
}

function parseDownloadTicket(
  value: Record<string, unknown>,
  requestBody: Record<string, unknown>,
  senderDid: string,
): { value: string; expiresAt: string } {
  const required = new Set([
    "download_ticket_b64u",
    "expires_at",
    "ticket_binding",
  ]);
  const extensions = new Set([
    "ticket",
    "object_id",
    "attachment_id",
    "download_url",
    "download_uri",
    "download_headers",
  ]);
  if (!hasRequiredAndKnownFields(value, required, extensions)) {
    throw new Error(
      "attachment service returned an invalid download-ticket result",
    );
  }
  const binding = value.ticket_binding;
  if (
    typeof binding !== "object" ||
    binding === null ||
    Array.isArray(binding)
  ) {
    throw new Error(
      "attachment service returned a mismatched download-ticket binding",
    );
  }
  const expected: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(requestBody)) {
    if (key !== "one_time") {
      expected[key] = item;
    }
  }
  const bindingRecord = binding as Record<string, unknown>;
  const bindingWithoutSender = Object.fromEntries(
    Object.entries(bindingRecord).filter(([key]) => key !== "sender_did"),
  );
  if (
    !sameRecord(bindingWithoutSender, expected) ||
    ("sender_did" in bindingRecord && bindingRecord.sender_did !== senderDid)
  ) {
    throw new Error(
      "attachment service returned a mismatched download-ticket binding",
    );
  }
  const expiresAt = nonempty(value.expires_at, "expires_at");
  requireUnexpired(expiresAt, "attachment download ticket");
  const ticket = nonempty(value.download_ticket_b64u, "download ticket");
  validateTicketExtensions(value, requestBody, ticket);
  return {
    value: ticket,
    expiresAt,
  };
}

function hasRequiredAndKnownFields(
  value: Record<string, unknown>,
  required: Set<string>,
  extensions: Set<string>,
): boolean {
  const keys = Object.keys(value);
  return (
    [...required].every((key) => key in value) &&
    keys.every((key) => required.has(key) || extensions.has(key))
  );
}

function validateSlotExtensions(
  value: Record<string, unknown>,
  slot: AttachmentSlot,
  prepared: PreparedFile,
): void {
  for (const field of ["object_id", "upload_token"]) {
    if (field in value) nonempty(value[field], field);
  }
  if ("upload_url" in value && value.upload_url !== slot.uploadUri) {
    throw new Error("attachment service returned a mismatched upload URL");
  }
  if (
    "expected_size" in value &&
    String(value.expected_size) !== String(prepared.size)
  ) {
    throw new Error("attachment service returned a mismatched expected size");
  }
  if ("expected_digest" in value) {
    const digest = asObject(value.expected_digest);
    if (digest.alg !== "sha-256" || digest.value_b64u !== prepared.sha256B64u) {
      throw new Error(
        "attachment service returned a mismatched expected digest",
      );
    }
  }
  if ("content_type" in value && value.content_type !== prepared.mimeType) {
    throw new Error("attachment service returned a mismatched content type");
  }
}

function validateCommitExtensions(
  value: Record<string, unknown>,
  slot: AttachmentSlot,
  prepared: PreparedFile,
): void {
  if ("slot_id" in value && value.slot_id !== slot.slotId) {
    throw new Error("attachment service returned a mismatched slot identifier");
  }
  if ("object_id" in value) nonempty(value.object_id, "object_id");
  if ("size" in value && String(value.size) !== String(prepared.size)) {
    throw new Error("attachment service returned a mismatched committed size");
  }
  const expectedHex = Buffer.from(prepared.sha256B64u, "base64url").toString(
    "hex",
  );
  if ("sha256" in value && value.sha256 !== expectedHex) {
    throw new Error(
      "attachment service returned a mismatched committed digest",
    );
  }
  if ("digest" in value) {
    const digest = asObject(value.digest);
    if (digest.alg !== "sha-256" || digest.value_b64u !== prepared.sha256B64u) {
      throw new Error(
        "attachment service returned a mismatched committed digest",
      );
    }
  }
  if ("content_type" in value && value.content_type !== prepared.mimeType) {
    throw new Error("attachment service returned a mismatched content type");
  }
}

function validateTicketExtensions(
  value: Record<string, unknown>,
  requestBody: Record<string, unknown>,
  ticket: string,
): void {
  if ("ticket" in value && value.ticket !== ticket) {
    throw new Error("attachment service returned a mismatched download ticket");
  }
  if ("object_id" in value) nonempty(value.object_id, "object_id");
  if (
    "attachment_id" in value &&
    value.attachment_id !== requestBody.attachment_id
  ) {
    throw new Error(
      "attachment service returned a mismatched attachment identifier",
    );
  }
  if ("download_url" in value) nonempty(value.download_url, "download_url");
  if ("download_uri" in value) nonempty(value.download_uri, "download_uri");
  if (
    "download_url" in value &&
    "download_uri" in value &&
    value.download_url !== value.download_uri
  ) {
    throw new Error("attachment service returned mismatched download URLs");
  }
  if ("download_headers" in value) {
    const headers = asObject(value.download_headers);
    if (!sameRecord(headers, { Authorization: `Bearer ${ticket}` })) {
      throw new Error("attachment service returned invalid download headers");
    }
  }
}

function sameRecord(
  left: Record<string, unknown>,
  right: Record<string, unknown>,
): boolean {
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  if (leftKeys.join(",") !== rightKeys.join(",")) {
    return false;
  }
  return leftKeys.every((key) => left[key] === right[key]);
}

function requireUnexpired(
  value: string,
  subject = "attachment upload slot",
): void {
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(
      value,
    )
  ) {
    throw new Error("attachment service returned an invalid expires_at");
  }
  const expires = Date.parse(value);
  if (Number.isNaN(expires) || expires <= Date.now()) {
    throw new Error(`${subject} has expired`);
  }
}

function decimalSize(value: unknown, field: string): number {
  if (typeof value !== "string" || !/^[0-9]+$/.test(value)) {
    throw new Error(`attachment service returned an invalid ${field}`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`attachment service returned an invalid ${field}`);
  }
  return parsed;
}

function asObject(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("service returned an invalid result");
  }
  return value as Record<string, unknown>;
}
