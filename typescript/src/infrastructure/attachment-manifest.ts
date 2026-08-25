import { basename } from "node:path";

import { InvalidInputError } from "../application/errors.js";
import type { AttachmentRef } from "../domain/models.js";

export const MAX_CAPTION_CHARS = 4096;
export const MANIFEST_CONTENT_TYPE = "application/anp-attachment-manifest+json";

export function normalizeCaption(
  value: string | null | undefined,
): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  if (value.length > MAX_CAPTION_CHARS) {
    throw new InvalidInputError(
      `attachment caption must not exceed ${MAX_CAPTION_CHARS} characters`,
    );
  }
  return value === "" ? null : value;
}

export function buildManifest(
  attachment: AttachmentRef,
  caption: string | null,
): Record<string, unknown> {
  const normalized = normalizeCaption(caption);
  validateRef(attachment);
  const manifest: Record<string, unknown> = {
    attachments: [
      {
        attachment_id: attachment.attachmentId,
        filename: attachment.filename,
        mime_type: attachment.mimeType,
        size: String(attachment.size),
        digest: { alg: "sha-256", value_b64u: attachment.sha256B64u },
        access_info: { object_uri: attachment.objectUri },
        encryption_info: { mode: "none" },
      },
    ],
    primary_attachment_id: attachment.attachmentId,
  };
  if (normalized !== null) {
    manifest.caption = normalized;
  }
  return manifest;
}

export function parseManifest(value: unknown): [AttachmentRef, string | null] {
  const manifest = asObject(value, "attachment Manifest");
  const keys = new Set(Object.keys(manifest));
  const allowed =
    (keys.size === 2 &&
      keys.has("attachments") &&
      keys.has("primary_attachment_id")) ||
    (keys.size === 3 &&
      keys.has("attachments") &&
      keys.has("caption") &&
      keys.has("primary_attachment_id"));
  if (!allowed) {
    throw new Error(
      "message contains an unsupported attachment Manifest shape",
    );
  }
  const attachments = manifest.attachments;
  if (!Array.isArray(attachments) || attachments.length !== 1) {
    throw new Error("message does not contain exactly one attachment");
  }
  const item = asObject(attachments[0], "attachment entry");
  if (
    !sameKeys(item, [
      "attachment_id",
      "filename",
      "mime_type",
      "size",
      "digest",
      "access_info",
      "encryption_info",
    ])
  ) {
    throw new Error("message contains an unsupported attachment entry");
  }
  const digest = asObject(item.digest, "attachment digest");
  const access = asObject(item.access_info, "attachment access info");
  const encryption = asObject(
    item.encryption_info,
    "attachment encryption info",
  );
  if (!sameKeys(digest, ["alg", "value_b64u"]) || digest.alg !== "sha-256") {
    throw new Error("message contains an invalid attachment digest");
  }
  if (!sameKeys(access, ["object_uri"])) {
    throw new Error("message contains invalid attachment access info");
  }
  if (encryption.mode !== "none" || Object.keys(encryption).length !== 1) {
    throw new Error("message attachment is not a plain P7 object");
  }
  const ref: AttachmentRef = {
    attachmentId: requiredString(item.attachment_id, "attachment id"),
    objectUri: objectUri(access.object_uri),
    filename: filenameOf(item.filename),
    mimeType: mimeTypeOf(item.mime_type),
    size: sizeOf(item.size),
    sha256B64u: digestOf(digest.value_b64u),
  };
  if (manifest.primary_attachment_id !== ref.attachmentId) {
    throw new Error("message contains a mismatched primary attachment id");
  }
  const captionValue = manifest.caption;
  if (captionValue !== undefined && typeof captionValue !== "string") {
    throw new Error("message contains an invalid attachment caption");
  }
  try {
    return [ref, normalizeCaption(captionValue ?? null)];
  } catch {
    throw new Error("message contains an invalid attachment caption");
  }
}

function validateRef(value: AttachmentRef): void {
  const [parsed] = parseManifest({
    attachments: [
      {
        attachment_id: value.attachmentId,
        filename: value.filename,
        mime_type: value.mimeType,
        size: String(value.size),
        digest: { alg: "sha-256", value_b64u: value.sha256B64u },
        access_info: { object_uri: value.objectUri },
        encryption_info: { mode: "none" },
      },
    ],
    primary_attachment_id: value.attachmentId,
  });
  if (JSON.stringify(parsed) !== JSON.stringify(value)) {
    throw new Error("attachment reference is invalid");
  }
}

function filenameOf(value: unknown): string {
  const filename = requiredString(value, "attachment filename");
  if (
    filename === "." ||
    filename === ".." ||
    basename(filename) !== filename ||
    filename.includes("/") ||
    filename.includes("\\") ||
    filename.includes("\0") ||
    Buffer.byteLength(filename) > 255 ||
    [...filename].some((character) => {
      const code = character.charCodeAt(0);
      return code < 32 || code === 127;
    })
  ) {
    throw new Error("message contains an unsafe attachment filename");
  }
  return filename;
}

function mimeTypeOf(value: unknown): string {
  const mime = requiredString(value, "attachment MIME type");
  if (mime.length > 255 || mime.includes("\r") || mime.includes("\n")) {
    throw new Error("message contains an invalid attachment MIME type");
  }
  return mime;
}

function digestOf(value: unknown): string {
  const encoded = requiredString(value, "attachment digest");
  if (encoded.length !== 43) {
    throw new Error("message contains an invalid SHA-256 digest");
  }
  const decoded = Buffer.from(encoded, "base64url");
  if (decoded.length !== 32 || decoded.toString("base64url") !== encoded) {
    throw new Error("message contains an invalid SHA-256 digest");
  }
  return encoded;
}

function objectUri(value: unknown): string {
  const uri = requiredString(value, "attachment object URI");
  if (!uri.startsWith("https://")) {
    throw new Error("message contains an unsafe attachment object URI");
  }
  return uri;
}

function sizeOf(value: unknown): number {
  if (typeof value !== "string" || !/^[0-9]+$/.test(value)) {
    throw new Error("message contains an invalid attachment size");
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error("message contains an invalid attachment size");
  }
  return parsed;
}

function requiredString(value: unknown, field: string): string {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > 1024 ||
    [...value].some((character) => {
      const code = character.charCodeAt(0);
      return code < 32 || code === 127;
    })
  ) {
    throw new Error(`message contains an invalid ${field}`);
  }
  return value;
}

function asObject(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`message contains an invalid ${field}`);
  }
  return value as Record<string, unknown>;
}

function sameKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const keys = Object.keys(value);
  return (
    keys.length === expected.length &&
    expected.every((key) => keys.includes(key))
  );
}
