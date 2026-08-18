import { describe, expect, test } from 'vitest';

import { parseManifest, normalizeCaption, buildManifest } from '../src/infrastructure/attachment-manifest.js';

const ref = {
  attachmentId: 'att-1',
  objectUri: 'https://example.com/obj/1',
  filename: 'report.pdf',
  mimeType: 'application/pdf',
  size: 12,
  sha256B64u: Buffer.alloc(32, 0).toString('base64url'),
};

describe('parse_manifest', () => {
  test('round-trips a closed manifest', () => {
    const manifest = buildManifest(ref, 'hello');
    const [parsed, caption] = parseManifest(manifest);
    expect(parsed).toEqual(ref);
    expect(caption).toBe('hello');
  });

  test('rejects extra keys', () => {
    const manifest = buildManifest(ref, null) as Record<string, unknown>;
    manifest.extra = true;
    expect(() => parseManifest(manifest)).toThrow(/unsupported attachment Manifest shape/);
  });

  test('rejects integer size', () => {
    const manifest = buildManifest(ref, null) as Record<string, unknown>;
    const attachments = manifest.attachments as Array<Record<string, unknown>>;
    attachments[0]!.size = 12;
    expect(() => parseManifest(manifest)).toThrow(/invalid attachment size/);
  });

  test('normalizeCaption enforces 4096', () => {
    expect(normalizeCaption(null)).toBeNull();
    expect(() => normalizeCaption('x'.repeat(4097))).toThrow(/4096/);
  });
});
