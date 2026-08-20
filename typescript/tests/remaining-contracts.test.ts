import { describe, expect, test } from 'vitest';

import { parseManifest } from '../src/infrastructure/attachment-manifest.js';
import { parseSyncChanged, websocketUrl } from '../src/infrastructure/listener.js';
import { validatePendingInput } from '../src/infrastructure/state.js';
import { defaultStateDir, DEFAULT_SERVICE_URL, DEFAULT_STATE_APPNAME } from '../src/config.js';

describe('remaining TypeScript contracts', () => {
  test('default appname remains isolated from Python state', () => {
    expect(DEFAULT_SERVICE_URL).toBe('https://awiki.ai');
    expect(DEFAULT_STATE_APPNAME).toBe('awiki-lite-cli-ts');
    expect(defaultStateDir(DEFAULT_STATE_APPNAME)).toContain('awiki-lite-cli-ts');
  });

  test('listener websocket path and subprotocol payload parser', () => {
    expect(websocketUrl('https://awiki.info')).toBe('wss://awiki.info/im/ws');
    const event = parseSyncChanged(
      JSON.stringify({
        method: 'sync.changed',
        payload: { domains: ['inbox'], reason: 'new-message' },
        sync: { schema_version: 2, account_scan_seq_hint: '3', domain_versions: { inbox: '1' } },
      }),
    );
    expect(event.domains).toEqual(['inbox']);
  });

  test('pending values still allow the forbidden substrings in values', () => {
    expect(() =>
      validatePendingInput('direct.send', 'did:wba:example.com:user:bob', 'ab'.repeat(32), {
        caption: 'the header of the report',
      }),
    ).not.toThrow();
  });

  test('manifest still rejects extra attachment keys', () => {
    expect(() =>
      parseManifest({
        attachments: [
          {
            attachment_id: 'a',
            filename: 'f.txt',
            mime_type: 'text/plain',
            size: '1',
            digest: { alg: 'sha-256', value_b64u: Buffer.alloc(32, 1).toString('base64url') },
            access_info: { object_uri: 'https://example.com/o' },
            encryption_info: { mode: 'none' },
            extra: true,
          },
        ],
        primary_attachment_id: 'a',
      }),
    ).toThrow(/unsupported attachment entry/);
  });
});
