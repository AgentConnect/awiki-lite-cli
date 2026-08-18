import { createHash, generateKeyPairSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, test } from 'vitest';

import { GroupWorkflow } from '../src/application/groups.js';
import { stableValues, uuid5FromUrlName } from '../src/application/attachments.js';
import { renderDirectMessages, saveAttachmentContextsFromMessages } from '../src/commands/direct.js';
import { MANIFEST_CONTENT_TYPE, buildManifest } from '../src/infrastructure/attachment-manifest.js';
import { GroupService } from '../src/infrastructure/group-service.js';
import { MessageService } from '../src/infrastructure/message-service.js';
import { SecureStateStore } from '../src/infrastructure/state.js';
import type { PendingOperation, UnlockedIdentity } from '../src/domain/models.js';
import type { HttpClient, HttpResponse } from '../src/infrastructure/rpc.js';

const GROUP_DID = 'did:wba:groups.example.test:group:fixture:e1_group';
const MEMBER_DID = 'did:wba:example.test:user:bob:e1_fixture';
const SERVICE_DID = 'did:wba:message.example.test';
const ALICE_DID = 'did:wba:example.test:user:alice:e1_alice';

const repoRoot = join(fileURLToPath(new URL('../..', import.meta.url)));

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), 'awiki-gdm-'));
}

function digestB64u(): string {
  return Buffer.alloc(32, 3).toString('base64url');
}

function manifest(): Record<string, unknown> {
  return {
    attachments: [
      {
        attachment_id: 'att-inbox',
        filename: 'notes.txt',
        mime_type: 'text/plain',
        size: '4',
        digest: { alg: 'sha-256', value_b64u: digestB64u() },
        access_info: { object_uri: 'https://example.com/objects/notes' },
        encryption_info: { mode: 'none' },
      },
    ],
    primary_attachment_id: 'att-inbox',
    caption: 'see notes',
  };
}

function pythonAttachmentPayload(): Record<string, unknown> {
  const digest = createHash('sha256').update('payload').digest('base64url');
  return buildManifest(
    {
      attachmentId: 'att-fixture',
      objectUri: 'https://objects.example.test/object-1',
      filename: 'group.txt',
      mimeType: 'text/plain',
      size: 7,
      sha256B64u: digest,
    },
    null,
  );
}

function unlockedFixture(): UnlockedIdentity {
  const signing = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const root = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const agreement = generateKeyPairSync('x25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  return {
    identity: {
      did: ALICE_DID,
      handle: 'alice.example.test',
      verificationMethod: `${ALICE_DID}#key-1`,
      deviceId: 'dev-1',
      didDocument: { id: ALICE_DID },
    },
    session: { accessToken: 'fixture-token' },
    rootPrivateKeyPem: root,
    deviceSigningPrivateKeyPem: signing,
    deviceAgreementPrivateKeyPem: agreement,
  };
}

function pending(kind: string, target: string, message = false): PendingOperation {
  return {
    schemaVersion: 2,
    kind,
    targetDid: target,
    inputSha256: createHash('sha256').update('fixture').digest('hex'),
    operationId: `operation-${kind}`,
    messageId: message ? `message-${kind}` : null,
    createdAt: '2026-08-06T00:00:00Z',
    proofCreated: 1785974400,
    proofNonce: `nonce-${kind}`,
    values: {},
    stage: null,
  };
}

function jsonRpcClient(handler: (method: string) => unknown): HttpClient {
  return {
    async post(_url, init): Promise<HttpResponse> {
      const body = JSON.parse(String(init.body)) as { method: string; id: string };
      return {
        status: 200,
        ok: true,
        headers: {},
        async json() {
          return { jsonrpc: '2.0', id: body.id, result: handler(body.method) };
        },
        async bytes() {
          return new Uint8Array();
        },
      };
    },
    async put() {
      throw new Error('unused put');
    },
    async get() {
      throw new Error('unused get');
    },
    async getStream() {
      throw new Error('unused getStream');
    },
  };
}

function seedStore(dir: string): SecureStateStore {
  const store = new SecureStateStore(dir);
  store.initialize();
  const identityPath = join(dir, 'identity.json');
  const sessionPath = join(dir, 'session.json');
  writeFileSync(
    identityPath,
    JSON.stringify({
      did: 'did:wba:example.com:user:alice:e1_alice',
      handle: 'alice.example.com',
      verification_method: 'did:wba:example.com:user:alice:e1_alice#key-1',
      device_id: 'dev-1',
      did_document: { id: 'did:wba:example.com:user:alice:e1_alice' },
    }),
  );
  writeFileSync(sessionPath, JSON.stringify({ access_token: 'tok' }));
  chmodSync(identityPath, 0o600);
  chmodSync(sessionPath, 0o600);
  return store;
}

describe('group messages and dm attachment contexts', () => {
  test('GroupService info/list/create/messages replay the Python wire fixtures', async () => {
    const unlocked = unlockedFixture();
    const authenticated = { identity: unlocked.identity, session: unlocked.session };
    const methods: string[] = [];
    const client = jsonRpcClient((method) => {
      methods.push(method);
      if (method === 'anp.get_capabilities') {
        return {
          service_did: SERVICE_DID,
          supported_profiles: ['anp.group.base.v1', 'anp.attachment.v1'],
          supported_security_profiles: ['transport-protected'],
          supported_content_types: ['text/plain', MANIFEST_CONTENT_TYPE],
          limits: { max_group_message_bytes: '262144' },
        };
      }
      if (method === 'group.create') {
        return {
          accepted: true,
          group_did: GROUP_DID,
          group_state_version: '1',
          group_event_seq: '1',
          created_at: 'now',
          creator_did: unlocked.identity.did,
          group_profile: { display_name: 'Fixture' },
        };
      }
      if (method === 'group.list') {
        return {
          groups: [
            {
              group_did: GROUP_DID,
              group_state_version: '2',
              group_profile: { display_name: 'Fixture' },
              member_count: 2,
              my_role: 'owner',
            },
            {
              group_did: 'did:wba:groups.example.test:group:cipher:e1_group',
              group_state_version: '1',
              group_profile: { display_name: 'Secret' },
              group_policy: { message_security_profile: 'group-e2ee' },
              member_count: 2,
            },
          ],
          total: 1,
          has_more: true,
          next_cursor: 'next',
        };
      }
      if (method === 'group.get_info') {
        return {
          group_did: GROUP_DID,
          group_state_version: '2',
          group_profile: { display_name: 'Fixture' },
          member_count: 2,
        };
      }
      if (method === 'group.list_members') {
        return {
          group_did: GROUP_DID,
          group_state_version: '2',
          members: [{ agent_did: unlocked.identity.did, role: 'owner', status: 'active' }],
          total: 1,
          has_more: false,
        };
      }
      if (method === 'group.list_messages') {
        return {
          messages: [
            {
              message_id: 'plain',
              group_did: GROUP_DID,
              sender_did: unlocked.identity.did,
              type: 'text',
              content: 'hello',
              content_type: 'text/plain',
              group_event_seq: '3',
              sent_at: 'now',
            },
            {
              message_id: 'attachment',
              group_did: GROUP_DID,
              sender_did: unlocked.identity.did,
              type: 'attachment_manifest',
              content: pythonAttachmentPayload(),
              content_type: MANIFEST_CONTENT_TYPE,
              group_event_seq: '4',
              sent_at: 'now',
            },
            {
              message_id: 'cipher',
              group_did: GROUP_DID,
              sender_did: unlocked.identity.did,
              type: 'group_e2ee_cipher',
              content: {},
              content_type: 'application/json',
              group_event_seq: '5',
            },
          ],
          total: 2,
          has_more: false,
          next_since_seq: 5,
        };
      }
      throw new Error(`unexpected method ${method}`);
    });
    const service = new GroupService(client, 'https://example.test');
    const created = await service.create(
      unlocked,
      SERVICE_DID,
      'Fixture',
      500,
      pending('group.create', SERVICE_DID),
    );
    expect(created.displayName).toBe('Fixture');
    expect(created.groupDid).toBe(GROUP_DID);
    const [groups, cursor] = await service.listGroups(authenticated, 20, null);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.displayName).toBe('Fixture');
    expect(groups[0]?.myRole).toBe('owner');
    expect(cursor).toBe('next');
    const info = await service.info(authenticated, GROUP_DID);
    expect(info.displayName).toBe('Fixture');
    const [members] = await service.members(authenticated, GROUP_DID, 20, null);
    expect(members[0]?.role).toBe('owner');
    const [messages, nextSeq] = await service.messages(authenticated, GROUP_DID, 20, null);
    expect(messages.map((item) => item.messageId)).toEqual(['plain', 'attachment']);
    expect(messages[0]?.content).toBe('hello');
    expect(typeof messages[0]?.content).toBe('string');
    expect(messages[0]?.createdAt).toBe('now');
    expect(nextSeq).toBe(5);
    expect(methods).toEqual([
      'group.create',
      'group.list',
      'group.get_info',
      'group.list_members',
      'group.list_messages',
    ]);
    void MEMBER_DID;
  });

  test('group info without group_profile.display_name fails closed', async () => {
    const unlocked = unlockedFixture();
    const client = jsonRpcClient((method) => {
      expect(method).toBe('group.get_info');
      return {
        group_did: GROUP_DID,
        group_state_version: '2',
        member_count: 2,
      };
    });
    await expect(
      new GroupService(client, 'https://example.test').info(
        { identity: unlocked.identity, session: unlocked.session },
        GROUP_DID,
      ),
    ).rejects.toThrow(/display name/);
  });

  test('group messages persist attachment contexts from Manifest rows', async () => {
    const dir = tempDir();
    const store = seedStore(dir);
    const payload = pythonAttachmentPayload();
    const client = jsonRpcClient((method) => {
      expect(method).toBe('group.list_messages');
      return {
        messages: [
          {
            message_id: 'attachment',
            group_did: GROUP_DID,
            sender_did: ALICE_DID,
            type: 'attachment_manifest',
            message_type: 'text',
            content: payload,
            content_type: MANIFEST_CONTENT_TYPE,
            group_event_seq: '4',
            sent_at: 'now',
          },
        ],
        next_since_seq: 5,
      };
    });
    const workflow = new GroupWorkflow(new GroupService(client, 'https://example.test'), store);
    const [rows] = await workflow.messages(GROUP_DID, 20, null);
    expect(rows[0]?.messageType).toBe('attachment_manifest');
    const saved = store.loadAttachmentContext('attachment', 'att-fixture');
    expect(saved.attachment.filename).toBe('group.txt');
    expect(saved.groupDid).toBe(GROUP_DID);
  });

  test('dm inbox saves contexts and renders [attachment] rows', async () => {
    const dir = tempDir();
    const store = seedStore(dir);
    const identity = { identity: store.loadPublic(), session: store.loadSession() };
    const client = jsonRpcClient((method) => {
      expect(method).toBe('inbox.get');
      return {
        messages: [
          {
            message_id: 'm-dm',
            sender_did: 'did:wba:example.com:user:bob:e1_bob',
            target_did: identity.identity.did,
            created_at: '2026-01-03T00:00:00Z',
            content_type: 'application/anp-attachment-manifest+json',
            payload: manifest(),
          },
        ],
        has_more: false,
      };
    });
    const service = new MessageService(client, 'https://example.com');
    const [messages] = await service.inbox(identity, 20, 0);
    saveAttachmentContextsFromMessages(store, messages);
    const lines = renderDirectMessages(messages);
    expect(lines[0]).toContain('[attachment notes.txt id=att-inbox message=m-dm]');
    expect(lines[0]).toContain('caption=see notes');
    const saved = store.loadAttachmentContext('m-dm', 'att-inbox');
    expect(saved.messageTargetDid).toBe(identity.identity.did);
    expect(saved.groupDid).toBeNull();
  });

  test('uuid5 stable attachment ids match Python NAMESPACE_URL', () => {
    const name =
      'awiki-lite:v0.2:did:wba:example.com:user:alice:e1_alice:direct.attachment.send:did:wba:example.com:user:bob:e1_bob:deadbeef:attachment';
    const python = spawnSync(
      'uv',
      ['run', 'python', '-c', `from uuid import NAMESPACE_URL, uuid5; print(uuid5(NAMESPACE_URL, ${JSON.stringify(name)}))`],
      { cwd: repoRoot, encoding: 'utf8' },
    );
    expect(python.status).toBe(0);
    expect(uuid5FromUrlName(name)).toBe(python.stdout.trim());
    const first = stableValues(
      'did:wba:example.com:user:alice:e1_alice',
      'direct.attachment.send',
      'did:wba:example.com:user:bob:e1_bob',
      'ab'.repeat(32),
    );
    const second = stableValues(
      'did:wba:example.com:user:alice:e1_alice',
      'direct.attachment.send',
      'did:wba:example.com:user:bob:e1_bob',
      'ab'.repeat(32),
    );
    expect(first).toEqual(second);
    expect(first.attachment_id.startsWith('att-')).toBe(true);
  });
});
