import { createHash, generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { AttachmentWorkflow } from "../src/application/attachments.js";
import {
  InvalidInputError,
  JsonRpcFailure,
} from "../src/application/errors.js";
import { renderGroups, renderMembers } from "../src/commands/groups.js";
import {
  ATTACHMENT_PROFILE,
  selectAttachmentServiceDid,
} from "../src/infrastructure/anp-sdk.js";
import {
  AttachmentService,
  prepareFile,
} from "../src/infrastructure/attachment-service.js";
import { MessageService } from "../src/infrastructure/message-service.js";
import { SecureStateStore } from "../src/infrastructure/state.js";
import type { HttpClient, HttpResponse } from "../src/infrastructure/rpc.js";

const ALICE = "did:wba:example.test:user:alice:e1_alice";
const BOB = "did:wba:example.test:user:bob:e1_bob";
const SERVICE = "did:wba:message.example.test";

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "awiki-fix-"));
}

function jsonRpcClient(
  handler: (method: string, params: Record<string, unknown>) => unknown,
): HttpClient {
  return {
    async post(_url, init): Promise<HttpResponse> {
      const body = JSON.parse(String(init.body)) as {
        method: string;
        id: string;
        params: Record<string, unknown>;
      };
      return {
        status: 200,
        ok: true,
        headers: {},
        async json() {
          return {
            jsonrpc: "2.0",
            id: body.id,
            result: handler(body.method, body.params),
          };
        },
        async bytes() {
          return new Uint8Array();
        },
      };
    },
    async put() {
      throw new Error("unused put");
    },
    async get() {
      throw new Error("unused get");
    },
    async getStream() {
      throw new Error("unused getStream");
    },
  };
}

describe("core protocol regressions", () => {
  test("JsonRpcFailure keeps the RPC message for unauthorized mapping", () => {
    const error = new JsonRpcFailure(-32001, "Unauthorized", null);
    expect(error.message).toBe("JSON-RPC request failed with code -32001");
    expect(error.rpcMessage).toBe("Unauthorized");
  });

  test("mark_read uses updated_count and defaults to zero", async () => {
    const identity = {
      identity: {
        did: ALICE,
        handle: "alice.example.test",
        verificationMethod: `${ALICE}#key-1`,
        deviceId: "dev-1",
        didDocument: { id: ALICE },
      },
      session: { accessToken: "token" },
    };
    const missing = new MessageService(
      jsonRpcClient(() => ({})),
      "https://example.test",
    );
    await expect(missing.markRead(identity, ["m1"])).resolves.toBe(0);
    const counted = new MessageService(
      jsonRpcClient(() => ({ updated_count: 2 })),
      "https://example.test",
    );
    await expect(counted.markRead(identity, ["m1", "m2"])).resolves.toBe(2);
  });

  test("direct preflight accepts the Open Server proof policy", async () => {
    const identity = {
      identity: {
        did: ALICE,
        handle: "alice.example.test",
        verificationMethod: `${ALICE}#key-1`,
        deviceId: "dev-1",
        didDocument: { id: ALICE },
      },
      session: { accessToken: "token" },
    };
    const service = new MessageService(
      jsonRpcClient(() => ({
        supported_profiles: ["anp.direct.base.v1"],
        supported_security_profiles: ["transport-protected"],
        supported_content_types: ["text/plain"],
        proof_policies: {
          direct_base_origin_proof:
            "required_for_canonical_local_and_cross_domain",
        },
      })),
      "https://example.test",
    );
    await expect(service.ensureDirectBase(identity)).resolves.toBeUndefined();
  });

  test("attachment capabilities reject a non-decimal size cap", async () => {
    const identity = {
      identity: {
        did: ALICE,
        handle: "alice.example.test",
        verificationMethod: `${ALICE}#key-1`,
        deviceId: "dev-1",
        didDocument: { id: ALICE },
      },
      session: { accessToken: "token" },
    };
    const service = new AttachmentService(
      jsonRpcClient(() => ({
        supported_profiles: [ATTACHMENT_PROFILE],
        supported_security_profiles: ["transport-protected"],
        supported_content_types: ["application/anp-attachment-manifest+json"],
        service_did: SERVICE,
        limits: { max_object_bytes: "nope" },
      })),
      "https://example.test",
    );
    await expect(service.capabilities(identity)).rejects.toThrow(
      /invalid max_object_bytes/,
    );
    const openServer = new AttachmentService(
      jsonRpcClient(() => ({
        supported_profiles: [ATTACHMENT_PROFILE],
        supported_security_profiles: ["transport-protected"],
        supported_content_types: ["application/anp-attachment-manifest+json"],
        service_did: SERVICE,
        limits: { max_attachment_bytes: "10485760" },
      })),
      "https://example.test",
    );
    await expect(openServer.capabilities(identity)).resolves.toMatchObject({
      maxObjectBytes: 10485760,
    });
    const unsafeLimit = new AttachmentService(
      jsonRpcClient(() => ({
        supported_profiles: [ATTACHMENT_PROFILE],
        supported_security_profiles: ["transport-protected"],
        supported_content_types: ["application/anp-attachment-manifest+json"],
        service_did: SERVICE,
        limits: { max_object_bytes: "9007199254740993" },
      })),
      "https://example.test",
    );
    await expect(unsafeLimit.capabilities(identity)).rejects.toThrow(
      /invalid max_object_bytes/,
    );
  });

  test("missing attachment path is invalid input", () => {
    expect(() => prepareFile(join(tempDir(), "missing.bin"), 1024)).toThrow(
      InvalidInputError,
    );
  });

  test("commit rejects an empty result", async () => {
    const dir = tempDir();
    const path = join(dir, "a.txt");
    writeFileSync(path, "hello");
    const prepared = prepareFile(path, 1024);
    const identity = {
      identity: {
        did: ALICE,
        handle: "alice.example.test",
        verificationMethod: `${ALICE}#key-1`,
        deviceId: "dev-1",
        didDocument: { id: ALICE },
      },
      session: { accessToken: "token" },
      rootPrivateKeyPem: "x",
      deviceSigningPrivateKeyPem: "x",
      deviceAgreementPrivateKeyPem: "x",
    };
    const service = new AttachmentService(
      jsonRpcClient(() => ({})),
      "https://example.test",
    );
    try {
      await expect(
        service.commit(
          identity,
          SERVICE,
          {
            attachmentId: "att-1",
            slotId: "slot-1",
            uploadUri: "https://example.com/upload",
            uploadHeaders: {},
            objectUri: "https://example.com/objects/blob",
            commitToken: "commit",
            expiresAt: "2099-01-01T00:00:00Z",
          },
          prepared,
          "op",
          "2026-08-06T00:00:00Z",
        ),
      ).rejects.toThrow(/invalid commit/);
    } finally {
      prepared.close();
    }
  });

  test("accepts validated Open Server attachment control responses", async () => {
    const dir = tempDir();
    const path = join(dir, "open.txt");
    const raw = Buffer.from("open server attachment");
    writeFileSync(path, raw);
    const prepared = prepareFile(path, 1024);
    const objectUri = "https://example.com/objects/object-open";
    const expiresAt = "2099-08-06T00:10:00Z";
    const identity = {
      identity: {
        did: ALICE,
        handle: "alice.example.test",
        verificationMethod: `${ALICE}#key-1`,
        deviceId: "dev-1",
        didDocument: { id: ALICE },
      },
      session: { accessToken: "token" },
      rootPrivateKeyPem: "unused",
      deviceSigningPrivateKeyPem: "unused",
      deviceAgreementPrivateKeyPem: "unused",
    };
    const service = new AttachmentService(
      jsonRpcClient((method, params) => {
        if (method === "attachment.create_slot") {
          return {
            attachment_id: "att-open",
            slot_id: "slot-open",
            object_id: "object-open",
            upload_token: "upload-open",
            upload_headers: { "X-ANP-Upload-Token": "upload-open" },
            commit_token: "commit-open",
            upload_url: "https://example.com/objects/upload/slot-open",
            upload_uri: "https://example.com/objects/upload/slot-open",
            object_uri: objectUri,
            expires_at: expiresAt,
            expected_size: raw.length,
            expected_digest: {
              alg: "sha-256",
              value_b64u: prepared.sha256B64u,
            },
            content_type: "text/plain",
          };
        }
        if (method === "attachment.commit_object") {
          return {
            committed: true,
            attachment_id: "att-open",
            slot_id: "slot-open",
            object_id: "object-open",
            object_uri: objectUri,
            committed_at: "2099-08-06T00:01:00Z",
            size: raw.length,
            sha256: createHash("sha256").update(raw).digest("hex"),
            digest: { alg: "sha-256", value_b64u: prepared.sha256B64u },
            content_type: "text/plain",
          };
        }
        const requestBody = params.body as Record<string, unknown>;
        return {
          ticket: "ticket-open",
          download_ticket_b64u: "ticket-open",
          object_id: "object-open",
          attachment_id: "att-open",
          download_url:
            "https://example.com/objects/object-open?ticket=ticket-open",
          download_uri:
            "https://example.com/objects/object-open?ticket=ticket-open",
          download_headers: { Authorization: "Bearer ticket-open" },
          ticket_binding: {
            ...Object.fromEntries(
              Object.entries(requestBody).filter(([key]) => key !== "one_time"),
            ),
            sender_did: BOB,
          },
          expires_at: expiresAt,
        };
      }),
      "https://example.test",
      false,
      async () => SERVICE,
    );
    try {
      const slot = await service.createSlot(
        identity,
        SERVICE,
        "att-open",
        prepared,
        "agent",
        ALICE,
        "create-open",
        "2026-08-06T00:00:00Z",
      );
      const committed = await service.commit(
        identity,
        SERVICE,
        slot,
        prepared,
        "commit-open",
        "2026-08-06T00:00:00Z",
      );
      const ticket = await service.getDownloadTicket(identity, {
        messageId: "message-open",
        senderDid: BOB,
        messageTargetDid: ALICE,
        groupDid: null,
        attachment: {
          attachmentId: "att-open",
          objectUri,
          filename: "open.txt",
          mimeType: "text/plain",
          size: raw.length,
          sha256B64u: prepared.sha256B64u,
        },
      });
      expect(committed.attachment.objectUri).toBe(objectUri);
      expect(ticket.value).toBe("ticket-open");
    } finally {
      prepared.close();
    }
  });

  test("direct send rejects a non-string accepted_at", async () => {
    const signing = generateKeyPairSync("ed25519")
      .privateKey.export({ type: "pkcs8", format: "pem" })
      .toString();
    const identity = {
      identity: {
        did: ALICE,
        handle: "alice.example.test",
        verificationMethod: `${ALICE}#key-1`,
        deviceId: "dev-1",
        didDocument: { id: ALICE },
      },
      session: { accessToken: "token" },
      rootPrivateKeyPem: signing,
      deviceSigningPrivateKeyPem: signing,
      deviceAgreementPrivateKeyPem: signing,
    };
    const service = new MessageService(
      jsonRpcClient((_method, params) => {
        const meta = params.meta as Record<string, unknown>;
        return {
          accepted: true,
          message_id: meta.message_id,
          operation_id: meta.operation_id,
          target_did: BOB,
          accepted_at: null,
        };
      }),
      "https://example.test",
    );
    await expect(
      service.send(identity, BOB, "hello", {}, false),
    ).rejects.toThrow(/invalid direct.send/);
  });

  test("group and member rendering matches the Python contract", () => {
    expect(renderGroups([])).toEqual(["No ordinary groups."]);
    expect(
      renderGroups([
        {
          displayName: "Room",
          groupDid: "did:wba:example.test:group:one",
          memberCount: 3,
          myRole: "owner",
        },
      ]),
    ).toEqual(["Room (did:wba:example.test:group:one) members=3 role=owner"]);
    expect(renderMembers([])).toEqual(["No group members."]);
  });

  test("selectAttachmentServiceDid requires the plain attachment profile", () => {
    const document = {
      id: ALICE,
      service: [
        {
          type: "ANPMessageService",
          serviceEndpoint: "https://message.example.test/anp-im/rpc",
          serviceDid: SERVICE,
          profiles: [ATTACHMENT_PROFILE],
          securityProfiles: ["transport-protected"],
        },
      ],
    };
    expect(selectAttachmentServiceDid(ALICE, document)).toBe(SERVICE);
    document.service[0]!.profiles = ["anp.attachment.v2"];
    expect(() => selectAttachmentServiceDid(ALICE, document)).toThrow(
      /compatible service/,
    );
  });

  test("upload failure aborts the slot and discards pending state", async () => {
    const root = tempDir();
    const store = new SecureStateStore(root);
    store.initialize();
    const identityPath = join(root, "identity.json");
    const sessionPath = join(root, "session.json");
    writeFileSync(
      identityPath,
      JSON.stringify({
        did: ALICE,
        handle: "alice.example.test",
        verification_method: `${ALICE}#key-1`,
        device_id: "dev-1",
        did_document: { id: ALICE },
      }),
    );
    writeFileSync(sessionPath, JSON.stringify({ access_token: "token" }));
    chmodSync(identityPath, 0o600);
    chmodSync(sessionPath, 0o600);
    const file = join(root, "note.txt");
    writeFileSync(file, "hello");
    const aborted: string[] = [];
    const attachments = {
      async capabilities() {
        return { serviceDid: SERVICE, maxObjectBytes: 1024 };
      },
      async createSlot() {
        return {
          attachmentId: "att-1",
          slotId: "slot-1",
          uploadUri: "https://objects.example.test/upload",
          uploadHeaders: {},
          objectUri: "https://objects.example.test/object",
          commitToken: "commit",
          expiresAt: "2099-01-01T00:00:00Z",
        };
      },
      async upload() {
        throw new Error("attachment upload failed with HTTP 500");
      },
      async bestEffortAbort(
        _identity: unknown,
        _serviceDid: string,
        _slot: unknown,
        operationId: string,
      ) {
        aborted.push(operationId);
      },
      async commit() {
        throw new Error("commit should not run");
      },
    };
    const workflow = new AttachmentWorkflow(
      attachments as never,
      {
        async ensureDirectBase() {
          return;
        },
        async sendAttachment() {
          throw new Error("send should not run");
        },
      } as never,
      {
        async capabilities() {
          return { serviceDid: SERVICE, maxGroupMessageBytes: null };
        },
      } as never,
      store,
    );
    const signing = generateKeyPairSync("ed25519")
      .privateKey.export({ type: "pkcs8", format: "pem" })
      .toString();
    await expect(
      workflow.send(
        {
          identity: {
            did: ALICE,
            handle: "alice.example.test",
            verificationMethod: `${ALICE}#key-1`,
            deviceId: "dev-1",
            didDocument: { id: ALICE },
          },
          session: { accessToken: "token" },
          rootPrivateKeyPem: signing,
          deviceSigningPrivateKeyPem: signing,
          deviceAgreementPrivateKeyPem: signing,
        },
        file,
        {
          recipientDid: "did:wba:example.test:user:bob:e1_bob",
          groupDid: null,
          caption: null,
        },
      ),
    ).rejects.toThrow(/upload failed/);
    expect(aborted).toHaveLength(1);
    expect(existsSync(join(root, "pending-send.json"))).toBe(false);
  });
});
