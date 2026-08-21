import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { SyncRecoveryRequiredError } from "../src/application/errors.js";
import { historyWithSync, inboxWithSync } from "../src/commands/direct.js";
import {
  MessageService,
  buildSyncBootstrap,
} from "../src/infrastructure/message-service.js";
import { SecureStateStore } from "../src/infrastructure/state.js";

const identity = {
  identity: {
    did: "did:wba:example.com:user:alice:e1_alice",
    handle: "alice.example.com",
    verificationMethod: "did:wba:example.com:user:alice:e1_alice#key-1",
    deviceId: "dev-1",
    didDocument: { id: "did:wba:example.com:user:alice:e1_alice" },
  },
  session: { accessToken: "token-1" },
};

function clientFor(result: () => Record<string, unknown>) {
  return {
    async post(
      _url: string,
      init: { headers: Record<string, string>; body: string },
    ) {
      const request = JSON.parse(init.body) as { id: string; method: string };
      expect(request.method).toBe("sync.bootstrap");
      expect(init.headers.Authorization).toBe("Bearer token-1");
      return {
        status: 200,
        ok: true,
        headers: {},
        async json() {
          return { jsonrpc: "2.0", id: request.id, result: result() };
        },
        async bytes() {
          return new Uint8Array();
        },
      };
    },
  } as never;
}

describe("Sync V2 bootstrap", () => {
  test("builds the narrow v2 capability request", () => {
    const params = buildSyncBootstrap(
      identity.identity.did,
      "lite-installation-fixture",
    );
    expect(params.meta).toMatchObject({
      profile: "anp.sync.local.v2",
      security_profile: "transport-protected",
      sender_did: identity.identity.did,
    });
    expect(params.body).toEqual({
      client_instance_id: "lite-installation-fixture",
      capabilities: {
        sync_profile: "anp.sync.local.v2",
        event_schema_max: 1,
      },
    });
  });

  test("accepts tail_only and rejects compact recovery", async () => {
    let mode = "tail_only";
    const service = new MessageService(
      clientFor(() =>
        mode === "tail_only"
          ? {
              mode,
              account_id: "account-1",
              device_id: "dev-1",
              server_time: "2026-08-21T00:00:00Z",
              cursor: { stream_epoch: "1", scan_seq: "7" },
              read_state_baseline: [],
              group_state_baseline: [],
              warnings: [],
            }
          : {
              mode: "compact_recovery_required",
              recovery: { token: "secret" },
            },
      ),
      "https://example.com",
    );
    await expect(
      service.bootstrapSync(identity, "lite-installation-fixture"),
    ).resolves.toMatchObject({ deviceId: "dev-1", scanSeq: "7" });
    mode = "compact_recovery_required";
    await expect(
      service.bootstrapSync(identity, "lite-installation-fixture"),
    ).rejects.toBeInstanceOf(SyncRecoveryRequiredError);
  });

  test.each(["inbox", "history"] as const)(
    "legacy empty %s bootstraps once and retries",
    async (kind) => {
      const root = mkdtempSync(join(tmpdir(), "awiki-sync-command-"));
      const store = new SecureStateStore(root);
      const keys = {
        "root-key": generateKeyPairSync("ed25519")
          .privateKey.export({ type: "pkcs8", format: "pem" })
          .toString(),
        "device-signing": generateKeyPairSync("ed25519")
          .privateKey.export({ type: "pkcs8", format: "pem" })
          .toString(),
        "device-agreement": generateKeyPairSync("x25519")
          .privateKey.export({ type: "pkcs8", format: "pem" })
          .toString(),
      };
      store.stageRegistration(identity.identity, keys, "twelve chars!!");
      store.finalizeRegistration(identity.identity, "token-1");
      const readMethod = kind === "inbox" ? "inbox.get" : "direct.get_history";
      const methods: string[] = [];
      const client = {
        async post(
          _url: string,
          init: { headers: Record<string, string>; body: string },
        ) {
          const request = JSON.parse(init.body) as {
            id: string;
            method: string;
          };
          methods.push(request.method);
          let result: Record<string, unknown>;
          if (request.method === "sync.bootstrap") {
            result = {
              mode: "tail_only",
              account_id: "account-1",
              device_id: identity.identity.deviceId,
              server_time: "2026-08-21T00:00:00Z",
              cursor: { stream_epoch: "1", scan_seq: "7" },
              read_state_baseline: [],
              group_state_baseline: [],
              warnings: [],
            };
          } else if (
            methods.filter((method) => method === readMethod).length === 1
          ) {
            result = { messages: [], has_more: false };
          } else {
            result = {
              messages: [
                {
                  id: "message-after-bootstrap",
                  sender_did: identity.identity.did,
                  receiver_did: identity.identity.did,
                  content: "visible",
                  content_type: "text/plain",
                  sent_at: "2026-08-21T00:00:01Z",
                },
              ],
              has_more: false,
            };
          }
          return {
            status: 200,
            ok: true,
            headers: {},
            async json() {
              return { jsonrpc: "2.0", id: request.id, result };
            },
            async bytes() {
              return new Uint8Array();
            },
          };
        },
      } as never;
      const service = new MessageService(client, "https://example.com");
      const page =
        kind === "inbox"
          ? await inboxWithSync(service, store, identity, 10, 0)
          : await historyWithSync(
              service,
              store,
              identity,
              identity.identity.did,
              10,
              0,
            );
      if (kind === "inbox") {
        await inboxWithSync(service, store, identity, 10, 0);
      } else {
        await historyWithSync(
          service,
          store,
          identity,
          identity.identity.did,
          10,
          0,
        );
      }
      expect(page[0].map((item) => item.messageId)).toEqual([
        "message-after-bootstrap",
      ]);
      expect(methods.slice(0, 3)).toEqual([
        readMethod,
        "sync.bootstrap",
        readMethod,
      ]);
      expect(methods.slice(3)).toEqual([readMethod]);
      expect(store.loadSync(identity.identity.did)?.bootstrap).not.toBeNull();
    },
  );

  test("legacy empty later page does not bootstrap", async () => {
    const root = mkdtempSync(join(tmpdir(), "awiki-sync-later-page-"));
    const store = new SecureStateStore(root);
    const keys = {
      "root-key": generateKeyPairSync("ed25519")
        .privateKey.export({ type: "pkcs8", format: "pem" })
        .toString(),
      "device-signing": generateKeyPairSync("ed25519")
        .privateKey.export({ type: "pkcs8", format: "pem" })
        .toString(),
      "device-agreement": generateKeyPairSync("x25519")
        .privateKey.export({ type: "pkcs8", format: "pem" })
        .toString(),
    };
    store.stageRegistration(identity.identity, keys, "twelve chars!!");
    store.finalizeRegistration(identity.identity, "token-1");
    const methods: string[] = [];
    const client = {
      async post(_url: string, init: { body: string }) {
        const request = JSON.parse(init.body) as { id: string; method: string };
        methods.push(request.method);
        return {
          status: 200,
          ok: true,
          headers: {},
          async json() {
            return {
              jsonrpc: "2.0",
              id: request.id,
              result: { messages: [], has_more: false },
            };
          },
          async bytes() {
            return new Uint8Array();
          },
        };
      },
    } as never;
    await inboxWithSync(
      new MessageService(client, "https://example.com"),
      store,
      identity,
      10,
      10,
    );
    expect(methods).toEqual(["inbox.get"]);
    expect(store.loadSync(identity.identity.did)).toBeNull();
  });
});
