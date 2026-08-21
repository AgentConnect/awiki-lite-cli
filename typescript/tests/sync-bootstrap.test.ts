import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { SyncRecoveryRequiredError } from "../src/application/errors.js";
import { initializeMessageSync } from "../src/commands/identity.js";
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

  test("explicit initialization reuses one installation and bootstraps once", async () => {
    const store = new SecureStateStore(
      mkdtempSync(join(tmpdir(), "awiki-explicit-sync-")),
    );
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
    const clientIds: string[] = [];
    const service = {
      async bootstrapSync(
        authenticated: { identity: { deviceId: string } },
        clientInstanceId: string,
      ) {
        clientIds.push(clientInstanceId);
        return {
          accountId: "account-1",
          deviceId: authenticated.identity.deviceId,
          serverTime: "2026-08-21T00:00:00Z",
          streamEpoch: "1",
          scanSeq: "7",
        };
      },
    };

    const first = await initializeMessageSync(store, service as never);
    const second = await initializeMessageSync(store, service as never);

    expect(second).toEqual(first);
    expect(clientIds).toHaveLength(1);
    expect(store.loadSync(identity.identity.did)?.bootstrap).toEqual(first);
  });
});
