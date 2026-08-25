import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import {
  InvalidInputError,
  JsonRpcFailure,
} from "../src/application/errors.js";
import {
  RegistrationWorkflow,
  registrationDomain,
} from "../src/application/registration.js";
import { initializeMessageSync } from "../src/commands/identity.js";
import {
  generateIdentity,
  generateOriginProof,
} from "../src/infrastructure/anp-sdk.js";
import { SecureStateStore } from "../src/infrastructure/state.js";
import { UserService } from "../src/infrastructure/user-service.js";
import { CLIENT_IDENTIFIER } from "../src/version.js";

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "awiki-reg-"));
}

function acceptedRegistrationService(registerDids: string[] = []) {
  return {
    baseUrl: "https://example.test",
    async validateHandle() {
      return { available: true };
    },
    async sendRegistrationOtp() {
      return true;
    },
    async register(document: Record<string, unknown>) {
      const did = String(document.id);
      registerDids.push(did);
      return { state: "registered", did, access_token: "token-1" };
    },
  };
}

describe("registration and session", () => {
  test("registration domain comes from the user service URL hostname", () => {
    expect(registrationDomain("https://awiki.info/")).toBe("awiki.info");
    expect(() => registrationDomain("not-a-url")).toThrow(InvalidInputError);
  });

  test("generated identity advertises the Message Service RPC endpoint", () => {
    const generated = generateIdentity(
      "example.test",
      "alice",
      "https://message.example.test/",
    );
    const services = generated.didDocument.service as Array<{
      serviceEndpoint: string;
    }>;
    expect(services[0]?.serviceEndpoint).toBe(
      "https://message.example.test/anp-im/rpc",
    );
  });

  test("registration publishes the identity and bootstraps sync", async () => {
    const root = tempDir();
    const store = new SecureStateStore(root);
    const clientInstanceIds: string[] = [];
    const userService = acceptedRegistrationService();
    const syncService = {
      async bootstrapSync(
        authenticated: { identity: { deviceId: string } },
        clientInstanceId: string,
      ) {
        clientInstanceIds.push(clientInstanceId);
        return {
          accountId: "account-1",
          deviceId: authenticated.identity.deviceId,
          serverTime: "2026-08-21T00:00:00Z",
          streamEpoch: "1",
          scanSeq: "0",
        };
      },
    };
    const workflow = new RegistrationWorkflow(
      userService as never,
      syncService as never,
      store,
      "https://example.test",
      generateIdentity,
    );
    const [handle, phone, domain] = await workflow.begin(
      "alice",
      "+15555550100",
    );
    const registered = await workflow.finish(
      handle,
      phone,
      domain,
      "123456",
      "twelve chars!!",
    );
    const installation = store.loadSync(registered.did);
    expect(store.loadPublic().did).toBe(registered.did);
    expect(installation?.bootstrap?.deviceId).toBe(registered.deviceId);
    expect(clientInstanceIds).toEqual([installation?.clientInstanceId]);
  });

  test("sync failure leaves registration recoverable by init-sync", async () => {
    const store = new SecureStateStore(tempDir());
    const registerDids: string[] = [];
    const workflow = new RegistrationWorkflow(
      acceptedRegistrationService(registerDids) as never,
      {
        async bootstrapSync() {
          expect(store.loadPublic().did).toBe(registerDids[0]);
          expect(store.loadSession().accessToken).toBe("token-1");
          throw new Error("sync timeout");
        },
      } as never,
      store,
      "https://example.test",
      generateIdentity,
    );

    await expect(
      workflow.finish(
        "alice",
        "+15555550100",
        "example.test",
        "123456",
        "twelve chars!!",
      ),
    ).rejects.toThrow(/registered locally.*run id init-sync/);

    const identity = store.loadPublic();
    expect(registerDids).toEqual([identity.did]);
    expect(store.loadSession().accessToken).toBe("token-1");
    expect(store.loadPendingIdentity()).toBeNull();
    const pendingSync = store.loadSync(identity.did);
    expect(pendingSync?.bootstrap).toBeNull();

    const recovered = await initializeMessageSync(store, {
      async bootstrapSync(_identity, clientInstanceId) {
        expect(clientInstanceId).toBe(pendingSync?.clientInstanceId);
        return {
          accountId: "account-1",
          deviceId: identity.deviceId,
          serverTime: "2026-08-25T00:00:00Z",
          streamEpoch: "1",
          scanSeq: "0",
        };
      },
    } as never);
    expect(store.loadSync(identity.did)?.bootstrap).toEqual(recovered);
  });

  test("OTP exemption requires all three conjuncts", async () => {
    const client = {
      async post() {
        throw new JsonRpcFailure(-32010, "unavailable", {
          feature: "contact_verification",
          reason: "email_or_phone_verification_is_not_part_of_open_server_mvp",
        });
      },
      async get() {
        throw new Error("unused");
      },
    };
    const service = new UserService(client, "https://awiki.info");
    expect(
      await service.sendRegistrationOtp("alice", "awiki.info", "+15555550100"),
    ).toBe(false);
    const strict = new UserService(
      {
        async post() {
          throw new JsonRpcFailure(-32010, "unavailable", {
            feature: "contact_verification",
          });
        },
        async get() {
          throw new Error("unused");
        },
      },
      "https://awiki.info",
    );
    await expect(
      strict.sendRegistrationOtp("alice", "awiki.info", "+15555550100"),
    ).rejects.toBeInstanceOf(JsonRpcFailure);
  });

  test("Open Server can defer handle availability to registration", async () => {
    const service = new UserService(
      {
        async post() {
          throw new JsonRpcFailure(-32601, "method_not_found");
        },
      } as never,
      "https://example.test",
    );
    await expect(
      service.validateHandle("alice", "example.test"),
    ).resolves.toEqual({ available: true, validation_deferred: true });
  });

  test("session refresh uses frozen client header and 401 does not delete session.json", async () => {
    const root = tempDir();
    const store = new SecureStateStore(root);
    const passphrase = "twelve chars!!";
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
    const identity = {
      did: "did:wba:example.com:user:alice:e1_alice",
      handle: "alice.example.com",
      verificationMethod: "did:wba:example.com:user:alice:e1_alice#key-1",
      deviceId: "dev-1",
      didDocument: {
        id: "did:wba:example.com:user:alice:e1_alice",
        verificationMethod: [
          {
            id: "did:wba:example.com:user:alice:e1_alice#key-1",
            type: "JsonWebKey2020",
            controller: "did:wba:example.com:user:alice:e1_alice",
          },
        ],
      },
    };
    store.stageRegistration(identity, keys, passphrase);
    store.finalizeRegistration(identity, "old-token");
    const seen: string[] = [];
    const client = {
      async post(_url: string, init: { headers: Record<string, string> }) {
        seen.push(init.headers["X-AWiki-Client-Version"] ?? "");
        return {
          status: 401,
          ok: false,
          async json() {
            return {
              jsonrpc: "2.0",
              id: JSON.parse(init.headers.unused ?? "null"),
              error: { code: 401, message: "unauthorized" },
            };
          },
        };
      },
      async get() {
        throw new Error("unused");
      },
    };
    const service = new UserService(client, "https://awiki.info");
    const signing = store.loadDeviceSigningKeyPem(passphrase);
    await expect(service.refreshSession(identity, signing)).rejects.toThrow();
    expect(
      JSON.parse(readFileSync(join(root, "session.json"), "utf8")),
    ).toEqual({ access_token: "old-token" });
    expect(seen[0] ?? CLIENT_IDENTIFIER).toBe(CLIENT_IDENTIFIER);
  });

  test("origin proof uses the public SDK helper", () => {
    const pem = generateKeyPairSync("ed25519")
      .privateKey.export({ type: "pkcs8", format: "pem" })
      .toString();
    const proof = generateOriginProof(
      "direct.send",
      {
        profile: "anp.direct.base.v1",
        sender_did: "did:wba:example.com:user:alice:e1_alice",
        target: { kind: "agent", did: "did:wba:example.com:user:bob:e1_bob" },
      },
      { text: "hello" },
      pem,
      "did:wba:example.com:user:alice:e1_alice#key-1",
      { created: 1712000000, nonce: "nonce-1" },
    );
    expect(proof.signatureInput).toContain("created=1712000000");
    expect(proof.signatureInput).toContain('nonce="nonce-1"');
  });

  test("registration and refresh accept a bearer token from the response header", async () => {
    const generated = generateIdentity(
      "example.test",
      "alice",
      "https://example.test",
    );
    const identity = {
      did: generated.did,
      handle: "alice.example.test",
      verificationMethod: generated.deviceSigningKeyId,
      deviceId: generated.deviceId,
      didDocument: generated.didDocument,
    };
    const client = {
      async post(_url: string, init: { body: string | Uint8Array }) {
        const body = JSON.parse(init.body.toString());
        return {
          status: 200,
          ok: true,
          headers: { authorization: "Bearer header-token" },
          async json() {
            return {
              jsonrpc: "2.0",
              id: body.id,
              result:
                body.method === "register"
                  ? { did: generated.did }
                  : { did: generated.did },
              error: null,
            };
          },
          async bytes() {
            return new Uint8Array();
          },
        };
      },
    };
    const service = new UserService(client as never, "https://example.test");

    await expect(
      service.register(
        generated.didDocument,
        "alice",
        "+15555550100",
        "123456",
      ),
    ).resolves.toMatchObject({ access_token: "header-token" });
    await expect(
      service.refreshSession(identity, generated.deviceSigningPrivateKeyPem),
    ).resolves.toBe("header-token");
  });

  test("ANP root key survives encrypted state roundtrip", () => {
    const generated = generateIdentity(
      "example.test",
      "alice",
      "https://example.test",
    );
    expect(generated.rootPrivateKeyPem).toContain("BEGIN PRIVATE KEY");
    const identity = {
      did: generated.did,
      handle: "alice.example.test",
      verificationMethod: generated.deviceSigningKeyId,
      deviceId: generated.deviceId,
      didDocument: generated.didDocument,
    };
    const store = new SecureStateStore(tempDir());
    const passphrase = "twelve chars!!";
    store.stageRegistration(
      identity,
      {
        "root-key": generated.rootPrivateKeyPem,
        "device-signing": generated.deviceSigningPrivateKeyPem,
        "device-agreement": generated.deviceAgreementPrivateKeyPem,
      },
      passphrase,
    );
    store.finalizeRegistration(identity, "token-1");

    expect(store.unlock(passphrase).rootPrivateKeyPem).toContain(
      "BEGIN PRIVATE KEY",
    );
  });

  test("pending registration state can be reopened", () => {
    const root = tempDir();
    const store = new SecureStateStore(root);
    const passphrase = "twelve chars!!";
    const generated = {
      did: "did:wba:example.com:user:alice:e1_alice",
      didDocument: { id: "did:wba:example.com:user:alice:e1_alice" },
      deviceId: "dev-1",
      rootKeyId: "root",
      deviceSigningKeyId: "sign",
      deviceAgreementKeyId: "e2ee",
      rootPrivateKeyPem: generateKeyPairSync("ed25519")
        .privateKey.export({ type: "pkcs8", format: "pem" })
        .toString(),
      deviceSigningPrivateKeyPem: generateKeyPairSync("ed25519")
        .privateKey.export({ type: "pkcs8", format: "pem" })
        .toString(),
      deviceAgreementPrivateKeyPem: generateKeyPairSync("x25519")
        .privateKey.export({ type: "pkcs8", format: "pem" })
        .toString(),
    };
    const identity = {
      did: generated.did,
      handle: "alice.example.com",
      verificationMethod: generated.deviceSigningKeyId,
      deviceId: generated.deviceId,
      didDocument: generated.didDocument,
    };
    store.stageRegistration(
      identity,
      {
        "root-key": generated.rootPrivateKeyPem,
        "device-signing": generated.deviceSigningPrivateKeyPem,
        "device-agreement": generated.deviceAgreementPrivateKeyPem,
      },
      passphrase,
    );
    expect(store.loadPendingIdentity()?.handle).toBe("alice.example.com");
    expect(store.unlockPendingKeys(passphrase)).toHaveLength(3);
  });
});
