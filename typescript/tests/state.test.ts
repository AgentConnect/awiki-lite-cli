import { generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { StateError } from "../src/application/errors.js";
import {
  SecureStateStore,
  validatePassphrase,
  validatePendingInput,
} from "../src/infrastructure/state.js";

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "awiki-lite-ts-"));
}

function sampleIdentity() {
  return {
    did: "did:wba:example.com:user:alice:e1_alice",
    handle: "alice.example.com",
    verificationMethod: "did:wba:example.com:user:alice:e1_alice#dev-sign",
    deviceId: "dev-alice",
    didDocument: { id: "did:wba:example.com:user:alice:e1_alice" },
  };
}

function keyPems() {
  const root = generateKeyPairSync("ed25519")
    .privateKey.export({ type: "pkcs8", format: "pem" })
    .toString();
  const sign = generateKeyPairSync("ed25519")
    .privateKey.export({ type: "pkcs8", format: "pem" })
    .toString();
  const agree = generateKeyPairSync("x25519")
    .privateKey.export({ type: "pkcs8", format: "pem" })
    .toString();
  return {
    "root-key": root,
    "device-signing": sign,
    "device-agreement": agree,
  };
}

describe("state store", () => {
  test("rejects short passphrases without writes", () => {
    const root = tempDir();
    const store = new SecureStateStore(root);
    expect(() => validatePassphrase("short")).toThrow(StateError);
    expect(() =>
      store.stageRegistration(sampleIdentity(), keyPems(), "short"),
    ).toThrow(/at least 12 characters/);
    expect(existsSync(join(root, "pending-registration.json"))).toBe(false);
  });

  test("pending values ban is key-name only", () => {
    expect(() =>
      validatePendingInput(
        "direct.send",
        "did:wba:example.com:user:bob",
        "a".repeat(64),
        {
          note: "contains token in the value",
        },
      ),
    ).not.toThrow();
    expect(() =>
      validatePendingInput(
        "direct.send",
        "did:wba:example.com:user:bob",
        "a".repeat(64),
        {
          proof_nonce: "ok",
        },
      ),
    ).toThrow(/unsafe/);
  });

  test("legacy pending-send maps recipient_did and content_sha256", () => {
    const root = tempDir();
    const store = new SecureStateStore(root);
    store.initialize();
    writeFileSync(
      join(root, "pending-send.json"),
      JSON.stringify({
        recipient_did: "did:wba:example.com:user:bob",
        content_sha256: "ab".repeat(32),
        operation_id: "op-1",
        message_id: "msg-1",
        created_at: "2026-01-01T00:00:00Z",
        proof_created: 1,
        proof_nonce: "n1",
      }),
      { mode: 0o600 },
    );
    chmodSync(join(root, "pending-send.json"), 0o600);
    const pending = store.prepareOperation(
      "direct.send",
      "did:wba:example.com:user:bob",
      "ab".repeat(32),
      {
        needsMessageId: true,
      },
    );
    expect(pending.kind).toBe("direct.send");
    expect(pending.targetDid).toBe("did:wba:example.com:user:bob");
  });

  test("unlocks a staged identity after Python-compatible encryption", () => {
    const root = tempDir();
    const store = new SecureStateStore(root);
    const passphrase = "twelve chars!!";
    store.stageRegistration(sampleIdentity(), keyPems(), passphrase);
    store.finalizeRegistration(sampleIdentity(), "token-1");
    const unlocked = store.unlock(passphrase);
    expect(unlocked.identity.did).toBe(sampleIdentity().did);
    expect(unlocked.session.accessToken).toBe("token-1");
    store.saveSession("token-2");
    expect(store.loadSession().accessToken).toBe("token-2");
  });
});
