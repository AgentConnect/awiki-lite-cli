import { generateKeyPairSync } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
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

  test("reuses the opaque sync installation id and persists bootstrap", () => {
    const root = tempDir();
    const store = new SecureStateStore(root);
    store.stageRegistration(sampleIdentity(), keyPems(), "twelve chars!!");
    store.finalizeRegistration(sampleIdentity(), "token-1");
    const first = store.initializeSync(sampleIdentity().did);
    const second = new SecureStateStore(root).initializeSync(
      sampleIdentity().did,
    );
    expect(second).toEqual(first);
    expect(first.clientInstanceId).toMatch(/^lite-installation-/);
    expect(first.clientInstanceId).not.toContain(sampleIdentity().did);
    const completed = store.completeSyncBootstrap(first, {
      accountId: "account-1",
      deviceId: sampleIdentity().deviceId,
      serverTime: "2026-08-21T00:00:00Z",
      streamEpoch: "1",
      scanSeq: "7",
    });
    expect(store.loadSync(sampleIdentity().did)).toEqual(completed);
    const raw = readFileSync(join(root, "sync-installation.json"), "utf8");
    expect(raw).not.toContain("token-1");
    expect(raw).not.toContain("recovery");
  });

  test("rejects a sync installation owned by another identity", () => {
    const store = new SecureStateStore(tempDir());
    store.initializeSync(sampleIdentity().did);
    expect(() =>
      store.loadSync("did:wba:example.com:user:other:e1_other"),
    ).toThrow(/another identity/);
  });

  test.runIf(process.platform === "win32")(
    "protects state with a non-inherited current-user and SYSTEM ACL",
    () => {
      const root = tempDir();
      const store = new SecureStateStore(root);
      store.stageRegistration(sampleIdentity(), keyPems(), "twelve chars!!");
      store.finalizeRegistration(sampleIdentity(), "token-1");
      store.initializeSync(sampleIdentity().did);
      const script = [
        "$acl = Get-Acl -LiteralPath $env:AWIKI_ACL_TEST_PATH",
        "$value = [pscustomobject]@{ protected = $acl.AreAccessRulesProtected; sddl = $acl.Sddl }",
        "$value | ConvertTo-Json -Compress",
      ].join("; ");
      for (const path of ["session.json", "sync-installation.json"]) {
        const result = spawnSync(
          "powershell.exe",
          ["-NoProfile", "-NonInteractive", "-Command", script],
          {
            encoding: "utf8",
            windowsHide: true,
            env: {
              ...process.env,
              AWIKI_ACL_TEST_PATH: join(root, path),
            },
          },
        );
        expect(result.status, result.stderr).toBe(0);
        const acl = JSON.parse(result.stdout) as {
          protected: boolean;
          sddl: string;
        };
        expect(acl.protected).toBe(true);
        expect(acl.sddl).toContain("D:P");
        expect(acl.sddl).toMatch(/;;;SY\)/);
      }
    },
  );
});
