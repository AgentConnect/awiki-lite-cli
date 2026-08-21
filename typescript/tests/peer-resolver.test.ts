import { describe, expect, test, vi } from "vitest";

vi.mock("../src/infrastructure/safe-network.js", () => ({
  async pinHttpsUrl(value: string) {
    const hostname = new URL(value).hostname;
    return { url: value, hostHeader: hostname, serverHostname: hostname };
  },
  pinnedHeaders(target: { hostHeader: string }, extra: Record<string, string>) {
    return { Host: target.hostHeader, ...extra };
  },
}));

import { generateIdentity } from "../src/infrastructure/anp-sdk.js";
import {
  normalizePeerReference,
  resolvePeerDid,
} from "../src/infrastructure/peer-resolver.js";
import type { HttpClient, HttpResponse } from "../src/infrastructure/rpc.js";

function response(value: unknown): HttpResponse {
  return {
    status: 200,
    ok: true,
    headers: {},
    async json() {
      return value;
    },
    async bytes() {
      return new Uint8Array();
    },
  };
}

describe("peer handle resolution", () => {
  test("accepts bare, full, at-prefixed, and DID references", () => {
    const did = "did:wba:awiki.test:user:bob:e1_fixture";
    expect(normalizePeerReference("bob", "alice.awiki.test")).toEqual({
      value: "bob.awiki.test",
      isDid: false,
    });
    expect(normalizePeerReference("@bob", "alice.awiki.test")).toEqual({
      value: "bob.awiki.test",
      isDid: false,
    });
    expect(
      normalizePeerReference("bob.awiki.test", "alice.awiki.test"),
    ).toEqual({ value: "bob.awiki.test", isDid: false });
    expect(normalizePeerReference(did, "alice.awiki.test")).toEqual({
      value: did,
      isDid: true,
    });
  });

  test("does not use the network for an exact DID", async () => {
    const did = "did:wba:awiki.test:user:bob:e1_fixture";
    const client: HttpClient = {
      async get() {
        throw new Error("exact DID must not trigger a network request");
      },
      async post() {
        throw new Error("unused post");
      },
      async put() {
        throw new Error("unused put");
      },
      async getStream() {
        throw new Error("unused getStream");
      },
    };

    await expect(resolvePeerDid(client, did, "alice.awiki.test")).resolves.toBe(
      did,
    );
  });

  test("verifies the handle result and signed DID document", async () => {
    const generated = generateIdentity(
      "awiki.test",
      "bob",
      "https://awiki.test",
    );
    const paths: string[] = [];
    const client: HttpClient = {
      async get(url, init) {
        const parsed = new URL(url);
        paths.push(parsed.pathname);
        expect(init.headers.Host).toBe("awiki.test");
        return response(
          parsed.pathname === "/.well-known/handle/bob"
            ? {
                handle: "bob.awiki.test",
                did: generated.did,
                status: "active",
                binding_generation: "1",
              }
            : generated.didDocument,
        );
      },
      async post() {
        throw new Error("unused post");
      },
      async put() {
        throw new Error("unused put");
      },
      async getStream() {
        throw new Error("unused getStream");
      },
    };

    await expect(
      resolvePeerDid(client, "bob", "alice.awiki.test"),
    ).resolves.toBe(generated.did);
    expect(paths).toEqual([
      "/.well-known/handle/bob",
      `/user/bob/${generated.did.split(":").at(-1)}/did.json`,
    ]);
  });

  test("rejects a mismatched handle document", async () => {
    const client: HttpClient = {
      async get() {
        return response({
          handle: "mallory.awiki.test",
          did: "did:wba:awiki.test:user:bob:e1_fixture",
          status: "active",
        });
      },
      async post() {
        throw new Error("unused post");
      },
      async put() {
        throw new Error("unused put");
      },
      async getStream() {
        throw new Error("unused getStream");
      },
    };

    await expect(
      resolvePeerDid(client, "bob", "alice.awiki.test"),
    ).rejects.toThrow(/mismatched/);
  });

  test("rejects an inactive handle", async () => {
    const client: HttpClient = {
      async get() {
        return response({
          handle: "bob.awiki.test",
          did: "did:wba:awiki.test:user:bob:e1_fixture",
          status: "inactive",
        });
      },
      async post() {
        throw new Error("unused post");
      },
      async put() {
        throw new Error("unused put");
      },
      async getStream() {
        throw new Error("unused getStream");
      },
    };

    await expect(
      resolvePeerDid(client, "bob", "alice.awiki.test"),
    ).rejects.toThrow(/inactive/);
  });

  test("rejects a DID document with a failed signature", async () => {
    const generated = generateIdentity(
      "awiki.test",
      "bob",
      "https://awiki.test",
    );
    const tampered = structuredClone(generated.didDocument);
    const services = tampered.service as Array<Record<string, unknown>>;
    services[0]!.serviceEndpoint = "https://attacker.example/im/rpc";
    const client: HttpClient = {
      async get(url) {
        return response(
          new URL(url).pathname === "/.well-known/handle/bob"
            ? {
                handle: "bob.awiki.test",
                did: generated.did,
                status: "active",
              }
            : tampered,
        );
      },
      async post() {
        throw new Error("unused post");
      },
      async put() {
        throw new Error("unused put");
      },
      async getStream() {
        throw new Error("unused getStream");
      },
    };

    await expect(
      resolvePeerDid(client, "bob", "alice.awiki.test"),
    ).rejects.toThrow(/failed verification/);
  });

  test("rejects a missing handle document", async () => {
    const client: HttpClient = {
      async get() {
        return { ...response({}), status: 404, ok: false };
      },
      async post() {
        throw new Error("unused post");
      },
      async put() {
        throw new Error("unused put");
      },
      async getStream() {
        throw new Error("unused getStream");
      },
    };

    await expect(
      resolvePeerDid(client, "bob", "alice.awiki.test"),
    ).rejects.toThrow(/unable to read handle resolution URL/);
  });
});
