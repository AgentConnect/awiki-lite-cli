import { createHash } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";

import { describe, expect, test } from "vitest";

import {
  CHUNK_SIZE,
  prepareFile,
  AttachmentService,
} from "../src/infrastructure/attachment-service.js";
import type {
  HttpClient,
  HttpResponse,
  HttpStreamResponse,
} from "../src/infrastructure/rpc.js";

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "awiki-att-"));
}

function okJson(result: unknown, id: string): HttpResponse {
  return {
    status: 200,
    ok: true,
    headers: {},
    async json() {
      return { jsonrpc: "2.0", id, result };
    },
    async bytes() {
      return new Uint8Array();
    },
  };
}

describe("streaming attachments", () => {
  test("upload PUTs a 64KiB Readable and never concatenates the file", async () => {
    const dir = tempDir();
    const path = join(dir, "blob.bin");
    const payload = Buffer.alloc(CHUNK_SIZE + 20, 7);
    writeFileSync(path, payload);
    const prepared = prepareFile(path, 10 * 1024 * 1024);
    const seen: {
      url?: string;
      readable?: boolean;
      sizes: number[];
      concat: boolean;
    } = {
      sizes: [],
      concat: false,
    };
    const client: HttpClient = {
      async post() {
        throw new Error("upload must not POST the object body");
      },
      async put(url, init) {
        seen.url = url;
        seen.readable = init.body instanceof Readable;
        seen.concat =
          Buffer.isBuffer(init.body) || init.body instanceof Uint8Array;
        for await (const piece of init.body as AsyncIterable<
          Buffer | Uint8Array | string
        >) {
          seen.sizes.push(Buffer.byteLength(piece));
        }
        return {
          status: 200,
          ok: true,
          headers: {},
          async json() {
            return {};
          },
          async bytes() {
            return new Uint8Array();
          },
        };
      },
      async get() {
        throw new Error("unused get");
      },
      async getStream() {
        throw new Error("unused getStream");
      },
    };
    const service = new AttachmentService(client, "https://example.com");
    try {
      await service.upload(
        {
          attachmentId: "att-1",
          slotId: "slot-1",
          uploadUri: "https://example.com/upload",
          uploadHeaders: { "x-anp-upload-token": "tok" },
          objectUri: "https://example.com/objects/blob",
          commitToken: "commit",
        },
        prepared,
      );
    } finally {
      prepared.close();
    }
    expect(seen.url).toBe("https://example.com/upload");
    expect(seen.readable).toBe(true);
    expect(seen.concat).toBe(false);
    expect(seen.sizes[0]).toBe(CHUNK_SIZE);
    expect(seen.sizes[1]).toBe(20);
    expect(seen.sizes.reduce((sum, size) => sum + size, 0)).toBe(
      payload.length,
    );
  });

  test("download streams GET bytes, verifies sha256, and refuses overwrite", async () => {
    const dir = tempDir();
    const payload = Buffer.alloc(CHUNK_SIZE + 33, 9);
    const digest = createHash("sha256").update(payload).digest("base64url");
    const destination = join(dir, "notes.bin");
    const client: HttpClient = {
      async post() {
        throw new Error("download must not POST");
      },
      async put() {
        throw new Error("unused put");
      },
      async get() {
        throw new Error("download must not use JSON get");
      },
      async getStream(url): Promise<HttpStreamResponse> {
        expect(url).toBe("https://example.com/objects/blob");
        return {
          status: 200,
          ok: true,
          headers: { "content-length": String(payload.length) },
          async *chunks() {
            yield payload.subarray(0, CHUNK_SIZE);
            yield payload.subarray(CHUNK_SIZE);
          },
        };
      },
    };
    const service = new AttachmentService(client, "https://example.com");
    const attachment = {
      attachmentId: "att-1",
      objectUri: "https://example.com/objects/blob",
      filename: "notes.bin",
      mimeType: "application/octet-stream",
      size: payload.length,
      sha256B64u: digest,
    };
    const written = await service.download(
      { value: "ticket" },
      attachment,
      destination,
    );
    expect(written).toBe(destination);
    expect(readFileSync(destination).equals(payload)).toBe(true);
    await expect(
      service.download({ value: "ticket" }, attachment, destination),
    ).rejects.toThrow(/already exists/);
    expect(existsSync(destination)).toBe(true);
  });

  test("failed download removes its partial file", async () => {
    const dir = tempDir();
    const payload = Buffer.from("wrong payload");
    const client: HttpClient = {
      async post() {
        throw new Error("unused");
      },
      async put() {
        throw new Error("unused");
      },
      async get() {
        throw new Error("unused");
      },
      async getStream() {
        return {
          status: 200,
          ok: true,
          headers: {},
          async *chunks() {
            yield payload;
          },
        };
      },
    };
    const service = new AttachmentService(client, "https://example.com");
    await expect(
      service.download(
        { value: "ticket" },
        {
          attachmentId: "att-1",
          objectUri: "https://example.com/objects/blob",
          filename: "notes.bin",
          mimeType: "application/octet-stream",
          size: payload.length,
          sha256B64u: "A".repeat(43),
        },
        join(dir, "notes.bin"),
      ),
    ).rejects.toThrow(/integrity/);
    expect(readdirSync(dir).filter((name) => name.endsWith(".part"))).toEqual(
      [],
    );
  });

  test("create_slot uses the frozen RPC name", async () => {
    const methods: string[] = [];
    const client: HttpClient = {
      async post(_url, init) {
        const body = JSON.parse(String(init.body)) as {
          method: string;
          id: string;
        };
        methods.push(body.method);
        return okJson(
          {
            slot_id: "slot-1",
            upload_uri: "https://example.com/upload",
            upload_headers: { "x-anp-upload-token": "tok" },
            object_uri: "https://example.com/objects/blob",
            commit_token: "commit",
          },
          body.id,
        );
      },
      async put() {
        throw new Error("unused");
      },
      async get() {
        throw new Error("unused");
      },
      async getStream() {
        throw new Error("unused");
      },
    };
    const dir = tempDir();
    const path = join(dir, "a.txt");
    writeFileSync(path, "hello");
    const prepared = prepareFile(path, 1024);
    const service = new AttachmentService(client, "https://example.com");
    try {
      const slot = await service.createSlot(
        {
          identity: {
            did: "did:wba:example.com:user:alice:e1_alice",
            handle: "alice.example.com",
            verificationMethod: "did:wba:example.com:user:alice:e1_alice#key-1",
            deviceId: "dev-1",
            didDocument: {},
          },
          session: { accessToken: "tok" },
          rootPrivateKeyPem: "x",
          deviceSigningPrivateKeyPem: "x",
          deviceAgreementPrivateKeyPem: "x",
        },
        "did:wba:example.com:service:attachment:e1_svc",
        "att-1",
        prepared,
        "agent",
        "did:wba:example.com:user:bob:e1_bob",
        "op-create",
        "2026-01-01T00:00:00Z",
      );
      expect(slot.uploadUri).toBe("https://example.com/upload");
    } finally {
      prepared.close();
    }
    expect(methods).toEqual(["attachment.create_slot"]);
  });
});
