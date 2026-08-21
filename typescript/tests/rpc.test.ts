import { describe, expect, test } from "vitest";

import { ProtocolResponseError } from "../src/application/errors.js";
import {
  decodeJsonRpcResponse,
  fixedAddressLookup,
} from "../src/infrastructure/rpc.js";

function response(payload: unknown) {
  return {
    status: 200,
    ok: true,
    headers: {},
    async json() {
      return payload;
    },
    async bytes() {
      return new Uint8Array();
    },
  };
}

describe("JSON-RPC response decoding", () => {
  test("fixed DNS lookup supports single-address and all-address callers", async () => {
    const lookup = fixedAddressLookup("203.0.113.10", 4);
    const single = await new Promise<unknown>((resolve, reject) => {
      lookup("ignored.example", {}, (error, address, family) => {
        if (error) reject(error);
        else resolve({ address, family });
      });
    });
    const all = await new Promise<unknown>((resolve, reject) => {
      lookup("ignored.example", { all: true }, (error, addresses) => {
        if (error) reject(error);
        else resolve(addresses);
      });
    });

    expect(single).toEqual({ address: "203.0.113.10", family: 4 });
    expect(all).toEqual([{ address: "203.0.113.10", family: 4 }]);
  });

  test("accepts a result accompanied by error null", async () => {
    await expect(
      decodeJsonRpcResponse(
        response({
          jsonrpc: "2.0",
          id: "request-1",
          result: { ok: true },
          error: null,
        }),
        "request-1",
      ),
    ).resolves.toEqual({ ok: true });
  });

  test("still rejects non-null result and error together", async () => {
    await expect(
      decodeJsonRpcResponse(
        response({
          jsonrpc: "2.0",
          id: "request-1",
          result: { ok: true },
          error: { code: 1, message: "ambiguous" },
        }),
        "request-1",
      ),
    ).rejects.toBeInstanceOf(ProtocolResponseError);
  });
});
