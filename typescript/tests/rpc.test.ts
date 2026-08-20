import { describe, expect, test } from "vitest";

import { ProtocolResponseError } from "../src/application/errors.js";
import { decodeJsonRpcResponse } from "../src/infrastructure/rpc.js";

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
