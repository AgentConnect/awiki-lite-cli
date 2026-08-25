import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { requireReadableCaBundle, settingsFromEnv } from "../src/config.js";

describe("runtime configuration", () => {
  test("parses the private-network switch explicitly", () => {
    expect(
      settingsFromEnv({ AWIKI_LITE_ALLOW_PRIVATE_NETWORK: "YES" })
        .allowPrivateNetwork,
    ).toBe(true);
    expect(
      settingsFromEnv({ AWIKI_LITE_ALLOW_PRIVATE_NETWORK: "0" })
        .allowPrivateNetwork,
    ).toBe(false);
  });

  test("requires the CA bundle to be a readable file", () => {
    const root = mkdtempSync(join(tmpdir(), "awiki-ca-"));
    const path = join(root, "ca.pem");
    writeFileSync(path, "fixture certificate");
    expect(requireReadableCaBundle(path)).toBe(path);
    expect(() => requireReadableCaBundle(join(root, "missing.pem"))).toThrow(
      /readable/,
    );
  });
});
