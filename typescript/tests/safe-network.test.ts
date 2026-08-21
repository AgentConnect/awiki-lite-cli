import { describe, expect, test } from "vitest";

import { pinHttpsUrl } from "../src/infrastructure/safe-network.js";

describe("safe network pinning", () => {
  test("returns the exact checked address and preserves TLS authority", async () => {
    const target = await pinHttpsUrl("https://objects.example:8443/file", {
      resolver: async () => [
        { address: "2606:4700:4700::1111", family: 6 },
        { address: "1.1.1.1", family: 4 },
      ],
    });

    expect(target).toMatchObject({
      url: "https://objects.example:8443/file",
      hostHeader: "objects.example:8443",
      serverHostname: "objects.example",
      address: "1.1.1.1",
      family: 4,
    });
  });

  test.each([
    "10.0.0.1",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.1.1",
    "192.0.2.1",
    "::1",
    "::ffff:127.0.0.1",
  ])("rejects non-global address %s", async (address) => {
    await expect(
      pinHttpsUrl("https://objects.example/file", {
        resolver: async () => [
          { address, family: address.includes(":") ? 6 : 4 },
        ],
      }),
    ).rejects.toThrow(/unsafe/);
  });

  test("allows an explicitly trusted private address but still pins it", async () => {
    const target = await pinHttpsUrl("https://objects.internal/file", {
      allowPrivateNetwork: true,
      resolver: async () => [{ address: "10.0.0.8", family: 4 }],
    });
    expect(target.address).toBe("10.0.0.8");
  });
});
