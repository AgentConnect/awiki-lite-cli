import { describe, expect, test } from "vitest";

import { validatePublicHostname } from "../src/domain/validation.js";

describe("public hostname validation", () => {
  test("accepts canonical ASCII DNS names", () => {
    expect(validatePublicHostname("example.com")).toBe("example.com");
    expect(validatePublicHostname("api-1.example.test")).toBe(
      "api-1.example.test",
    );
  });

  test.each([
    "exämple.com",
    "example.com\u0000",
    "127.0.0.1",
    "localhost",
    "EXAMPLE.COM",
  ])("rejects unsafe hostname %j", (hostname) => {
    expect(() => validatePublicHostname(hostname)).toThrow();
  });
});
