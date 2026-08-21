import password from "@inquirer/password";

import {
  InvalidInputError,
  JsonRpcFailure,
  SessionExpiredError,
  StateError,
} from "../application/errors.js";
import { requireReadableCaBundle, settingsFromEnv } from "../config.js";
import { createHttpClient } from "../infrastructure/rpc.js";
import { SecureStateStore } from "../infrastructure/state.js";

export async function promptPassphrase(
  message = "Local key passphrase",
  confirm = false,
): Promise<string> {
  if (!process.stdin.isTTY) {
    throw new InvalidInputError("a TTY is required to enter the passphrase");
  }
  const first = await password({ message, mask: "*" });
  if (confirm) {
    const second = await password({ message: "Confirm passphrase", mask: "*" });
    if (first !== second) {
      throw new InvalidInputError("passphrases do not match");
    }
  }
  return first;
}

export async function promptText(message: string): Promise<string> {
  const { createInterface } = await import("node:readline/promises");
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return await rl.question(`${message}: `);
  } finally {
    rl.close();
  }
}

export function requireInteger(
  value: number,
  field: string,
  minimum: number,
  maximum?: number,
): number {
  if (
    !Number.isInteger(value) ||
    value < minimum ||
    (maximum !== undefined && value > maximum)
  ) {
    const range =
      maximum === undefined
        ? `at least ${minimum}`
        : `between ${minimum} and ${maximum}`;
    throw new InvalidInputError(`${field} must be an integer ${range}`);
  }
  return value;
}

export function createRuntime(
  overrides: {
    stateDir?: string;
    messageServiceUrl?: string;
    env?: NodeJS.ProcessEnv;
  } = {},
) {
  const settings = settingsFromEnv(overrides.env);
  const stateDir = overrides.stateDir ?? settings.stateDir;
  const messageServiceUrl =
    overrides.messageServiceUrl ?? settings.messageServiceUrl;
  const store = new SecureStateStore(stateDir);
  const http = createHttpClient({
    caBundle: requireReadableCaBundle(settings.caBundle),
    timeoutMs: 20_000,
  });
  return {
    settings: { ...settings, stateDir, messageServiceUrl },
    store,
    http,
  };
}

export function mapError(
  error: unknown,
  kind:
    | "registration"
    | "session"
    | "messaging"
    | "group"
    | "attachment"
    | "listener",
): never {
  const argv0 = "awiki-lite-ts";
  if (error instanceof InvalidInputError) {
    console.error(`Invalid input: ${error.message}`);
    process.exit(2);
  }
  if (error instanceof JsonRpcFailure) {
    if (
      error.code === 401 ||
      error.code === 1401 ||
      error.message.toLowerCase().includes("unauthorized")
    ) {
      console.error(`Session expired; run \`${argv0} id refresh-token\`.`);
      process.exit(1);
    }
    const service =
      kind === "registration"
        ? "Registration service"
        : kind === "session"
          ? "Session refresh"
          : kind === "group"
            ? "Group service"
            : kind === "attachment"
              ? "Attachment service"
              : "Message service";
    console.error(
      `${service} rejected the request (JSON-RPC code ${error.code}).`,
    );
    process.exit(1);
  }
  if (error instanceof SessionExpiredError) {
    console.error(`Session expired; run \`${argv0} id refresh-token\`.`);
    process.exit(1);
  }
  const label =
    kind === "registration"
      ? "Registration failed"
      : kind === "session"
        ? "Session refresh failed"
        : kind === "group"
          ? "Group command failed"
          : kind === "attachment"
            ? "Attachment command failed"
            : kind === "listener"
              ? "Listener failed"
              : "Messaging failed";
  const message = error instanceof Error ? error.message : String(error);
  if (error instanceof StateError || error instanceof Error) {
    console.error(`${label}: ${message}`);
    process.exit(1);
  }
  console.error(`${label}: ${message}`);
  process.exit(1);
}

export function wrapMain(
  kind: Parameters<typeof mapError>[1],
  fn: () => Promise<void>,
): void {
  fn().catch((error) => mapError(error, kind));
}
