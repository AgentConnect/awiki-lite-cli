import { statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { InvalidInputError } from "./application/errors.js";

export const DEFAULT_SERVICE_URL = "https://awiki.ai";
/** Kept separate because each Lite implementation owns one local identity state. */
export const DEFAULT_STATE_APPNAME = "awiki-lite-cli-ts";

export interface Settings {
  readonly userServiceUrl: string;
  readonly messageServiceUrl: string;
  readonly stateDir: string;
  readonly caBundle: string | null;
  readonly allowPrivateNetwork: boolean;
}

export function resolveStateDir(
  appname = DEFAULT_STATE_APPNAME,
  env: NodeJS.ProcessEnv = process.env,
): string {
  const override = env.AWIKI_LITE_STATE_DIR;
  if (override) {
    return override.replace(/^~(?=\/|$)/, homedir());
  }
  return defaultStateDir(appname);
}

export function defaultStateDir(appname: string): string {
  if (process.platform === "darwin") {
    return join(homedir(), "Library", "Application Support", appname);
  }
  if (process.platform === "win32") {
    const local =
      process.env.LOCALAPPDATA ?? join(homedir(), "AppData", "Local");
    return join(local, "AgentConnect", appname);
  }
  const xdg = process.env.XDG_STATE_HOME;
  return join(
    xdg && xdg.length > 0 ? xdg : join(homedir(), ".local", "state"),
    appname,
  );
}

export function settingsFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): Settings {
  const ca = optionalPath(env.AWIKI_LITE_CA_BUNDLE);
  return {
    userServiceUrl: (env.AWIKI_USER_SERVICE_URL ?? DEFAULT_SERVICE_URL).replace(
      /\/+$/,
      "",
    ),
    messageServiceUrl: (
      env.AWIKI_MESSAGE_SERVICE_URL ?? DEFAULT_SERVICE_URL
    ).replace(/\/+$/, ""),
    stateDir: resolveStateDir(DEFAULT_STATE_APPNAME, env),
    caBundle: ca,
    allowPrivateNetwork: ["1", "true", "yes"].includes(
      (env.AWIKI_LITE_ALLOW_PRIVATE_NETWORK ?? "").toLowerCase(),
    ),
  };
}

function optionalPath(value: string | undefined): string | null {
  if (!value || !value.trim()) {
    return null;
  }
  const path = value.replace(/^~(?=\/|$)/, homedir());
  return path;
}

export function requireReadableCaBundle(path: string | null): string | null {
  if (path === null) {
    return null;
  }
  try {
    if (!statSync(path).isFile()) {
      throw new InvalidInputError(
        "AWIKI_LITE_CA_BUNDLE must name a readable CA bundle file",
      );
    }
  } catch (error) {
    if (error instanceof InvalidInputError) {
      throw error;
    }
    throw new InvalidInputError(
      "AWIKI_LITE_CA_BUNDLE must name a readable CA bundle file",
    );
  }
  return path;
}
