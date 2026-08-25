import { lookup } from "node:dns/promises";
import { URL } from "node:url";

import ipaddr from "ipaddr.js";

import { validatePublicHostname } from "../domain/validation.js";

export interface PinnedHttpsTarget {
  readonly url: string;
  readonly hostHeader: string;
  readonly serverHostname: string;
  readonly address: string;
  readonly family: 4 | 6;
}

export type AddressResolver = (
  hostname: string,
) => Promise<Array<{ address: string; family: number }>>;

export async function pinHttpsUrl(
  value: string,
  options: {
    allowPrivateNetwork?: boolean;
    field?: string;
    resolver?: AddressResolver;
  } = {},
): Promise<PinnedHttpsTarget> {
  const field = options.field ?? "URL";
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`unsafe ${field}`);
  }
  if (
    parsed.protocol !== "https:" ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error(`unsafe ${field}`);
  }
  const hostname = parsed.hostname.toLowerCase().replace(/\.+$/, "");
  try {
    validatePublicHostname(hostname, field);
  } catch {
    throw new Error(`unsafe ${field}`);
  }
  let addresses: Array<{ address: string; family: number }>;
  try {
    addresses = await (
      options.resolver ?? ((name) => lookup(name, { all: true }))
    )(hostname);
  } catch {
    throw new Error(`unable to resolve ${field}`);
  }
  if (!addresses.length) {
    throw new Error(`unable to resolve ${field}`);
  }
  if (!options.allowPrivateNetwork) {
    if (addresses.some((row) => !isGlobalAddress(row.address))) {
      throw new Error(`unsafe ${field}`);
    }
  }
  const selected = [...addresses].sort((left, right) =>
    left.family === right.family
      ? left.address.localeCompare(right.address)
      : left.family - right.family,
  )[0];
  if (!selected || (selected.family !== 4 && selected.family !== 6)) {
    throw new Error(`unsafe ${field}`);
  }
  const hostHeader = parsed.port ? `${hostname}:${parsed.port}` : hostname;
  return {
    url: parsed.toString(),
    hostHeader,
    serverHostname: hostname,
    address: selected.address,
    family: selected.family,
  };
}

export function pinnedHeaders(
  target: PinnedHttpsTarget,
  extra: Record<string, string> = {},
): Record<string, string> {
  return { Host: target.hostHeader, ...extra };
}

function isGlobalAddress(address: string): boolean {
  try {
    return ipaddr.process(address).range() === "unicast";
  } catch {
    return false;
  }
}
