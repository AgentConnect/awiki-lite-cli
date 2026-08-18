import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { URL } from 'node:url';

import { validatePublicHostname } from '../domain/validation.js';

export interface PinnedHttpsTarget {
  readonly url: string;
  readonly hostHeader: string;
  readonly serverHostname: string;
}

export async function pinHttpsUrl(
  value: string,
  options: { allowPrivateNetwork?: boolean; field?: string } = {},
): Promise<PinnedHttpsTarget> {
  const field = options.field ?? 'URL';
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`unsafe ${field}`);
  }
  if (
    parsed.protocol !== 'https:' ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error(`unsafe ${field}`);
  }
  const hostname = parsed.hostname.toLowerCase().replace(/\.+$/, '');
  try {
    validatePublicHostname(hostname, field);
  } catch {
    throw new Error(`unsafe ${field}`);
  }
  if (!options.allowPrivateNetwork) {
    const addresses = await lookup(hostname, { all: true });
    if (addresses.some((row) => isPrivateAddress(row.address))) {
      throw new Error(`unsafe ${field}`);
    }
  }
  return { url: parsed.toString(), hostHeader: hostname, serverHostname: hostname };
}

export function pinnedHeaders(target: PinnedHttpsTarget, extra: Record<string, string> = {}): Record<string, string> {
  return { Host: target.hostHeader, ...extra };
}

function isPrivateAddress(address: string): boolean {
  if (isIP(address) === 4) {
    const [a, b] = address.split('.').map(Number);
    return a === 10 || a === 127 || (a === 172 && (b ?? 0) >= 16 && (b ?? 0) <= 31) || (a === 192 && b === 168);
  }
  return address === '::1' || address.startsWith('fe80:') || address.startsWith('fc') || address.startsWith('fd');
}
