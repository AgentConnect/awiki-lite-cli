import { buildResolutionUrl, validateHandle } from "@awiki/anp-typescript-sdk";

import { InvalidInputError } from "../application/errors.js";
import {
  validatePublicHostname,
  validateWbaDid,
} from "../domain/validation.js";
import { verifyResolvedDocument } from "./anp-sdk.js";
import { pinHttpsUrl, pinnedHeaders } from "./safe-network.js";
import type { HttpClient } from "./rpc.js";

export function normalizePeerReference(
  value: string,
  ownerHandle: string,
): { value: string; isDid: boolean } {
  let raw = value.trim();
  if (raw.startsWith("did:")) {
    return { value: validateWbaDid(raw, "peer"), isDid: true };
  }
  if (raw.startsWith("@")) {
    raw = raw.slice(1);
  }
  if (!raw.includes(".")) {
    const separator = ownerHandle.indexOf(".");
    if (separator < 0) {
      throw new InvalidInputError("local identity handle has no domain");
    }
    const domain = validatePublicHostname(
      ownerHandle.slice(separator + 1),
      "handle domain",
    );
    raw = `${raw}.${domain}`;
  }
  try {
    const [localPart, domain] = validateHandle(raw.toLowerCase());
    return { value: `${localPart}.${domain}`, isDid: false };
  } catch {
    throw new InvalidInputError(
      "peer must be a DID, full handle, or handle local-part",
    );
  }
}

export async function resolvePeerDid(
  client: HttpClient,
  value: string,
  ownerHandle: string,
): Promise<string> {
  const peer = normalizePeerReference(value, ownerHandle);
  if (peer.isDid) {
    return peer.value;
  }

  const [localPart, domain] = validateHandle(peer.value);
  const resolution = await getPublicJson(
    client,
    buildResolutionUrl(localPart, domain),
    "handle resolution URL",
  );
  if (resolution.handle !== peer.value || resolution.status !== "active") {
    throw new Error(
      "handle resolution returned an inactive or mismatched handle",
    );
  }
  if (typeof resolution.did !== "string") {
    throw new Error("handle resolution returned an invalid DID");
  }
  let did: string;
  try {
    did = validateWbaDid(resolution.did, "resolved peer DID");
  } catch {
    throw new Error("handle resolution returned an invalid DID");
  }
  if (did.split(":")[2] !== domain) {
    throw new Error("handle and DID domains do not match");
  }

  const segments = did
    .split(":")
    .slice(3)
    .map((segment) => encodeURIComponent(decodeURIComponent(segment)));
  const didUrl = segments.length
    ? `https://${domain}/${segments.join("/")}/did.json`
    : `https://${domain}/.well-known/did.json`;
  const document = await getPublicJson(client, didUrl, "peer DID URL");
  try {
    verifyResolvedDocument(did, document);
  } catch {
    throw new Error("resolved peer DID document failed verification");
  }
  return did;
}

async function getPublicJson(
  client: HttpClient,
  url: string,
  field: string,
): Promise<Record<string, unknown>> {
  const target = await pinHttpsUrl(url, { field });
  const response = await client.get(target.url, {
    headers: pinnedHeaders(target, { Accept: "application/json" }),
  });
  if (!response.ok) {
    throw new Error(`unable to read ${field}`);
  }
  let value: unknown;
  try {
    value = await response.json();
  } catch {
    throw new Error(`${field} returned invalid JSON`);
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${field} returned invalid JSON`);
  }
  return value as Record<string, unknown>;
}
