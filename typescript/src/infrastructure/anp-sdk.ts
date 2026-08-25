import {
  createPrivateKey,
  generateKeyPairSync,
  randomBytes,
} from "node:crypto";
import { URL } from "node:url";

import {
  DidProfile,
  DeviceManifestEntry,
  PROFILE_CORE_BINDING_V1,
  PROFILE_DIRECT_BASE_V1,
  PROFILE_DIRECT_E2EE_V2,
  PROFILE_GROUP_BASE_V1,
  PROFILE_GROUP_E2EE_V2,
  PROFILE_IDENTITY_DISCOVERY_V1,
  buildVnextDidDocument,
  createDidDocument,
  createProof,
  extractPublicKey,
  findVerificationMethod,
  generateHttpSignatureHeaders,
  generateRfc9421OriginProof,
  validateDeviceManifest,
  validateDidBinding,
  verifyW3cProof,
} from "@awiki/anp-typescript-sdk";
import { validateWbaDid } from "../domain/validation.js";
import { pinHttpsUrl, pinnedHeaders } from "./safe-network.js";
import type { HttpClient } from "./rpc.js";

export const ATTACHMENT_PROFILE = "anp.attachment.v1";
export const CANONICAL_MANIFEST_PROFILES = [
  PROFILE_CORE_BINDING_V1,
  PROFILE_IDENTITY_DISCOVERY_V1,
  PROFILE_DIRECT_BASE_V1,
  PROFILE_DIRECT_E2EE_V2,
  PROFILE_GROUP_BASE_V1,
  PROFILE_GROUP_E2EE_V2,
] as const;

export interface GeneratedIdentity {
  readonly did: string;
  readonly didDocument: Record<string, unknown>;
  readonly deviceId: string;
  readonly rootKeyId: string;
  readonly deviceSigningKeyId: string;
  readonly deviceAgreementKeyId: string;
  readonly rootPrivateKeyPem: string;
  readonly deviceSigningPrivateKeyPem: string;
  readonly deviceAgreementPrivateKeyPem: string;
}

export function generateIdentity(
  hostname: string,
  handle: string,
  messageServiceUrl: string,
): GeneratedIdentity {
  const challenge = randomBytes(18).toString("base64url");
  const bundle = createDidDocument(hostname, {
    pathSegments: ["user", handle],
    services: [
      {
        id: "#message",
        type: "ANPMessageService",
        serviceEndpoint: `${messageServiceUrl.replace(/\/+$/, "")}/anp-im/rpc`,
        serviceDid: defaultServiceDid(messageServiceUrl),
        profiles: [
          PROFILE_CORE_BINDING_V1,
          PROFILE_DIRECT_BASE_V1,
          PROFILE_GROUP_BASE_V1,
          ATTACHMENT_PROFILE,
        ],
        securityProfiles: ["transport-protected"],
      },
    ],
    proofPurpose: "assertionMethod",
    domain: hostname,
    challenge,
    enableE2ee: false,
    didProfile: DidProfile.E1,
  });
  const baseDocument = bundle.didDocument as unknown as Record<string, unknown>;
  const did = String(baseDocument.id);
  const rootMethod = (
    baseDocument.verificationMethod as Array<Record<string, unknown>>
  )[0];
  if (!rootMethod) {
    throw new Error("DID document is missing a root verification method");
  }
  const rootKeyId = String(rootMethod.id);
  const anpRootPrivateKeyPem = bundle.keys["key-1"]?.privateKeyPem;
  if (!anpRootPrivateKeyPem) {
    throw new Error("DID document is missing a root private key");
  }
  const rootPrivateKeyPem = normalizeRootPrivateKey(anpRootPrivateKeyPem);
  const signing = generateKeyPairSync("ed25519");
  const agreement = generateKeyPairSync("x25519");
  const deviceId = `dev-${randomBytes(8).toString("hex")}`;
  const signingKeyId = `${did}#${deviceId}-sign`;
  const agreementKeyId = `${did}#${deviceId}-e2ee`;
  const signingPem = signing.privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  const agreementPem = agreement.privateKey
    .export({ type: "pkcs8", format: "pem" })
    .toString();
  const unsigned = buildVnextDidDocument(
    Object.fromEntries(
      Object.entries(baseDocument).filter(
        ([key]) =>
          ![
            "proof",
            "verificationMethod",
            "authentication",
            "assertionMethod",
          ].includes(key),
      ),
    ),
    rootKeyId,
    rootMethod,
    new DeviceManifestEntry(deviceId, signingKeyId, agreementKeyId, [
      ...CANONICAL_MANIFEST_PROFILES,
    ]),
    okpJwkMethod(
      signingKeyId,
      did,
      "Ed25519",
      signing.publicKey.export({ format: "jwk" }).x ?? "",
    ),
    okpJwkMethod(
      agreementKeyId,
      did,
      "X25519",
      agreement.publicKey.export({ format: "jwk" }).x ?? "",
    ),
  );
  const signed = createProof(unsigned, anpRootPrivateKeyPem, rootKeyId, {
    proofPurpose: "assertionMethod",
    proofType: "DataIntegrityProof",
    cryptosuite: "eddsa-jcs-2022",
    domain: hostname,
    challenge,
  });
  validateDeviceManifest(signed as Record<string, unknown>);
  return {
    did,
    didDocument: signed as Record<string, unknown>,
    deviceId,
    rootKeyId,
    deviceSigningKeyId: signingKeyId,
    deviceAgreementKeyId: agreementKeyId,
    rootPrivateKeyPem,
    deviceSigningPrivateKeyPem: signingPem,
    deviceAgreementPrivateKeyPem: agreementPem,
  };
}

export function generateOriginProof(
  method: string,
  meta: Record<string, unknown>,
  body: Record<string, unknown>,
  privateKeyPem: string,
  keyId: string,
  options: { created?: number; nonce?: string } = {},
): Record<string, string> {
  const proof = generateRfc9421OriginProof(
    method,
    meta,
    body,
    toAnpPrivateKey(privateKeyPem),
    keyId,
    {
      created: options.created ?? Math.floor(Date.now() / 1000),
      nonce: options.nonce ?? randomBytes(9).toString("base64url"),
    } satisfies { created: number; nonce: string },
  );
  return {
    contentDigest: proof.contentDigest,
    signatureInput: proof.signatureInput,
    signature: proof.signature,
  };
}

export function signHttpRequest(
  didDocument: Record<string, unknown>,
  url: string,
  method: string,
  privateKeyPem: string,
  headers: Record<string, string>,
  body: Uint8Array,
  keyId: string,
): Record<string, string> {
  return generateHttpSignatureHeaders(
    didDocument as never,
    url,
    method,
    toAnpPrivateKey(privateKeyPem),
    headers,
    body,
    { keyid: keyId },
  );
}

export function verifyResolvedDocument(
  senderDid: string,
  document: Record<string, unknown>,
): void {
  if (document.id !== senderDid) {
    throw new Error("DID document ID mismatch");
  }
  if (!validateDidBinding(document as never, true)) {
    throw new Error("DID document binding verification failed");
  }
  const proof = document.proof;
  if (typeof proof !== "object" || proof === null) {
    throw new Error("DID document proof is missing");
  }
  const methodId = (proof as Record<string, unknown>).verificationMethod;
  if (typeof methodId !== "string" || !methodId) {
    throw new Error("DID document proof method is missing");
  }
  const method = findVerificationMethod(document as never, methodId);
  try {
    if (!method || !verifyW3cProof(document, extractPublicKey(method))) {
      throw new Error("DID document proof verification failed");
    }
  } catch (error) {
    throw new Error("DID document proof verification failed", { cause: error });
  }
}

export function didDocumentUrl(did: string): string {
  const validated = validateWbaDid(did);
  const parts = validated.split(":");
  const domain = decodeURIComponent(parts[2] ?? "");
  const segments = parts
    .slice(3)
    .map((segment) => encodeURIComponent(decodeURIComponent(segment)));
  return segments.length
    ? `https://${domain}/${segments.join("/")}/did.json`
    : `https://${domain}/.well-known/did.json`;
}

export function selectAttachmentServiceDid(
  senderDid: string,
  document: Record<string, unknown>,
): string {
  if (document.id !== senderDid) {
    throw new Error("resolved attachment sender DID document does not match");
  }
  const services = document.service;
  if (!Array.isArray(services)) {
    throw new Error("attachment sender DID document has no compatible service");
  }
  const candidates: Array<[number, number, string]> = [];
  services.forEach((raw, index) => {
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
      return;
    }
    const item = raw as Record<string, unknown>;
    if (item.type !== "ANPMessageService") {
      return;
    }
    const profiles = item.profiles;
    const security = item.securityProfiles ?? item.security_profiles;
    const serviceDid = item.serviceDid;
    const endpoint = item.serviceEndpoint;
    if (
      !Array.isArray(profiles) ||
      !profiles.includes(ATTACHMENT_PROFILE) ||
      !Array.isArray(security) ||
      !security.includes("transport-protected") ||
      typeof serviceDid !== "string" ||
      serviceDid.split(":").length < 3 ||
      !serviceDid.startsWith("did:wba:") ||
      typeof endpoint !== "string" ||
      !safeHttpsEndpoint(endpoint)
    ) {
      return;
    }
    const priority = item.priority;
    const rank = typeof priority === "number" ? priority : 2 ** 31 - 1;
    candidates.push([rank, index, serviceDid]);
  });
  if (!candidates.length) {
    throw new Error("attachment sender DID document has no compatible service");
  }
  candidates.sort((left, right) =>
    left[0] === right[0] ? left[1] - right[1] : left[0] - right[0],
  );
  const selected = candidates[0];
  if (!selected) {
    throw new Error("attachment sender DID document has no compatible service");
  }
  return selected[2];
}

export async function resolveAttachmentServiceDid(
  senderDid: string,
  client: HttpClient,
  options: { allowPrivateNetwork?: boolean } = {},
): Promise<string> {
  validateWbaDid(senderDid, "attachment sender DID");
  try {
    const target = await pinHttpsUrl(didDocumentUrl(senderDid), {
      field: "attachment sender DID URL",
      allowPrivateNetwork: options.allowPrivateNetwork === true,
    });
    const response = await client.get(target.url, {
      headers: pinnedHeaders(target, { Accept: "application/json" }),
      pinnedAddress: target.address,
      pinnedFamily: target.family,
      serverHostname: target.serverHostname,
    });
    if (!response.ok) {
      throw new Error("unable to resolve the attachment sender DID document");
    }
    const document = await response.json();
    if (
      typeof document !== "object" ||
      document === null ||
      Array.isArray(document)
    ) {
      throw new Error("unable to resolve the attachment sender DID document");
    }
    const record = document as Record<string, unknown>;
    verifyResolvedDocument(senderDid, record);
    return selectAttachmentServiceDid(senderDid, record);
  } catch {
    throw new Error("unable to resolve the attachment sender DID document");
  }
}

function safeHttpsEndpoint(value: string): boolean {
  try {
    const parsed = new URL(value);
    return (
      parsed.protocol === "https:" &&
      Boolean(parsed.hostname) &&
      !parsed.username &&
      !parsed.password &&
      !parsed.search &&
      !parsed.hash
    );
  } catch {
    return false;
  }
}

export function defaultServiceDid(messageServiceUrl: string): string {
  const parsed = new URL(messageServiceUrl);
  if (
    parsed.protocol !== "https:" ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password
  ) {
    throw new Error("Message Service URL must be an authority-safe HTTPS URL");
  }
  return `did:wba:${parsed.hostname}`;
}

function toAnpPrivateKey(pem: string): {
  type: "ed25519" | "x25519" | "secp256k1" | "secp256r1";
  bytes: Uint8Array;
} {
  const key = createPrivateKey(pem);
  const jwk = key.export({ format: "jwk" });
  const d = jwk.d;
  if (!d) {
    throw new Error("private key is missing material");
  }
  const bytes = new Uint8Array(Buffer.from(d, "base64url"));
  if (jwk.crv === "Ed25519") {
    return { type: "ed25519", bytes };
  }
  if (jwk.crv === "X25519") {
    return { type: "x25519", bytes };
  }
  if (jwk.crv === "P-256") {
    return { type: "secp256r1", bytes };
  }
  return { type: "secp256k1", bytes };
}

function normalizeRootPrivateKey(pem: string): string {
  if (!pem.includes("BEGIN ANP ED25519 PRIVATE KEY")) {
    return pem;
  }
  const match =
    /^-----BEGIN ANP ED25519 PRIVATE KEY-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END ANP ED25519 PRIVATE KEY-----\r?\n?$/.exec(
      pem,
    );
  const encoded = match?.[1];
  if (!encoded) {
    throw new Error("DID document contains an invalid root private key");
  }
  const privateBytes = Buffer.from(encoded.replace(/\s/g, ""), "base64");
  if (privateBytes.length !== 32) {
    throw new Error("DID document contains an invalid root private key");
  }
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    privateBytes,
  ]);
  return createPrivateKey({
    key: pkcs8,
    format: "der",
    type: "pkcs8",
  })
    .export({ type: "pkcs8", format: "pem" })
    .toString();
}

function okpJwkMethod(
  id: string,
  did: string,
  curve: string,
  x: string,
): Record<string, unknown> {
  return {
    id,
    type: "JsonWebKey2020",
    controller: did,
    publicKeyJwk: { kty: "OKP", crv: curve, x },
  };
}

export function pemFromKeyMaterial(pem: string): string {
  createPrivateKey(pem);
  return pem;
}
