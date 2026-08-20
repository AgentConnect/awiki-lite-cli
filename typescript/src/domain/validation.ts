const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const PATH_SEGMENT = /^[A-Za-z0-9._~-]+$/;
const PERCENT_ESCAPE = /%(?:[0-9A-Fa-f]{2})/g;

export function validateWbaDid(value: string, field = "DID"): string {
  if (
    typeof value !== "string" ||
    value !== value.trim() ||
    !value.startsWith("did:wba:")
  ) {
    throw new Error(`${field} must be an exact did:wba identifier`);
  }
  const parts = value.split(":");
  if (parts.length < 3) {
    throw new Error(`${field} must be an exact did:wba identifier`);
  }
  const encodedHost = parts[2] ?? "";
  validatePercentEncoding(encodedHost, field);
  const hostname = decodeURIComponent(encodedHost)
    .toLowerCase()
    .replace(/\.+$/, "");
  validatePublicHostname(hostname, field);
  if (encodedHost.toLowerCase().replace(/\.+$/, "") !== hostname) {
    throw new Error(`${field} hostname must use canonical lowercase ASCII`);
  }
  for (const encodedSegment of parts.slice(3)) {
    validatePercentEncoding(encodedSegment, field);
    const segment = decodeURIComponent(encodedSegment);
    if (
      !segment ||
      segment === "." ||
      segment === ".." ||
      !PATH_SEGMENT.test(segment) ||
      [...segment].some((character) => {
        const code = character.charCodeAt(0);
        return code < 0x20 || code === 0x7f;
      })
    ) {
      throw new Error(`${field} contains an invalid path segment`);
    }
  }
  return value;
}

export function validatePublicHostname(
  hostname: string,
  field = "hostname",
): string {
  if (
    !hostname ||
    hostname.length > 253 ||
    [...hostname].some((character) => character.charCodeAt(0) > 0x7f) ||
    hostname !== hostname.toLowerCase() ||
    hostname === "localhost" ||
    hostname.endsWith(".localhost")
  ) {
    throw new Error(`${field} is not a safe public hostname`);
  }
  if (/^[0-9.]+$/.test(hostname) || hostname.startsWith("0x")) {
    if (isIpAddress(hostname)) {
      throw new Error(`${field} is not a public IP address`);
    }
    throw new Error(`${field} uses an ambiguous numeric address`);
  }
  if (isIpAddress(hostname)) {
    throw new Error(`${field} is not a public IP address`);
  }
  const labels = hostname.split(".");
  if (labels.some((label) => !DOMAIN_LABEL.test(label))) {
    throw new Error(`${field} is not a valid DNS hostname`);
  }
  return hostname;
}

function validatePercentEncoding(value: string, field: string): void {
  const remainder = value.replace(PERCENT_ESCAPE, "");
  if (remainder.includes("%")) {
    throw new Error(`${field} contains invalid percent encoding`);
  }
}

function isIpAddress(value: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(value) || value.includes(":");
}
