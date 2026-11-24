import { getTypesForEIP712Domain, hashDomain } from "viem";

// Hardening: registry record signing. A signed location-registry record (v1 or v2) is signed as its canonical JSON,
// text or the 0x hex of its UTF-8 bytes. Such a payload is signed only for the TinyCloud One, Home, Secrets and Share production
// origins below; every other origin, and an unattributed request, is refused before an approval is offered.

/** Origins that may ask for a registry record signature, compared as exact strings. */
export const REGISTRY_RECORD_SIGN_ORIGINS: readonly string[] = [
  "https://home.tinycloud.xyz",
  "https://secrets.tinycloud.xyz",
  "https://share.tinycloud.xyz",
  "https://tinycloud.one",
];

/** Words for the refusal, in one place: the popup page, the embed page and the API error. */
export const REGISTRY_RECORD_SIGN_REFUSED = {
  code: "registry_record_sign_refused",
  title: "This app's request can't be signed",
  popupBody:
    "It would set which TinyCloud node holds your data. Only TinyCloud's own apps can ask for that, so this app can't. Nothing was signed. You can close this window.",
  embedBody:
    "It would set which TinyCloud node holds your data. Only TinyCloud's own apps can ask for that, so this app can't. Nothing was signed. You can go back to the app.",
  popupButton: "Close",
  embedButton: "Back to the app",
  apiMessage:
    "Only TinyCloud's own apps can request a signature that sets the account's node location through OpenKey. Nothing was signed.",
} as const;

const V1_FIELDS = ["version", "subject", "multiaddrs", "updated_at", "sequence"] as const;
const V2_FIELDS = ["version", "subject", "nodes", "spaces", "encryptionNode", "updated_at", "sequence"] as const;

/** Even-length `0x` hex, either case of the digits. */
const HEX_MESSAGE = /^0[xX](?:[0-9a-fA-F]{2})*$/;

function hexToUtf8(message: string): string | null {
  if (!HEX_MESSAGE.test(message)) return null;
  const digits = message.slice(2);
  const bytes = new Uint8Array(digits.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(digits.slice(i * 2, i * 2 + 2), 16);
  return new TextDecoder("utf-8").decode(bytes);
}

function isRecordObject(text: string): boolean {
  if (!text.trimStart().startsWith("{")) return false;
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return false;
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const fields = record.version === 1 ? V1_FIELDS : record.version === 2 ? V2_FIELDS : null;
  return fields !== null && fields.every((field) => Object.hasOwn(record, field));
}

/**
 * Is this message a v1 or v2 registry record payload: its text, or the 0x hex of its UTF-8 bytes, parses to an object
 * with the record's version and its full field set? Key order, whitespace and extra fields (such as `signature`) do
 * not matter. Other JSON and other text are not.
 */
export function isRegistryRecordPayload(message: string): boolean {
  if (isRecordObject(message)) return true;
  const decoded = hexToUtf8(message);
  return decoded !== null && isRecordObject(decoded);
}

/** May this origin ask for a registry record signature? Exact match only. */
export function registryRecordSignOriginAllowed(requestOrigin: unknown): boolean {
  return typeof requestOrigin === "string" && REGISTRY_RECORD_SIGN_ORIGINS.includes(requestOrigin);
}

/** The refusal for this message and requesting origin, or null when it may go on to the other checks. */
export function registryRecordSignRefusal(
  message: string,
  requestOrigin: unknown,
): { reason: "registry_record"; message: string } | null {
  if (registryRecordSignOriginAllowed(requestOrigin) || !isRegistryRecordPayload(message)) return null;
  return { reason: "registry_record", message: REGISTRY_RECORD_SIGN_REFUSED.apiMessage };
}

/** The EIP-712 domain name of the registry contract, and its struct, compared without case or surrounding spaces. */
const REGISTRY_TYPED_DOMAIN_NAME = "tinycloudregistry";
const REGISTRY_TYPED_PRIMARY_TYPE = "setnode";

const folded = (value: unknown): string | null => (typeof value === "string" ? value.trim().toLowerCase() : null);

/**
 * Is this EIP-712 request the registry's node-location struct: its primary type, any struct it defines, or its domain
 * name is the registry's? Case and surrounding spaces do not matter.
 */
export function isRegistryTypedData(typedData: unknown): boolean {
  if (typedData === null || typeof typedData !== "object") return false;
  const { domain, types, primaryType } = typedData as { domain?: unknown; types?: unknown; primaryType?: unknown };
  if (folded(primaryType) === REGISTRY_TYPED_PRIMARY_TYPE) return true;
  if (domain !== null && typeof domain === "object" && folded((domain as { name?: unknown }).name) === REGISTRY_TYPED_DOMAIN_NAME) return true;
  if (types !== null && typeof types === "object" && Object.keys(types).some((name) => folded(name) === REGISTRY_TYPED_PRIMARY_TYPE)) return true;
  return registryDomainByAddressOrSeparator(typedData);
}

// The registry contracts are upgradeable proxies, so the domain is also recognised by where it points and by the
// separator it hashes to, whatever the request calls it or however it declares its domain fields.
const REGISTRY_PROXIES = [
  { chainId: 1, address: "0xbA1bf1B4C72d779f3dd21a8f29a70A82fD4dc3B7" },
  { chainId: 11155111, address: "0x89e5DEc611f357b7274B3d74fF3E2e03075ec1F8" },
] as const;

type DomainArg = Parameters<typeof hashDomain>[0];

/** The domain separator as viem computes it for a typed-data request: explicit `EIP712Domain` types win. */
function domainSeparatorOf(domain: DomainArg["domain"], types: object): string {
  return hashDomain({
    domain,
    types: { EIP712Domain: getTypesForEIP712Domain({ domain }), ...types } as DomainArg["types"],
  });
}

const REGISTRY_DOMAIN_SEPARATORS: ReadonlySet<string> = new Set(
  REGISTRY_PROXIES.map(({ chainId, address }) =>
    domainSeparatorOf({ name: "TinyCloudRegistry", version: "1", chainId, verifyingContract: address }, {}),
  ),
);
const REGISTRY_PROXY_ADDRESSES: ReadonlySet<string> = new Set(REGISTRY_PROXIES.map(({ address }) => address.toLowerCase()));

/** True when the request's domain points at a registry proxy or hashes to a registry separator; a domain that cannot be hashed counts. */
function registryDomainByAddressOrSeparator(typedData: object): boolean {
  const { domain, types } = typedData as { domain?: unknown; types?: unknown };
  if (domain !== null && typeof domain === "object") {
    const contract = folded((domain as { verifyingContract?: unknown }).verifyingContract);
    if (contract !== null && REGISTRY_PROXY_ADDRESSES.has(contract)) return true;
  }
  try {
    const explicit = types !== null && typeof types === "object" ? types : {};
    return REGISTRY_DOMAIN_SEPARATORS.has(domainSeparatorOf(domain as DomainArg["domain"], explicit));
  } catch {
    return true;
  }
}

/** The refusal for this typed data and requesting origin, or null when it may go on to the other checks. */
export function registryTypedDataSignRefusal(
  typedData: unknown,
  requestOrigin: unknown,
): { reason: "registry_record"; message: string } | null {
  if (registryRecordSignOriginAllowed(requestOrigin) || !isRegistryTypedData(typedData)) return null;
  return { reason: "registry_record", message: REGISTRY_RECORD_SIGN_REFUSED.apiMessage };
}
