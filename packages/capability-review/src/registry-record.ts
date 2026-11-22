// Hardening: registry record signing. A signed location-registry record (v1 or v2) is signed as its canonical JSON,
// text or the 0x hex of its UTF-8 bytes. Such a payload is signed only for the TinyCloud One / Home origins below;
// every other origin, and an unattributed request, is refused before an approval is offered.

/** Origins that may ask for a registry record signature, compared as exact strings. */
export const REGISTRY_RECORD_SIGN_ORIGINS: readonly string[] = [
  "https://home.tinycloud.xyz",
  "https://tinycloud.one",
  "https://app.tinycloud.one",
  "tauri://localhost",
  "http://tauri.localhost",
  "tinycloudone://app.tinycloud.one",
];

/** Words for the refusal, in one place: the popup page, the embed page and the API error. */
export const REGISTRY_RECORD_SIGN_REFUSED = {
  code: "registry_record_sign_refused",
  title: "This app's request can't be signed",
  popupBody:
    "It would set which TinyCloud node holds your data. Only TinyCloud One or the TinyCloud CLI can ask for that, so this app can't. Nothing was signed. You can close this window.",
  embedBody:
    "It would set which TinyCloud node holds your data. Only TinyCloud One or the TinyCloud CLI can ask for that, so this app can't. Nothing was signed. You can go back to the app.",
  popupButton: "Close",
  embedButton: "Back to the app",
  apiMessage:
    "Only TinyCloud One and the TinyCloud CLI can request a signature that sets the account's node location. Nothing was signed.",
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
