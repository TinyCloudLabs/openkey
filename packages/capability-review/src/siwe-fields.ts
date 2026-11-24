// The one reader of a SIWE message's fields (TC-3826).
//
// The TinyCloud node reads an EIP-4361 message with the siwe crate: lines split
// on `\n` only, every field in grammar order. A JS `m`-mode regex also breaks
// lines at `\r`, U+2028 and U+2029, so `/^Expiration Time: (.+)$/m` can match a
// fake line inside the statement while the node enforces the real field after
// `Issued At`. Every OpenKey reader of a signed message's fields (expiry caps,
// refusals, previews, the approval screen) reads them here instead, and a
// message carrying any of those characters does not parse at all.

export interface SiweFields {
  scheme?: string;
  domain: string;
  address: string;
  statement?: string;
  uri: string;
  version: string;
  chainId: string;
  nonce: string;
  issuedAt: string;
  expirationTime?: string;
  notBefore?: string;
  requestId?: string;
  /** Every resource as written; absent when the message has no `Resources:` line. */
  resources?: string[];
}

export type SiweFieldsOutcome = { ok: true; fields: SiweFields } | { ok: false; message: string };

/** A resource or URI value: `<scheme>:<non-space>`. */
export const SIWE_URI_PATTERN = /^[A-Za-z][A-Za-z0-9+.-]*:\S+$/;

const HEADER = /^(?:([A-Za-z][A-Za-z0-9+.-]*):\/\/)?(\S+) wants you to sign in with your Ethereum account:$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const CHAIN_ID = /^[1-9][0-9]*$/;
const NONCE = /^[A-Za-z0-9]{8,}$/;
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const REQUEST_ID = /^(?:[A-Za-z0-9\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})*$/;
// Every C0 control except line feed, DEL, and the two characters JS regexes
// treat as line breaks but the node does not (U+2028, U+2029).
const FORBIDDEN_CHARACTER = /[\u0000-\u0009\u000b-\u001f\u007f\u2028\u2029]/;

/** Whether `text` carries a character OpenKey never signs or shows in a SIWE: a C0 control other than `\n`, DEL, U+2028 or U+2029. */
export function hasForbiddenSiweCharacter(text: string): boolean {
  return FORBIDDEN_CHARACTER.test(text);
}

function isDateTime(value: string): boolean {
  return DATE_TIME.test(value) && Number.isFinite(Date.parse(value));
}

export function serializeSiwe(siwe: SiweFields): string {
  const lines = [
    `${siwe.scheme !== undefined ? `${siwe.scheme}://` : ""}${siwe.domain} wants you to sign in with your Ethereum account:`,
    siwe.address,
    "",
  ];
  if (siwe.statement !== undefined) lines.push(siwe.statement);
  lines.push(
    "",
    `URI: ${siwe.uri}`,
    `Version: ${siwe.version}`,
    `Chain ID: ${siwe.chainId}`,
    `Nonce: ${siwe.nonce}`,
    `Issued At: ${siwe.issuedAt}`,
  );
  if (siwe.expirationTime !== undefined) lines.push(`Expiration Time: ${siwe.expirationTime}`);
  if (siwe.notBefore !== undefined) lines.push(`Not Before: ${siwe.notBefore}`);
  if (siwe.requestId !== undefined) lines.push(`Request ID: ${siwe.requestId}`);
  if (siwe.resources !== undefined) lines.push("Resources:", ...siwe.resources.map((r) => `- ${r}`));
  return lines.join("\n");
}

/**
 * Read an EIP-4361 message the way the node does. Every field must appear in
 * grammar order at most once, every value must be well formed, there is no
 * other line, and re-serializing the result reproduces the input byte for
 * byte. A message with a forbidden character (see `hasForbiddenSiweCharacter`)
 * does not parse.
 */
export function parseSiweFields(message: string): SiweFieldsOutcome {
  try {
    return { ok: true, fields: parseOrThrow(message) };
  } catch (e) {
    return { ok: false, message: e instanceof Error ? e.message : "unparsable SIWE" };
  }
}

/**
 * The `Expiration Time` field of a SIWE message, read by `parseSiweFields`;
 * null when the message does not parse or has no expiry. Callers holding a
 * message to a lifetime cap must treat null as over the cap.
 */
export function siweExpirationTime(message: string): string | null {
  const parsed = parseSiweFields(message);
  return parsed.ok ? (parsed.fields.expirationTime ?? null) : null;
}

function parseOrThrow(message: string): SiweFields {
  if (hasForbiddenSiweCharacter(message)) throw new Error("message contains a forbidden character");
  const lines = message.split("\n");
  let n = 0;
  const line = (): string => {
    const current = lines[n];
    if (current === undefined) throw new Error("message ends early");
    return current;
  };
  const required = (label: string, valid: (value: string) => boolean): string => {
    const current = line();
    if (!current.startsWith(`${label}: `)) throw new Error(`line ${n + 1}: expected "${label}:"`);
    const value = current.slice(label.length + 2);
    if (!valid(value)) throw new Error(`line ${n + 1}: invalid ${label}`);
    n += 1;
    return value;
  };
  const optional = (label: string, valid: (value: string) => boolean): string | undefined =>
    lines[n]?.startsWith(`${label}: `) ? required(label, valid) : undefined;

  const header = HEADER.exec(line());
  if (!header) throw new Error("line 1: not a SIWE header");
  n += 1;
  const address = line();
  if (!ADDRESS.test(address)) throw new Error("line 2: not an address");
  n += 1;
  if (line() !== "") throw new Error("line 3: expected a blank line");
  n += 1;
  let statement: string | undefined;
  if (line() !== "") {
    statement = line();
    n += 1;
  }
  if (line() !== "") throw new Error(`line ${n + 1}: expected a blank line`);
  n += 1;

  const siwe: SiweFields = {
    ...(header[1] !== undefined ? { scheme: header[1] } : {}),
    domain: header[2]!,
    address,
    ...(statement !== undefined ? { statement } : {}),
    uri: required("URI", (v) => SIWE_URI_PATTERN.test(v)),
    version: required("Version", (v) => v === "1"),
    chainId: required("Chain ID", (v) => CHAIN_ID.test(v) && Number.isSafeInteger(Number(v))),
    nonce: required("Nonce", (v) => NONCE.test(v)),
    issuedAt: required("Issued At", isDateTime),
  };
  const expirationTime = optional("Expiration Time", isDateTime);
  if (expirationTime !== undefined) siwe.expirationTime = expirationTime;
  const notBefore = optional("Not Before", isDateTime);
  if (notBefore !== undefined) siwe.notBefore = notBefore;
  const requestId = optional("Request ID", (v) => REQUEST_ID.test(v));
  if (requestId !== undefined) siwe.requestId = requestId;

  if (n < lines.length && lines[n] === "Resources:") {
    n += 1;
    const resources: string[] = [];
    for (; n < lines.length; n += 1) {
      const current = lines[n]!;
      if (!current.startsWith("- ") || !SIWE_URI_PATTERN.test(current.slice(2))) {
        throw new Error(`line ${n + 1}: not a resource`);
      }
      resources.push(current.slice(2));
    }
    if (new Set(resources).size !== resources.length) throw new Error("a resource is listed twice");
    siwe.resources = resources;
  }
  if (n !== lines.length) throw new Error(`line ${n + 1}: unexpected line`);
  if (serializeSiwe(siwe) !== message) throw new Error("message does not re-serialize to the same bytes");
  return siwe;
}
