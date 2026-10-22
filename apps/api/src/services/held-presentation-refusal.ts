import { SiweMessage } from 'siwe';
import { decodeHexUtf8 } from './siwe-origin';

// TC-1456 S5 (DESIGN-v5 §3.3b): refuse signing that would grant the held
// `tinycloud.credentials/present` ability. Default OFF; with the flag unset
// the behaviour matches main exactly.
export const HELD_PRESENT_SIGNING_FLAG = 'HELD_PRESENT_SIGNING_ENABLED';

const SIWE_MARKER = ' wants you to sign in with your Ethereum account:';
const RECAP_TOKEN = /urn:recap:[A-Za-z0-9_-]+/g;
const CREDENTIALS_SERVICE = 'credentials';
const CREDENTIALS_ABILITY_PREFIX = 'tinycloud.credentials/';
const PRESENT_LITERAL = 'credentials/present';
const PRESENT_ABILITY = 'tinycloud.credentials/present';

export function heldPresentSigningEnabled(env: Record<string, string | undefined> = process.env): boolean {
  return env[HELD_PRESENT_SIGNING_FLAG] === 'true';
}

/**
 * True for the held credentials service under either spelling used by
 * permission entries. Exact service equality only; never a prefix match.
 */
export function isHeldCredentialsService(service: string): boolean {
  return service === CREDENTIALS_SERVICE || service === 'tinycloud.credentials';
}

/**
 * Decodes `urn:recap:<base64url JSON>` into resource -> ability names.
 * Returns null when the resource does not decode, so callers fail closed.
 */
function decodeRecapAtt(uri: string): Record<string, string[]> | null {
  const body = uri.slice('urn:recap:'.length).replace(/-/g, '+').replace(/_/g, '/');
  const padded = body + '='.repeat((4 - (body.length % 4)) % 4);
  let json: unknown;
  try {
    json = JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
  } catch {
    return null;
  }
  if (typeof json !== 'object' || json === null || !('att' in json)) return null;
  const att = json.att;
  if (typeof att !== 'object' || att === null) return null;

  const out: Record<string, string[]> = {};
  for (const [resource, abilities] of Object.entries(att)) {
    if (typeof abilities !== 'object' || abilities === null) return null;
    out[resource] = Object.keys(abilities);
  }
  return out;
}

/** Resource service is the second `/` segment of `<space>/<service>/<path>`. */
function recapTouchesCredentials(uri: string): boolean | null {
  const att = decodeRecapAtt(uri);
  if (att === null) return null;
  return Object.entries(att).some(
    ([resource, abilities]) =>
      resource.split('/')[1] === CREDENTIALS_SERVICE ||
      abilities.some((ability) => ability.startsWith(CREDENTIALS_ABILITY_PREFIX)),
  );
}

function recapGrantsPresent(uri: string): boolean | null {
  const att = decodeRecapAtt(uri);
  if (att === null) return null;
  return Object.values(att).some((abilities) => abilities.includes(PRESENT_ABILITY));
}

/**
 * Shared SIWE scan. `recapHit` returning null (unreadable ReCap) counts as a hit.
 * Only SIWE-shaped text is inspected; other bytes are never matched.
 */
function siweScan(text: string, recapHit: (uri: string) => boolean | null): boolean {
  if (!text.includes(SIWE_MARKER)) return false;

  const recapUris = text.match(RECAP_TOKEN) ?? [];
  let parsed: SiweMessage | null = null;
  try {
    parsed = new SiweMessage(text);
  } catch {
    parsed = null;
  }

  if (parsed === null) {
    // Fail closed: a ReCap we cannot read, or the literal ability anywhere.
    return recapUris.length > 0 || text.includes(PRESENT_LITERAL);
  }

  for (const uri of recapUris) {
    if (recapHit(uri) !== false) return true;
  }
  return [parsed.statement ?? '', ...(parsed.resources ?? [])].some((s) => s.includes(PRESENT_LITERAL));
}

/**
 * True when this text, as the signer would cover it, grants a credentials
 * ability. Holder-binding and account-binding bytes are never refused here.
 */
function refusesText(text: string): boolean {
  return siweScan(text, recapTouchesCredentials);
}

/** True when this SIWE text grants `tinycloud.credentials/present` (or the literal). */
export function grantsHeldPresent(text: string): boolean {
  return siweScan(text, recapGrantsPresent);
}

/**
 * Checks the message both as written and as the UTF-8 bytes a `raw` signature
 * covers, so SIWE text cannot hide inside `0x` hex.
 */
export function refusesHeldPresentation(message: string): boolean {
  if (refusesText(message)) return true;
  const decoded = decodeHexUtf8(message);
  return decoded !== null && refusesText(decoded);
}

/** Origins whose held presentations may be signed (DESIGN-v5 §3.2.3). Exo and preview hosts are excluded. */
export const FIRST_PARTY_ORIGINS: readonly string[] = ['https://share.tinycloud.xyz'];

/**
 * D-5 (DESIGN-v5 §3.2.3): a held presentation may only be signed when the
 * verified origin is first-party and the SIWE `Scheme:` (absent = https) and
 * `domain` equal that origin exactly. Returns a refusal reason, or null.
 */
export function heldPresentOriginRefusal(siweText: string, verifiedOrigin: string | undefined): string | null {
  if (!verifiedOrigin) return 'no verified origin (CLI handoff or missing context)';
  if (!FIRST_PARTY_ORIGINS.includes(verifiedOrigin)) return 'origin is not a first-party origin';
  let siwe: SiweMessage;
  try {
    siwe = new SiweMessage(siweText);
  } catch {
    return 'SIWE message unreadable';
  }
  const expected = new URL(verifiedOrigin);
  if ((siwe.scheme ?? 'https') !== expected.protocol.slice(0, -1)) return 'SIWE scheme does not match origin';
  if (siwe.domain !== expected.host) return 'SIWE domain does not match origin host';
  return null;
}
