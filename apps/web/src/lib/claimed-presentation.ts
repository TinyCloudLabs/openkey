// What an app says about its own sign request, and what the sign screen may show of it.
//
// `client.signMessage({ message, keyId, presentation })` carries the app's own words: a name, who the grant is for and a
// reason, with an optional icon. The signed bytes are the message and nothing here; the words are display-only and
// never leave this module toward the API, the signer or any record. The verified origin stays the screen's only
// identity: these words sit beneath it, in the app's voice, and are marked as unchecked.
//
// `claimedPresentation` cleans every field, drops what must not be shown, and `claimedPresentationView` turns the
// survivors into the exact lines the screen renders.

/** Longest text of each claim, in characters, after cleaning. */
export const CLAIM_LIMITS = { displayName: 64, onBehalfOf: 64, reason: 280 } as const;

/** Longest icon data URI, in characters of the encoded string. */
export const MAX_ICON_URI_LENGTH = 32768;

// More input than any claim needs is never read: NFKC can expand one character into several, so the cap on what is
// cleaned bounds the work for a hostile string.
const MAX_INPUT_LENGTH = 1024;

/**
 * Names of OpenKey and TinyCloud's own products. A name or an "on behalf of" that contains one of these (however it is
 * spaced, punctuated or disguised) is shown only for a requester on `TRUSTED_SHELL_ORIGINS`.
 */
export const RESERVED_NAMES: readonly string[] = [
  'TinyCloud',
  'TinyCloud One',
  'OpenKey',
  'TinyChat',
  'Share',
  'Secret Manager',
];

/**
 * Requesters that may call themselves by a reserved name: the exact origins of OpenKey's own pages and of the TinyCloud
 * apps that sign in through OpenKey (TinyChat on tinycloud.chat, Home on home.tinycloud.xyz and tinycloud.one, the
 * desktop app, Share, Secret Manager). Matching is byte-exact on the verified origin the widget saw.
 */
export const TRUSTED_SHELL_ORIGINS: Record<string, true | undefined> = {
  'https://openkey.so': true,
  'https://console.openkey.so': true,
  'https://tinycloud.chat': true,
  'https://home.tinycloud.xyz': true,
  'https://tinycloud.one': true,
  'tauri://localhost': true,
  'http://tauri.localhost': true,
  'https://share.tinycloud.xyz': true,
  'https://secrets.tinycloud.xyz': true,
};

/** What survives of an app's presentation. Every text is cleaned; an absent field is `null`. */
export interface ClaimedPresentation {
  displayName: string | null;
  /** The name's icon: set only when `displayName` is. */
  iconUrl: string | null;
  /** `verified` is true only when the text equals the delegatee DID or URI of the signed message. */
  onBehalfOf: { text: string; verified: boolean } | null;
  reason: string | null;
}

// ---- cleaning -------------------------------------------------------------

// Characters that render as nothing or change the direction of what follows: controls, format characters (bidi marks,
// embeddings, overrides and isolates, zero-width spaces and joiners, the byte order mark, tags), private-use,
// unassigned and surrogate code points, variation selectors, and the letters and symbols that draw as blanks.
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Cs}\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180f\u2800\u3164\ufe00-\ufe0f\uffa0]/gu;

function cleanText(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const text = value
    .slice(0, MAX_INPUT_LENGTH)
    .normalize('NFKC')
    // Line breaks and tabs are controls too, but they separate words: they become a space before the rest goes.
    .replace(/\s+/gu, ' ')
    .replace(INVISIBLE, '')
    .replace(/\s+/gu, ' ')
    .trim();
  return text === '' ? null : text;
}

/** At most `limit` characters; a longer text is cut and ends in an ellipsis. */
function capText(text: string, limit: number): string {
  const characters = Array.from(text);
  if (characters.length <= limit) return text;
  return `${characters.slice(0, limit - 1).join('').trimEnd()}…`;
}

// ---- reserved names -------------------------------------------------------

// Letters from other scripts and lookalike symbols, as the Latin letter or digit they pass for. The text is
// lower-cased first, so only lower-case forms are listed.
const LOOKALIKES: Record<string, string> = {
  // Cyrillic
  'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c', 'т': 't',
  'у': 'y', 'х': 'x', 'і': 'i', 'ї': 'i', 'ј': 'j', 'ѕ': 's', 'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ѵ': 'v',
  'ӏ': 'l', 'ө': 'o',
  // Greek
  'α': 'a', 'β': 'b', 'γ': 'y', 'ε': 'e', 'ζ': 'z', 'η': 'n', 'ι': 'i', 'κ': 'k', 'μ': 'u', 'ν': 'v', 'ο': 'o',
  'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w', 'ϲ': 'c', 'ϳ': 'j',
  // Latin lookalikes: dotless i, script g, alpha, iota, and the small capitals
  'ı': 'i', 'ɡ': 'g', 'ɑ': 'a', 'ɩ': 'i', 'ᴀ': 'a', 'ʙ': 'b', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e', 'ɢ': 'g', 'ʜ': 'h',
  'ɪ': 'i', 'ᴊ': 'j', 'ᴋ': 'k', 'ʟ': 'l', 'ᴍ': 'm', 'ɴ': 'n', 'ᴏ': 'o', 'ᴘ': 'p', 'ʀ': 'r', 'ꜱ': 's', 'ᴛ': 't',
  'ᴜ': 'u', 'ᴠ': 'v', 'ᴡ': 'w', 'ʏ': 'y', 'ᴢ': 'z',
  // Digits and symbols used for letters
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '!': 'l', '|': 'l', '@': 'a', '$': 's', '€': 'e',
};

/**
 * The text as a reader sees it, reduced for comparison: NFKC, no invisible characters, no accents, lower case,
 * lookalikes folded to the letter they imitate (`i`, `l`, `1` and `|` are all `l`), then no spaces or punctuation.
 */
function skeleton(text: string): string {
  const reduced = (cleanText(text) ?? '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/\p{M}/gu, '');
  let folded = '';
  for (const character of reduced) folded += LOOKALIKES[character] ?? character;
  // `rn` reads as `m` and `cl` as `d`; both sides are folded the same way, so a name that spells one for the other matches.
  return folded
    .replace(/[^\p{L}\p{N}]/gu, '')
    .replace(/i/gu, 'l')
    .replace(/rn/gu, 'm')
    .replace(/cl/gu, 'd');
}

const RESERVED_SKELETONS: readonly string[] = RESERVED_NAMES.map(skeleton);

/** Does the text contain a reserved name once spacing, punctuation, invisible characters and lookalikes are folded? */
export function containsReservedName(text: string): boolean {
  const reduced = skeleton(text);
  return RESERVED_SKELETONS.some((reserved) => reduced.includes(reserved));
}

// ---- host-like names ------------------------------------------------------

// Labels of letters and digits joined by dots (the dot spelled as full stop, ideographic full stop or half-width
// ideographic full stop), ending in a label of two or more letters: `example.com`, `app.example.co.uk`.
const HOST_LIKE = /[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?(?:[.\u3002\uff61][\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?)*[.\u3002\uff61]\p{L}[\p{L}-]*\p{L}/gu;

function originHosts(origin: string): string[] {
  try {
    const url = new URL(origin);
    return [url.host.toLowerCase(), url.hostname.toLowerCase()];
  } catch {
    return [];
  }
}

/** Does the name hold something that reads as a host name other than the verified origin's own? */
function namesAnotherHost(name: string, origin: string): boolean {
  const own = originHosts(origin);
  const found = name.match(HOST_LIKE) ?? [];
  return found.some((candidate) => !own.includes(candidate.toLowerCase().replace(/[\u3002\uff61]/gu, '.')));
}

// ---- icon -----------------------------------------------------------------

// The start of each format's bytes, as base64: PNG signature, JPEG start of image, RIFF header (WebP).
const ICON_FORMATS: Record<string, string> = { png: 'iVBORw0KGgo', jpeg: '/9j/', webp: 'UklGR' };
const ICON_URI = /^data:image\/(png|jpeg|webp);base64,([A-Za-z0-9+/]+={0,2})$/;

function validIcon(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > MAX_ICON_URI_LENGTH) return null;
  const match = ICON_URI.exec(value);
  if (!match) return null;
  const [, format, data] = match;
  if (data!.length % 4 !== 0 || !data!.startsWith(ICON_FORMATS[format!]!)) return null;
  return value;
}

// ---- the decision ---------------------------------------------------------

/** Does the text name the signed message's delegatee: its URI, or the DID part of it? */
function namesDelegatee(text: string, signedUri: string | null): boolean {
  if (signedUri === null) return false;
  const uri = signedUri.trim();
  return uri !== '' && (text === uri || text === uri.split('#')[0]);
}

/** An own field of the app's presentation, whatever it holds. */
function fieldOf(source: object, name: string): unknown {
  return Object.hasOwn(source, name) ? Reflect.get(source, name) : undefined;
}

/**
 * What of the app's presentation may be shown under the verified `origin`, or `null` when nothing may.
 *
 * - A name that reads as another host than the origin's is dropped.
 * - A name or "on behalf of" that contains a reserved name is dropped unless the origin is a trusted shell. Nothing
 *   marks the drop: the screen shows what is left.
 * - An "on behalf of" equal to the delegatee DID or URI in the signed message (`signedUri`) is verified; any other is a claim.
 * - The icon is shown only beside a name that is shown, and only as a small PNG, JPEG or WebP data URI.
 *
 * Every text is cleaned and cut to its limit. With no verified origin nothing is shown.
 */
export function claimedPresentation(input: {
  presentation: unknown;
  origin: string;
  signedUri: string | null;
}): ClaimedPresentation | null {
  const { presentation, origin, signedUri } = input;
  if (!origin || origin === '*' || origin === 'null') return null;
  if (typeof presentation !== 'object' || presentation === null || Array.isArray(presentation)) return null;
  if (fieldOf(presentation, 'protocolVersion') !== 1) return null;
  const trusted = Object.hasOwn(TRUSTED_SHELL_ORIGINS, origin);

  let displayName = cleanText(fieldOf(presentation, 'displayName'));
  if (displayName !== null && (namesAnotherHost(displayName, origin) || (!trusted && containsReservedName(displayName)))) {
    displayName = null;
  }

  let onBehalfOf: ClaimedPresentation['onBehalfOf'] = null;
  const behalfText = cleanText(fieldOf(presentation, 'onBehalfOf'));
  if (behalfText !== null) {
    if (namesDelegatee(behalfText, signedUri)) onBehalfOf = { text: capText(behalfText, CLAIM_LIMITS.onBehalfOf), verified: true };
    else if (trusted || !containsReservedName(behalfText)) {
      onBehalfOf = { text: capText(behalfText, CLAIM_LIMITS.onBehalfOf), verified: false };
    }
  }

  const reasonText = cleanText(fieldOf(presentation, 'reason'));
  const reason = reasonText === null ? null : capText(reasonText, CLAIM_LIMITS.reason);
  const iconUrl = displayName === null ? null : validIcon(fieldOf(presentation, 'iconUrl'));
  displayName = displayName === null ? null : capText(displayName, CLAIM_LIMITS.displayName);

  if (displayName === null && onBehalfOf === null && reason === null) return null;
  return { displayName, iconUrl, onBehalfOf, reason };
}

// ---- the words on the screen ----------------------------------------------

/** The sign screen's lines for an app's own words; `{value}` is where the app's text goes. */
export const claimedPresentationCopy = {
  nameOnly: `It calls itself "{value}". OpenKey hasn't checked that name.`,
  name: `It calls itself "{value}".`,
  onBehalfOf: `It says it's asking for "{value}".`,
  verifiedOnBehalfOf: `It is asking for "{value}".`,
  reason: `Its reason: "{value}"`,
  closingOne: `OpenKey hasn't checked this.`,
  closingMany: `OpenKey hasn't checked these.`,
} as const;

/** One line: the copy around the app's text, which the screen sets apart so it cannot bend the surrounding words. */
export interface ClaimLine {
  kind: 'name' | 'onBehalfOf' | 'reason';
  before: string;
  value: string;
  after: string;
}

export interface ClaimedPresentationView {
  /** The "on behalf of" that matches the signed message; the only line that is not an unchecked claim. */
  verified: Omit<ClaimLine, 'kind'> | null;
  /** The claims in the order name, on-behalf-of, reason. */
  claims: ClaimLine[];
  /** One closing line after the claims; `null` where the name line says it itself. */
  closing: string | null;
  iconUrl: string | null;
}

function line<K extends ClaimLine['kind']>(kind: K, template: string, value: string): ClaimLine & { kind: K } {
  const [before = '', after = ''] = template.split('{value}');
  return { kind, before, value, after };
}

/** The text of a line, as a reader sees it. */
export function claimLineText(claim: Omit<ClaimLine, 'kind'>): string {
  return `${claim.before}${claim.value}${claim.after}`;
}

/** The lines the sign screen shows for what survived `claimedPresentation`. */
export function claimedPresentationView(claimed: ClaimedPresentation): ClaimedPresentationView {
  const claims: ClaimLine[] = [];
  const nameAlone = claimed.displayName !== null && (claimed.onBehalfOf === null || claimed.onBehalfOf.verified) && claimed.reason === null;
  if (claimed.displayName !== null) {
    claims.push(line('name', nameAlone ? claimedPresentationCopy.nameOnly : claimedPresentationCopy.name, claimed.displayName));
  }
  if (claimed.onBehalfOf && !claimed.onBehalfOf.verified) {
    claims.push(line('onBehalfOf', claimedPresentationCopy.onBehalfOf, claimed.onBehalfOf.text));
  }
  if (claimed.reason !== null) claims.push(line('reason', claimedPresentationCopy.reason, claimed.reason));
  const verified = claimed.onBehalfOf?.verified ? line('onBehalfOf', claimedPresentationCopy.verifiedOnBehalfOf, claimed.onBehalfOf.text) : null;
  return {
    verified: verified && { before: verified.before, value: verified.value, after: verified.after },
    claims,
    closing: nameAlone || claims.length === 0
      ? null
      : claims.length === 1 ? claimedPresentationCopy.closingOne : claimedPresentationCopy.closingMany,
    iconUrl: claimed.iconUrl,
  };
}
