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
 * Names of OpenKey and TinyCloud's own products. A name, an "on behalf of" or a reason that contains one of these
 * (however it is spaced, punctuated or disguised) is shown only for a requester on `TRUSTED_SHELL_ORIGINS`. "Share"
 * and "Secret Manager" count only as whole words.
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
 * Requesters that may call themselves by a reserved name: the exact https origins of OpenKey's own pages and of the
 * TinyCloud apps that sign in through OpenKey (TinyCloud One on tinycloud.one, Share, Secret Manager). Matching is
 * byte-exact on the verified origin the widget saw. A desktop webview origin is not here: every app in that webview
 * has it.
 */
export const TRUSTED_SHELL_ORIGINS: Record<string, true | undefined> = {
  'https://openkey.so': true,
  'https://console.openkey.so': true,
  'https://tinycloud.one': true,
  'https://share.tinycloud.xyz': true,
  'https://secrets.tinycloud.xyz': true,
};

/** What survives of an app's presentation. Every text is cleaned; an absent field is `null`. */
export interface ClaimedPresentation {
  displayName: string | null;
  /** The name's icon: set only when `displayName` is. */
  iconUrl: string | null;
  onBehalfOf: string | null;
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

// ---- scripts ----------------------------------------------------------------

// The scripts a name may be written in. Japanese and Korean text mixes Han with its own scripts, so those share a group.
const SCRIPT_GROUPS: ReadonlyArray<readonly [string, RegExp]> = [
  ['latin', /\p{Script=Latin}/u],
  ['cyrillic', /\p{Script=Cyrillic}/u],
  ['greek', /\p{Script=Greek}/u],
  ['armenian', /\p{Script=Armenian}/u],
  ['cherokee', /\p{Script=Cherokee}/u],
  ['georgian', /\p{Script=Georgian}/u],
  ['hebrew', /\p{Script=Hebrew}/u],
  ['arabic', /\p{Script=Arabic}/u],
  ['devanagari', /\p{Script=Devanagari}/u],
  ['thai', /\p{Script=Thai}/u],
  ['cjk', /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Bopomofo}]/u],
];
const NEUTRAL_SCRIPT = /[\p{Script=Common}\p{Script=Inherited}]/u;

/**
 * Is the text written in more than one script? Digits, punctuation, symbols and spaces belong to none; a letter of a
 * script not listed counts as one script of its own.
 */
function mixesScripts(text: string): boolean {
  const found = new Set<string>();
  for (const character of text) {
    if (!/\p{L}/u.test(character) || NEUTRAL_SCRIPT.test(character)) continue;
    found.add(SCRIPT_GROUPS.find(([, script]) => script.test(character))?.[0] ?? 'other');
    if (found.size > 1) return true;
  }
  return false;
}

// ---- reserved names -------------------------------------------------------

// Letters from other scripts and lookalike symbols, as the Latin letter or digit they pass for. The text is
// lower-cased first, so only lower-case forms are listed.
const LOOKALIKES: Record<string, string> = {
  // Cyrillic
  'а': 'a', 'в': 'b', 'ь': 'b', 'е': 'e', 'ё': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'п': 'n', 'р': 'p', 'с': 'c',
  'т': 't', 'у': 'y', 'ү': 'y', 'х': 'x', 'і': 'i', 'ї': 'i', 'ј': 'j', 'ѕ': 's', 'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
  'ѵ': 'v', 'ӏ': 'l', 'ө': 'o',
  // Greek
  'α': 'a', 'β': 'b', 'γ': 'y', 'ε': 'e', 'ζ': 'z', 'η': 'n', 'ι': 'i', 'κ': 'k', 'μ': 'u', 'ν': 'v', 'ο': 'o',
  'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w', 'ϲ': 'c', 'ϳ': 'j',
  // Armenian and Cherokee
  'օ': 'o', 'ս': 'u', 'ꮯ': 'c',
  // Latin lookalikes: dotless i, kra, script g, alpha, iota, reversed e, and the small capitals
  'ı': 'i', 'ĸ': 'k', 'ɡ': 'g', 'ɑ': 'a', 'ɩ': 'i', 'ɘ': 'e', 'ǝ': 'e', 'ɛ': 'e', 'ʋ': 'u', 'ᴀ': 'a', 'ʙ': 'b', 'ᴄ': 'c',
  'ᴅ': 'd', 'ᴇ': 'e', 'ɢ': 'g', 'ʜ': 'h', 'ɪ': 'i', 'ᴊ': 'j', 'ᴋ': 'k', 'ʟ': 'l', 'ᴍ': 'm', 'ɴ': 'n', 'ᴏ': 'o', 'ᴘ': 'p',
  'ʀ': 'r', 'ꜱ': 's', 'ᴛ': 't', 'ᴜ': 'u', 'ᴠ': 'v', 'ᴡ': 'w', 'ʏ': 'y', 'ᴢ': 'z',
  // Digits and symbols used for letters
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '!': 'l', '|': 'l', '@': 'a', '$': 's', '€': 'e',
  '○': 'o', '◯': 'o', '〇': 'o', '⚪': 'o', '◦': 'o',
};

/** The text lower-cased, in NFKD with no accents or invisible characters. */
function reduced(text: string): string {
  return (cleanText(text) ?? '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/\p{M}/gu, '');
}

/** `i` and `l`, `u` and `v`, `rn` and `m`, `cl` and `d` read alike, so each pair is folded to one spelling. */
function foldedSpelling(letters: string): string {
  return letters
    .replace(/i/gu, 'l')
    .replace(/v/gu, 'u')
    .replace(/rn/gu, 'm')
    .replace(/cl/gu, 'd');
}

/**
 * The text as a reader sees it, reduced for comparison: NFKC, no invisible characters, no accents, lower case,
 * lookalikes folded to the letter they imitate, then no spaces or punctuation. `i`, `l`, `1` and `|` are all `l`, `u`
 * and `v` are `u`, `o`, `0` and `○` are `o`, `rn` is `m` and `cl` is `d`; both sides of a comparison are folded the
 * same way, so a name that spells one for the other matches.
 */
function skeleton(text: string): string {
  let folded = '';
  for (const character of reduced(text)) folded += LOOKALIKES[character] ?? character;
  return foldedSpelling(folded.replace(/[^\p{L}\p{N}]/gu, ''));
}

/**
 * The words of the text after lookalike folding; every character that is not a letter ends a word. With
 * `boundaries`, a digit and a symbol that would pass for a letter (`4` for `a`, `!` for `l`) end a word instead of
 * being folded, so `Share!` and `Share1` read as the word `share`. Runs of single letters (`S h a r e`) are joined.
 */
function words(text: string, boundaries: boolean): string[] {
  let folded = '';
  for (const character of reduced(text)) {
    folded += boundaries && /[\p{N}!|@$€]/u.test(character) ? ' ' : LOOKALIKES[character] ?? character;
  }
  const joined: string[] = [];
  let inSingleRun = false;
  for (const word of folded.split(/[^\p{L}]+/u).filter((part) => part !== '')) {
    const single = Array.from(word).length === 1;
    if (single && inSingleRun) joined[joined.length - 1] += word;
    else joined.push(word);
    inSingleRun = single;
  }
  return joined.map(foldedSpelling);
}

// Generic words among the reserved names. They are matched as whole words, so "Shared Notes" and "ShareThis" are not
// reserved while "Share", "My Share" and "Share-Notes" are; the other names match anywhere in the text.
const WHOLE_WORD_NAMES: Record<string, true | undefined> = { Share: true, 'Secret Manager': true };

const SUBSTRING_SKELETONS: readonly string[] = RESERVED_NAMES.filter((name) => !Object.hasOwn(WHOLE_WORD_NAMES, name)).map(skeleton);
const WHOLE_WORD_SEQUENCES: readonly (readonly string[])[] = RESERVED_NAMES.filter((name) => Object.hasOwn(WHOLE_WORD_NAMES, name)).map((name) =>
  words(name, false),
);

function holdsWholeWord(textWords: readonly string[]): boolean {
  return WHOLE_WORD_SEQUENCES.some((sequence) => {
    const together = sequence.join('');
    return textWords.some(
      (word, start) => word === together || sequence.every((part, offset) => textWords[start + offset] === part),
    );
  });
}

/**
 * Does the text contain a reserved name once spacing, punctuation, invisible characters and lookalikes are folded?
 * "Share" and "Secret Manager" count only as whole words.
 */
export function containsReservedName(text: string): boolean {
  const folded = skeleton(text);
  return (
    SUBSTRING_SKELETONS.some((reserved) => folded.includes(reserved)) ||
    holdsWholeWord(words(text, false)) ||
    holdsWholeWord(words(text, true))
  );
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

// Marks people write for a dot so that a host name does not look like one.
const DOT_LOOKALIKES = /[\u00b7\u0387\u2024\u2027\u2e31\u30fb\u0701]/gu;
const BRACKETED_DOT = /\s*[[({]\s*(?:\.|dot)\s*[\])}]\s*/giu;
const SPACED_DOT = /\s+\.\s+|\s+\.(?=\p{L})|\s+dot\s+/giu;

/** The text with the ways of writing a dot that is not a plain full stop folded into one. */
function withPlainDots(text: string): string {
  return text.replace(DOT_LOOKALIKES, '.').replace(BRACKETED_DOT, '.').replace(SPACED_DOT, '.');
}

/** Does the text hold something that reads as a host name other than the verified origin's own? */
function namesAnotherHost(text: string, origin: string): boolean {
  const own = originHosts(origin);
  const found = withPlainDots(text).match(HOST_LIKE) ?? [];
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

/** An own field of the app's presentation, whatever it holds. */
function fieldOf(source: object, name: string): unknown {
  return Object.hasOwn(source, name) ? Reflect.get(source, name) : undefined;
}

/**
 * What of the app's presentation may be shown under the verified `origin`, or `null` when nothing may.
 *
 * - A name or "on behalf of" that mixes scripts is dropped.
 * - A name, "on behalf of" or reason that reads as another host than the origin's is dropped.
 * - A name, "on behalf of" or reason that contains a reserved name is dropped unless the origin is a trusted shell.
 *   Nothing marks a drop: the screen shows what is left.
 * - The icon is shown only beside a name that is shown, and only as a small PNG, JPEG or WebP data URI.
 *
 * Every text is cleaned and cut to its limit. With no verified origin nothing is shown.
 */
export function claimedPresentation(input: { presentation: unknown; origin: string }): ClaimedPresentation | null {
  const { presentation, origin } = input;
  if (!origin || origin === '*' || origin === 'null') return null;
  if (typeof presentation !== 'object' || presentation === null || Array.isArray(presentation)) return null;
  if (fieldOf(presentation, 'protocolVersion') !== 1) return null;
  const trusted = Object.hasOwn(TRUSTED_SHELL_ORIGINS, origin);
  const shown = (text: string | null): string | null =>
    text === null || namesAnotherHost(text, origin) || (!trusted && containsReservedName(text)) ? null : text;
  const shownName = (text: string | null): string | null => (text !== null && mixesScripts(text) ? null : shown(text));

  let displayName = shownName(cleanText(fieldOf(presentation, 'displayName')));
  let onBehalfOf = shownName(cleanText(fieldOf(presentation, 'onBehalfOf')));
  let reason = shown(cleanText(fieldOf(presentation, 'reason')));

  const iconUrl = displayName === null ? null : validIcon(fieldOf(presentation, 'iconUrl'));
  displayName = displayName === null ? null : capText(displayName, CLAIM_LIMITS.displayName);
  onBehalfOf = onBehalfOf === null ? null : capText(onBehalfOf, CLAIM_LIMITS.onBehalfOf);
  reason = reason === null ? null : capText(reason, CLAIM_LIMITS.reason);

  if (displayName === null && onBehalfOf === null && reason === null) return null;
  return { displayName, iconUrl, onBehalfOf, reason };
}

// ---- the words on the screen ----------------------------------------------

/** The sign screen's lines for an app's own words; `{value}` is where the app's text goes. */
export const claimedPresentationCopy = {
  nameOnly: `It calls itself "{value}". OpenKey hasn't checked that name.`,
  name: `It calls itself "{value}".`,
  onBehalfOf: `It says it's asking for "{value}".`,
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
  const nameAlone = claimed.displayName !== null && claimed.onBehalfOf === null && claimed.reason === null;
  if (claimed.displayName !== null) {
    claims.push(line('name', nameAlone ? claimedPresentationCopy.nameOnly : claimedPresentationCopy.name, claimed.displayName));
  }
  if (claimed.onBehalfOf !== null) claims.push(line('onBehalfOf', claimedPresentationCopy.onBehalfOf, claimed.onBehalfOf));
  if (claimed.reason !== null) claims.push(line('reason', claimedPresentationCopy.reason, claimed.reason));
  return {
    claims,
    closing: nameAlone || claims.length === 0
      ? null
      : claims.length === 1 ? claimedPresentationCopy.closingOne : claimedPresentationCopy.closingMany,
    iconUrl: claimed.iconUrl,
  };
}
