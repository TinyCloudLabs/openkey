// The app a request with app keys comes from: its name and its app id, shown at
// the top of the consent view.
//
// The name is the manifest's `name`, app-supplied text: it is shown only when
// the manifest was fetched from the requesting origin and matched its digest,
// only after the rules below, and never without the app id beneath it. The app
// id is the verified manifest's `app_id`; before the manifest is verified it is
// read from the key resources of the request itself.

export const APP_NAME_MAX_LENGTH = 48;

const NOT_DISPLAYABLE = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Cs}]/u;
const LATIN = /\p{Script=Latin}/u;
const LOOKALIKE = /[\p{Script=Cyrillic}\p{Script=Greek}]/u;

/**
 * The text of an app name that is safe to show, or `null` when the name has to
 * be left out.
 *
 * - Not a string: `null`.
 * - Any control (tab and line breaks included), format (bidi overrides and
 *   isolates, zero-width and joiner characters, byte order mark, tags),
 *   private-use, unassigned or surrogate character: `null`.
 * - Runs of whitespace (the Unicode line and paragraph separators included)
 *   collapse to one space; empty after trimming: `null`.
 * - Latin letters together with Cyrillic or Greek letters: `null` (the usual
 *   look-alike mix).
 * - Longer than 48 characters: cut to 47 characters and an ellipsis.
 *
 * The result is rendered as plain text, in its own isolated direction.
 */
export function appDisplayName(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const normalized = raw.normalize("NFC");
  if (NOT_DISPLAYABLE.test(normalized)) return null;
  const text = normalized.replace(/\s+/gu, " ").trim();
  if (text === "") return null;
  if (LATIN.test(text) && LOOKALIKE.test(text)) return null;
  const characters = [...text];
  if (characters.length <= APP_NAME_MAX_LENGTH) return text;
  return `${characters.slice(0, APP_NAME_MAX_LENGTH - 1).join("").trimEnd()}…`;
}
