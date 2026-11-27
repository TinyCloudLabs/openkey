// TC-3826: OpenKey never signs a sign-in (SIWE) message it cannot read the
// way the node does. JS regexes treat `\r`, U+2028 and U+2029 as line breaks
// and the node does not, so such a message can show one expiry and enforce
// another; any other message the node grammar refuses shows no expiry at all.
// Other messages (plain text, raw bytes) are not SIWEs and keep their bytes.

import { hasForbiddenSiweCharacter, parseSiweFields } from '@openkey/capability-review';
import { isSiweShaped } from './siwe-origin';

export const INVALID_SIWE_MESSAGE_CODE = 'invalid_siwe_message';

export interface InvalidSiweMessageBody {
  error: string;
  code: typeof INVALID_SIWE_MESSAGE_CODE;
}

/**
 * What a SIWE-shaped message must pass: `grammar` (the default) is the node's
 * whole grammar (`parseSiweFields`); `characters` is only the forbidden
 * characters, for routes whose own strict checks refuse the rest with their
 * established codes.
 */
export type SiweMessageRule = 'grammar' | 'characters';

/**
 * The text `0x` hex covers, a leading BOM kept. `utf8` is false when the bytes
 * are not UTF-8; the text is then the lossy (U+FFFD) decode, read only to see
 * whether the bytes hold a sign-in message. Null when `message` is not hex.
 */
function hexText(message: string): { text: string; utf8: boolean } | null {
  if (!/^0x(?:[0-9a-fA-F]{2})+$/.test(message)) return null;
  const bytes = Uint8Array.from(message.slice(2).match(/../g)!, (pair) => parseInt(pair, 16));
  try {
    return { text: new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes), utf8: true };
  } catch {
    return { text: new TextDecoder('utf-8', { ignoreBOM: true }).decode(bytes), utf8: false };
  }
}

/**
 * The 400 body when `message`, as written or as the text its `0x` hex covers,
 * is SIWE-shaped and fails `rule` (a SIWE in hex that is not UTF-8 always
 * fails); null otherwise. Hex that is not UTF-8 and holds no sign-in message is
 * binary data and keeps its bytes.
 */
export function invalidSiweMessage(message: string, rule: SiweMessageRule = 'grammar'): InvalidSiweMessageBody | null {
  const fails = (text: string) => hasForbiddenSiweCharacter(text) || (rule === 'grammar' && !parseSiweFields(text).ok);
  const hex = hexText(message);
  const refused = (isSiweShaped(message) && fails(message))
    || (hex !== null && isSiweShaped(hex.text) && (!hex.utf8 || fails(hex.text)));
  return refused
    ? {
        error: 'OpenKey cannot read this sign-in message the way the TinyCloud node does (it is not in the standard sign-in format, or it contains a control character, U+2028 or U+2029), so it will not sign it.',
        code: INVALID_SIWE_MESSAGE_CODE,
      }
    : null;
}

/** What the sign-route event records about a signed sign-in message: never its text. */
export interface SignedSiweFacts {
  expiry: boolean;
  recap: boolean;
}

/**
 * TC-3844: whether `message`, as written or as the UTF-8 its `0x` hex covers, is a sign-in message the node can read,
 * and if so whether it has an `Expiration Time` and a ReCap resource; null for any other message.
 */
export function signedSiweFacts(message: string): SignedSiweFacts | null {
  const hex = hexText(message);
  for (const text of [message, hex?.utf8 ? hex.text : null]) {
    if (text === null) continue;
    const parsed = parseSiweFields(text);
    if (parsed.ok) {
      return {
        expiry: parsed.fields.expirationTime !== undefined,
        recap: (parsed.fields.resources ?? []).some((resource) => resource.startsWith('urn:recap:')),
      };
    }
  }
  return null;
}
