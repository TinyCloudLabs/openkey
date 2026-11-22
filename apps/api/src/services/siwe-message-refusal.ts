// TC-3826: OpenKey never signs a sign-in (SIWE) message it cannot read the
// way the node does. JS regexes treat `\r`, U+2028 and U+2029 as line breaks
// and the node does not, so such a message can show one expiry and enforce
// another; any other message the node grammar refuses shows no expiry at all.
// Other messages (plain text, raw bytes) are not SIWEs and keep their bytes.

import { hasForbiddenSiweCharacter, parseSiweFields } from '@openkey/capability-review';
import { decodeHexUtf8, isSiweShaped } from './siwe-origin';

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
 * The 400 body when `message`, as written or as the UTF-8 its `0x` hex
 * covers, is SIWE-shaped and fails `rule`; null otherwise.
 */
export function invalidSiweMessage(message: string, rule: SiweMessageRule = 'grammar'): InvalidSiweMessageBody | null {
  const decoded = decodeHexUtf8(message);
  const refused = [message, decoded].some(
    (text) => text !== null && isSiweShaped(text)
      && (hasForbiddenSiweCharacter(text) || (rule === 'grammar' && !parseSiweFields(text).ok)),
  );
  return refused
    ? {
        error: 'OpenKey cannot read this sign-in message the way the TinyCloud node does (it is not in the standard sign-in format, or it contains a control character, U+2028 or U+2029), so it will not sign it.',
        code: INVALID_SIWE_MESSAGE_CODE,
      }
    : null;
}
