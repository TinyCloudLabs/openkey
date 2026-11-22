// TC-3826: OpenKey never signs a sign-in (SIWE) message carrying a control
// character other than `\n`, U+2028 or U+2029. JS regexes treat `\r`, U+2028
// and U+2029 as line breaks and the node does not, so such a message can show
// one expiry and enforce another. Other messages (plain text, raw bytes) are
// not SIWEs and keep their bytes.

import { hasForbiddenSiweCharacter } from '@openkey/capability-review';
import { decodeHexUtf8, isSiweShaped } from './siwe-origin';

export const INVALID_SIWE_MESSAGE_CODE = 'invalid_siwe_message';

export interface InvalidSiweMessageBody {
  error: string;
  code: typeof INVALID_SIWE_MESSAGE_CODE;
}

/**
 * The 400 body when `message`, as written or as the UTF-8 its `0x` hex
 * covers, is SIWE-shaped and carries a forbidden character; null otherwise.
 */
export function invalidSiweMessage(message: string): InvalidSiweMessageBody | null {
  const decoded = decodeHexUtf8(message);
  const forbidden = [message, decoded].some(
    (text) => text !== null && isSiweShaped(text) && hasForbiddenSiweCharacter(text),
  );
  return forbidden
    ? {
        error: 'The sign-in message contains a control character, U+2028 or U+2029. OpenKey does not sign it.',
        code: INVALID_SIWE_MESSAGE_CODE,
      }
    : null;
}
