import { describe, expect, test } from 'bun:test';
import { invalidSiweMessage } from '../services/siwe-message-refusal';

// TC-3826: the raw /sign refusal covers every shape the node could take as a
// SIWE. The node needs the exact header line `<domain> wants you to sign in
// with your Ethereum account:`; the check looks for that header anywhere, in
// any case and with any whitespace between its words, or for a `URI:` line plus
// a `Nonce:` line, so it catches a superset of what the node accepts.
const ADDRESS = '0x71C7656EC7ab88b098defB751B7401B5f6d8976F';
const FAKE = '2026-10-17T17:00:00.000Z';

function lines(statement: string): string[] {
  return [
    'example.com wants you to sign in with your Ethereum account:',
    ADDRESS,
    '',
    statement,
    '',
    'URI: https://example.com',
    'Version: 1',
    'Chain ID: 1',
    'Nonce: abcdefgh12345678',
    'Issued At: 2026-10-16T17:00:00.000Z',
    'Expiration Time: 2036-10-16T17:00:00.000Z',
  ];
}
const hex = (text: string) => `0x${Buffer.from(text, 'utf8').toString('hex')}`;

const SEPARATORS = [['CR', '\r'], ['U+2028', '\u2028'], ['U+2029', '\u2029']] as const;

function shapes(separator: string): Array<[string, string]> {
  const statement = `Expiration Time: ${FAKE}${separator} Sign in.`;
  const canonical = lines(statement).join('\n');
  const shaped: Array<[string, string]> = [
    ['canonical', canonical],
    ['\\r\\n between every line', lines(statement).join('\r\n')],
    ['\\r between every line', lines(statement).join('\r')],
    ['leading junk', `junk before\n${canonical}`],
    ['leading BOM', `\ufeff${canonical}`],
    ['trailing junk', `${canonical}\ntrailing junk`],
    ['trailing \\n', `${canonical}\n`],
    ['header in upper case', canonical.replace('wants you to sign in with your Ethereum account:', 'WANTS YOU TO SIGN IN WITH YOUR ETHEREUM ACCOUNT:')],
    ['header words split by \\r', canonical.replace('wants you to sign in', 'wants\ryou\rto\rsign\rin')],
    ['no header, URI and Nonce lines', lines(statement).slice(2).join('\n')],
    ['a NUL in the statement', lines(`Sign\u0000in ${separator}`).join('\n')],
  ];
  return [
    ...shaped,
    ...shaped.map(([name, text]): [string, string] => [`${name}, as 0x hex`, hex(text)]),
    ...shaped.map(([name, text]): [string, string] => [`${name}, as upper-case 0x hex`, `0x${hex(text).slice(2).toUpperCase()}`]),
    ['canonical with an invalid UTF-8 byte, as 0x hex', `${hex(canonical.slice(0, 80))}ff${hex(canonical.slice(80)).slice(2)}`],
  ];
}

describe('raw /sign refuses every SIWE shape with a forbidden character', () => {
  for (const [name, separator] of SEPARATORS) {
    for (const [shape, message] of shapes(separator)) {
      test(`${name}: ${shape}`, () => {
        expect(invalidSiweMessage(message)?.code).toBe('invalid_siwe_message');
      });
    }
  }

  test('every C0 control but \\n, and DEL, is refused in a SIWE', () => {
    for (let code = 0; code <= 0x1f; code++) {
      if (code === 0x0a) continue;
      expect(invalidSiweMessage(lines(`Sign in${String.fromCharCode(code)}.`).join('\n'))?.code).toBe('invalid_siwe_message');
    }
    expect(invalidSiweMessage(lines('Sign in\u007f.').join('\n'))?.code).toBe('invalid_siwe_message');
  });

  test('a SIWE without one, and text that is not a SIWE, are not refused', () => {
    expect(invalidSiweMessage(lines(`Expiration Time: ${FAKE} Sign in.`).join('\n'))).toBeNull();
    expect(invalidSiweMessage(hex(lines('Sign in.').join('\n')))).toBeNull();
    for (const text of ['hello\r\nworld', `Expiration Time: ${FAKE}\r\nhello`, 'tab\there\u2028and\u2029there']) {
      expect(invalidSiweMessage(text)).toBeNull();
      expect(invalidSiweMessage(hex(text))).toBeNull();
    }
  });
});
