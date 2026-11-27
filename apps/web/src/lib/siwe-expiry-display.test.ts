// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { siweExpirationTime } from '../../../../packages/capability-review/src/index';
import { parseSIWE } from './siwe-parser';

// TC-3826: the sign screens show the expiry the node enforces, never a fake
// `Expiration Time:` line hidden in the statement behind a line separator.
const FAKE = '2026-10-17T17:00:00.000Z';
const REAL = '2036-10-16T17:00:00.000Z';

function message(statementPrefix: string): string {
  return [
    'example.com wants you to sign in with your Ethereum account:',
    '0x71C7656EC7ab88b098defB751B7401B5f6d8976F',
    '',
    `${statementPrefix}Sign in to example.com.`,
    '',
    'URI: https://example.com',
    'Version: 1',
    'Chain ID: 1',
    'Nonce: abcdefgh12345678',
    'Issued At: 2026-10-16T17:00:00.000Z',
    `Expiration Time: ${REAL}`,
  ].join('\n');
}

describe('displayed SIWE expiry', () => {
  for (const [name, separator] of [['CR', '\r'], ['U+2028', '\u2028'], ['U+2029', '\u2029']] as const) {
    test(`a fake statement line behind ${name} shows no expiry`, () => {
      const attack = message(`Expiration Time: ${FAKE}${separator} `);
      expect(siweExpirationTime(attack)).toBeNull();
      const parsed = parseSIWE(attack);
      expect(parsed?.message.expirationTime).toBeUndefined();
      expect(parsed?.message.issuedAt).toBeUndefined();
    });
  }

  test('a normal message shows the signed field', () => {
    const normal = message(`Expiration Time: ${FAKE} `);
    expect(siweExpirationTime(normal)).toBe(REAL);
    const parsed = parseSIWE(normal);
    expect(parsed?.message.expirationTime).toBe(REAL);
    expect(parsed?.message.issuedAt).toBe('2026-10-16T17:00:00.000Z');
  });
});
