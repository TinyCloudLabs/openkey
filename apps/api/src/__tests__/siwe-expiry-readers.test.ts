import { describe, expect, test } from 'bun:test';
import { withExpirationTime } from '../services/approval-expiry';
import { invalidSiweMessage } from '../services/siwe-message-refusal';
import { parseTinyCloudSiwe } from '../services/tinycloud-siwe';

// TC-3826: the API reads a SIWE's times the way the node does.
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
const hex = (text: string) => `0x${Buffer.from(text, 'utf8').toString('hex')}`;

describe('SIWE expiry readers', () => {
  for (const [name, separator] of [['CR', '\r'], ['U+2028', '\u2028'], ['U+2029', '\u2029']] as const) {
    test(`a fake statement line behind ${name} is refused and never read`, () => {
      const attack = message(`Expiration Time: ${FAKE}${separator} `);
      expect(invalidSiweMessage(attack)?.code).toBe('invalid_siwe_message');
      expect(invalidSiweMessage(hex(attack))?.code).toBe('invalid_siwe_message');
      expect(withExpirationTime(attack, '2030-01-01T00:00:00.000Z')).toBeNull();
      expect(parseTinyCloudSiwe(attack)?.expirationTime).toBeUndefined();
    });
  }

  test('a non-SIWE with an Expiration Time line has no expiry and keeps its bytes', () => {
    const text = `Expiration Time: ${FAKE}`;
    expect(withExpirationTime(text, '2030-01-01T00:00:00.000Z')).toBeNull();
    expect(parseTinyCloudSiwe(text)).toBeNull();
    expect(invalidSiweMessage(`${text}\r\nhello`)).toBeNull();
    expect(invalidSiweMessage(hex(`${text}\r\nhello`))).toBeNull();
  });

  test('a normal message keeps its signed expiry', () => {
    const normal = message(`Expiration Time: ${FAKE} `);
    expect(invalidSiweMessage(normal)).toBeNull();
    expect(withExpirationTime(normal, '2030-01-01T00:00:00.000Z')).toBe(normal.replace(REAL, '2030-01-01T00:00:00.000Z'));
  });
});
