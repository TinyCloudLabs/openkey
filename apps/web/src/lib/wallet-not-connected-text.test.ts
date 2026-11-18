// @ts-expect-error bun:test is provided by the Bun runtime
import { describe, expect, test } from 'bun:test';
import { walletNotConnectedText } from './wallet-not-connected-text';

describe('walletNotConnectedText', () => {
  test('names the signed-in account', () => {
    expect(walletNotConnectedText('0x1234…abcd', 'a@b.co')).toBe(
      "This request is for wallet 0x1234…abcd. You're signed in as a@b.co, and none of your keys is that wallet. Sign in with the account that owns it, or link that wallet below.",
    );
  });

  test('works without an email', () => {
    expect(walletNotConnectedText('0x1234…abcd', null)).toBe(
      'This request is for wallet 0x1234…abcd. None of your keys is that wallet. Sign in with the account that owns it, or link that wallet below.',
    );
  });

  test('shows a long email whole', () => {
    const email = `${'long.local.part'.repeat(6)}@very-long-domain-name.example.com`;
    expect(walletNotConnectedText('0x1…2', email)).toContain(`signed in as ${email},`);
  });
});
