// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { shortRecipientKey } from './recipient-key';

describe('the short form of the key an approval request\'s access goes to', () => {
  test('leaves off did:key: and the z6Mk every Ed25519 key starts with, then shows 6 characters, an ellipsis and the last 4', () => {
    expect(shortRecipientKey('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK')).toBe('haXgBZ…2doK');
    expect(shortRecipientKey('did:key:z6Mkm7pWmPt7DDUanxuPcqVpxjfQwbL4z5FYNJQc7UG85YbU')).toBe('m7pWmP…5YbU');
  });

  test('leaves a fragment off', () => {
    expect(shortRecipientKey('did:key:z6Mkm7pWmPt7DDUanxuPcqVpxjfQwbL4z5FYNJQc7UG85YbU#z6Mkm7pWmPt7')).toBe('m7pWmP…5YbU');
  });

  test('shows what is left of the id whole when it is 10 characters or fewer', () => {
    expect(shortRecipientKey('did:key:z6Mk' + 'ab'.repeat(5))).toBe('ab'.repeat(5));
    expect(shortRecipientKey('did:key:z6Mk' + 'ab'.repeat(5) + 'c')).toBe('ababab…babc');
    expect(shortRecipientKey('did:key:z6Mk')).toBe('');
  });

  test('keeps the first 6 and last 4 of an id that does not start with z6Mk', () => {
    expect(shortRecipientKey('did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme')).toBe('zQ3sho…YBme');
    expect(shortRecipientKey('0123456789abcdef')).toBe('012345…cdef');
    expect(shortRecipientKey('did:key:abcdefghij')).toBe('abcdefghij');
  });
});
