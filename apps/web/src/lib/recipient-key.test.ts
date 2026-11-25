// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { shortRecipientKey } from './recipient-key';

describe('the short form of the key an approval request\'s access goes to', () => {
  test('is the first 6 and last 4 characters of the id, without the did:key prefix', () => {
    expect(shortRecipientKey('did:key:z6Mkm7pWmPt7DDUanxuPcqVpxjfQwbL4z5FYNJQc7UG85YbU')).toBe('z6Mkm7…5YbU');
    expect(shortRecipientKey('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK')).toBe('z6Mkha…2doK');
  });

  test('leaves a fragment off and shows a short id whole', () => {
    expect(shortRecipientKey('did:key:z6Mkm7pWmPt7DDUanxuPcqVpxjfQwbL4z5FYNJQc7UG85YbU#z6Mkm7pWmPt7')).toBe('z6Mkm7…5YbU');
    expect(shortRecipientKey('did:key:abcdefghij')).toBe('abcdefghij');
    expect(shortRecipientKey('0123456789abcdef')).toBe('012345…cdef');
  });
});
