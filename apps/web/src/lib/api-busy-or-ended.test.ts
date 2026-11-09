// The owner wording is chosen by HTTP status alone: any 409 means an approval
// is already in flight, any 410 on a sign path means the request already
// ended, and every other status keeps the server's own message.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { apiBusyOrEndedMessage } from './api-busy-or-ended';

describe('apiBusyOrEndedMessage', () => {
  test('any 409 means the request is already being approved', () => {
    expect(apiBusyOrEndedMessage(409)).toBe('This request is already being approved. Wait a moment.');
  });

  test('a 410 on a sign path means the request was answered or ended', () => {
    expect(apiBusyOrEndedMessage(410)).toBe('This request has already been answered or has ended.');
  });

  test('every other status keeps the server text', () => {
    for (const status of [400, 401, 403, 404, 429, 500, 503]) {
      expect(apiBusyOrEndedMessage(status)).toBeNull();
    }
  });
});
