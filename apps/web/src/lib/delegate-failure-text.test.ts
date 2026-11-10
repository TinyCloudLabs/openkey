// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { apiBusyOrEndedMessage } from './api-busy-or-ended';
import { delegateFailureText, shortCodeFailureText } from './delegate-failure-text';

describe('delegateFailureText', () => {
  test('includes a safe server code and status', () => {
    expect(delegateFailureText({ status: 503, code: 'some_code' })).toBe('Delegation failed (503 · some_code). Try again.');
  });

  test('includes the status when no safe server code exists', () => {
    expect(delegateFailureText({ status: 500, code: undefined })).toBe('Delegation failed (500). Try again.');
  });

  test.each([
    ['free text', 'server said retry now'],
    ['a long string', 'a'.repeat(65)],
    ['an object', { code: 'nested' }],
    ['a number', 7],
    ['an empty string', ''],
  ] as Array<[string, unknown]>)('treats %s as no code', (_label: string, code: unknown) => {
    expect(delegateFailureText({ status: 500, code })).toBe('Delegation failed (500). Try again.');
  });

  test('keeps busy and ended mappings ahead of the fallback', () => {
    expect(delegateFailureText({ status: 409, code: 'busy_code' })).toBe(apiBusyOrEndedMessage(409));
    expect(delegateFailureText({ status: 410, code: 'ended_code' })).toBe(apiBusyOrEndedMessage(410));
  });

  test('keeps a plain Error message', () => {
    expect(delegateFailureText(new Error('wallet failed'))).toBe('wallet failed');
  });
});

describe('shortCodeFailureText', () => {
  test('includes a safe code and status', () => {
    expect(shortCodeFailureText(503, 'some_code')).toBe('Short code unavailable (503 · some_code). Use the full delegation code instead.');
  });

  test('includes the status without an unsafe code', () => {
    expect(shortCodeFailureText(500, { code: 'nested' })).toBe('Short code unavailable (500). Use the full delegation code instead.');
  });

  test('keeps the no-status sentence unchanged', () => {
    expect(shortCodeFailureText()).toBe('Short code unavailable. Use the full delegation code instead.');
  });
});
