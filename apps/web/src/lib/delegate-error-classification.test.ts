// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { classifyDelegateError, type DelegateErrorClassification } from './delegate-error-classification';
describe('classifyDelegateError', () => {
  const cases = [
    [409, undefined, 'busy'], [409, 'expired_request', 'busy'], [409, 'expired_token', 'busy'], [409, 'context-expired', 'busy'], [409, 'context-not-found', 'busy'],
    [410, undefined, 'ended'], [410, 'expired_request', 'ended'], [410, 'expired_token', 'ended'], [410, 'context-expired', 'ended'], [410, 'context-not-found', 'ended'],
    [400, undefined, 'error'], [400, 'expired_request', 'error'], [400, 'expired_token', 'error'], [400, 'context-expired', 'refresh-once'], [400, 'context-not-found', 'refresh-once'],
    [500, undefined, 'error'], [500, 'expired_request', 'error'], [500, 'expired_token', 'error'], [500, 'context-expired', 'refresh-once'], [500, 'context-not-found', 'refresh-once'],
  ] as const satisfies ReadonlyArray<readonly [number, string | undefined, DelegateErrorClassification]>;

  test('status wins before code and context codes preserve refresh-once elsewhere', () => {
    for (const [status, code, expected] of cases) {
      expect(classifyDelegateError(status, code)).toBe(expected);
    }
  });
});
