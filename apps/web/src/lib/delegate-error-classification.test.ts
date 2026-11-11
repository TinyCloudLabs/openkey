// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { classifyDelegateError, type DelegateErrorClassification } from './delegate-error-classification';

describe('classifyDelegateError', () => {
  const cases = [
    [409, undefined, false, 'busy'], [409, 'expired_request', false, 'busy'], [409, 'expired_token', false, 'busy'], [409, 'context-expired', false, 'busy'], [409, 'context-not-found', false, 'busy'],
    [409, undefined, true, 'busy'], [409, 'expired_request', true, 'busy'], [409, 'expired_token', true, 'busy'], [409, 'context-expired', true, 'busy'], [409, 'context-not-found', true, 'busy'],
    [410, undefined, false, 'ended'], [410, 'expired_request', false, 'ended'], [410, 'expired_token', false, 'ended'], [410, 'context-expired', false, 'ended'], [410, 'context-not-found', false, 'ended'],
    [410, undefined, true, 'ended'], [410, 'expired_request', true, 'ended'], [410, 'expired_token', true, 'ended'], [410, 'context-expired', true, 'ended'], [410, 'context-not-found', true, 'ended'],
    [400, undefined, false, 'error'], [400, 'expired_request', false, 'error'], [400, 'expired_token', false, 'error'], [400, 'context-expired', false, 'refresh-once'], [400, 'context-not-found', false, 'refresh-once'],
    [400, undefined, true, 'error'], [400, 'expired_request', true, 'error'], [400, 'expired_token', true, 'error'], [400, 'context-expired', true, 'panel-after-failed-refresh'], [400, 'context-not-found', true, 'panel-after-failed-refresh'],
    [500, undefined, false, 'error'], [500, 'expired_request', false, 'error'], [500, 'expired_token', false, 'error'], [500, 'context-expired', false, 'refresh-once'], [500, 'context-not-found', false, 'refresh-once'],
    [500, undefined, true, 'error'], [500, 'expired_request', true, 'error'], [500, 'expired_token', true, 'error'], [500, 'context-expired', true, 'panel-after-failed-refresh'], [500, 'context-not-found', true, 'panel-after-failed-refresh'],
  ] as const satisfies ReadonlyArray<readonly [number, string | undefined, boolean, DelegateErrorClassification]>;

  test('status wins before code and exhausted refresh restores the panel path', () => {
    for (const [status, code, refreshAttempted, expected] of cases) {
      expect(classifyDelegateError(status, code, refreshAttempted)).toBe(expected);
    }
  });
});
