// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { describe, expect, test } from 'bun:test';
import { shouldShowLoopbackHint, type LoopbackHintState } from './delegate-signing-hint';

const loopbackInFlight: LoopbackHintState = {
  delegating: true,
  approvedCallback: 'http://127.0.0.1:52000/callback',
  deviceTransactionId: '',
  callbackInFlight: true,
  pasteCode: '',
};

describe('shouldShowLoopbackHint', () => {
  test('shown while the loopback callback to the CLI is in flight', () => {
    expect(shouldShowLoopbackHint(loopbackInFlight)).toBe(true);
  });

  test('hidden before the callback phase (pre-callback signing steps)', () => {
    expect(shouldShowLoopbackHint({ ...loopbackInFlight, callbackInFlight: false })).toBe(false);
  });

  test('hidden when not delegating (idle consent screen)', () => {
    expect(shouldShowLoopbackHint({ ...loopbackInFlight, delegating: false, callbackInFlight: false })).toBe(false);
  });

  test('hidden on the device-authorization flow', () => {
    expect(shouldShowLoopbackHint({ ...loopbackInFlight, deviceTransactionId: 'txn-1' })).toBe(false);
  });

  test('hidden when the CLI sent no loopback callback (paste-code flow)', () => {
    expect(shouldShowLoopbackHint({ ...loopbackInFlight, approvedCallback: null })).toBe(false);
  });

  test('hidden once the callback failed and the paste code is shown', () => {
    expect(
      shouldShowLoopbackHint({ ...loopbackInFlight, callbackInFlight: false, pasteCode: 'delegation-paste-code' }),
    ).toBe(false);
  });
});
