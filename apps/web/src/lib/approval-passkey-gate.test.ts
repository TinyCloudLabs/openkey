// What an Approve tap does about the passkey offer a screen fetches: send only with the offer for the input in front
// of the owner, wait while the fetch is in flight, fetch again otherwise.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { approvalPasskeyGate, type ApprovalPasskeyNeed } from './approval-passkey';

const REQUIRED: ApprovalPasskeyNeed = {
  required: true,
  challengeToken: 'challenge-1',
  options: { challenge: 'abc' } as never,
};
const NOT_REQUIRED: ApprovalPasskeyNeed = { required: false };

describe('approvalPasskeyGate', () => {
  test('waits for an offer that is still being fetched', () => {
    expect(approvalPasskeyGate({ input: 'a', held: null, fetch: 'pending' })).toEqual({ action: 'wait' });
  });

  test('keeps waiting when the held offer was fetched for other input', () => {
    expect(approvalPasskeyGate({ input: 'b', held: { input: 'a', need: REQUIRED }, fetch: 'pending' })).toEqual({ action: 'wait' });
  });

  test('fetches again after a failed fetch and sends nothing', () => {
    expect(approvalPasskeyGate({ input: 'a', held: null, fetch: 'failed' })).toEqual({ action: 'retry' });
  });

  test('fetches again when nothing was started and no offer is held', () => {
    expect(approvalPasskeyGate({ input: 'a', held: null, fetch: 'idle' })).toEqual({ action: 'retry' });
  });

  test('never sends on an offer fetched for other input', () => {
    expect(approvalPasskeyGate({ input: 'b', held: { input: 'a', need: REQUIRED }, fetch: 'idle' })).toEqual({ action: 'retry' });
    expect(approvalPasskeyGate({ input: 'b', held: { input: 'a', need: NOT_REQUIRED }, fetch: 'failed' })).toEqual({ action: 'retry' });
  });

  test('sends with the offer that landed for the current input', () => {
    expect(approvalPasskeyGate({ input: 'a', held: { input: 'a', need: REQUIRED }, fetch: 'idle' })).toEqual({ action: 'send', need: REQUIRED });
  });

  test('sends without an assertion when the offer says none is needed', () => {
    expect(approvalPasskeyGate({ input: 'a', held: { input: 'a', need: NOT_REQUIRED }, fetch: 'idle' })).toEqual({ action: 'send', need: NOT_REQUIRED });
  });

  test('a landed offer for the current input wins over a refetch in flight', () => {
    expect(approvalPasskeyGate({ input: 'a', held: { input: 'a', need: REQUIRED }, fetch: 'pending' })).toEqual({ action: 'send', need: REQUIRED });
  });

  test('a screen that fetches no offer sends without one', () => {
    expect(approvalPasskeyGate({ input: null, held: null, fetch: 'idle' })).toEqual({ action: 'send', need: null });
  });
});
