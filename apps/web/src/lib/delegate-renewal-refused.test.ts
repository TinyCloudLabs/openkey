// TC-3821: on /delegate (approval links and delegate-page sign-ins) the API's renewal refusal shows in the API's own
// words, inline where the renewal box is, never as the catch-all "Couldn't approve this request. Try again.": asking
// again with the same choice is always refused.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { stopForReply } from '@openkey/sdk/approval-copy';
import { delegateServerMessage } from './delegate-failure-text';

const R1A = 'Renewing access to your secrets or encrypted data needs your confirmation. Confirm "Renew sensitive access?" to keep renewal, or untick renewal and approve without it.';

describe('a renewal refusal on /delegate', () => {
  test("the reply's own words are read from its error", () => {
    expect(delegateServerMessage({ code: 'renewal_refused', error: R1A })).toBe(R1A);
    // Other replies still offer only their `message`.
    expect(delegateServerMessage({ code: 'renewal_failed', error: 'internal words' })).toBeUndefined();
  });

  test('shows inline as those words, with the status and code below; never the catch-all', () => {
    for (const editable of [false, true]) {
      const stop = stopForReply({ status: 400, code: 'renewal_refused', detail: R1A, renewalChangeable: editable, permissionsEditable: editable, expiryChangeable: editable });
      expect(stop).toMatchObject({ id: 'renewalRefused', placement: 'inline', title: '', body: R1A, support: 'HTTP 400 · renewal_refused', buttons: [] });
      expect(stop.detail).toBeUndefined();
    }
  });

  test('without words from the reply it still says what to do', () => {
    expect(stopForReply({ status: 400, code: 'renewal_refused' }).body)
      .toBe('Renewal can’t be set up for this approval. Untick renewal and approve without it.');
  });
});
