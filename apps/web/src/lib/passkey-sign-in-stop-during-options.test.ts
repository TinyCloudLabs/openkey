// A passkey click that lands while the autofill request is still fetching its options. The stop cannot abort a ceremony
// that has not started; when the options return, a fast authenticator answers the conditional ceremony before the
// next cancel, and the server verification starts. That verification is the sign-in: the click does not run a second one.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  ceremonyAfterAutofill,
  startPasskeyAutofill,
  supersedePasskeyAutofill,
  type AutofillDeps,
} from './passkey-sign-in';

const tick = (ms = 0) => new Promise((resolve) => setTimeout(resolve, ms));

type Result = { error?: unknown } | null | undefined;

/** An autofill request still fetching its options: `verify` starts the server verification, `finish` settles the request. */
function fetchingOptions(overrides: Partial<AutofillDeps> = {}) {
  const log = { signedIn: 0, cancelled: 0, signInCalls: 0 };
  const gate = Promise.withResolvers<Result>();
  let startVerify!: () => void;
  const value: AutofillDeps = {
    supported: async () => true,
    signIn: (hooks) => {
      log.signInCalls++;
      startVerify = hooks.onVerify;
      return gate.promise;
    },
    cancel: () => { log.cancelled++; },
    onSignedIn: () => { log.signedIn++; },
    retryEveryMs: 5,
    boundMs: 500,
    ...overrides,
  };
  return { log, value, verify: () => startVerify(), finish: (result: Result) => gate.resolve(result) };
}

describe('a stop that arrives before the verification starts, when the verification then starts', () => {
  test('is adopted: onSignedIn fires once, the cancelling ends and stop resolves true', async () => {
    const request = fetchingOptions();
    const autofill = startPasskeyAutofill(request.value);
    await tick();
    const stopped = autofill.stop();
    await tick(20);
    expect(request.log.cancelled).toBeGreaterThan(1);

    request.verify();
    const atVerify = request.log.cancelled;
    await tick(30);
    expect(request.log.cancelled).toBe(atVerify);
    expect(request.log.signedIn).toBe(0);

    request.finish({ error: null });
    expect(await stopped).toBe(true);
    expect(request.log.signedIn).toBe(1);
  });

  test('is not adopted when the verification fails', async () => {
    const request = fetchingOptions();
    const autofill = startPasskeyAutofill(request.value);
    await tick();
    const stopped = autofill.stop();
    request.verify();
    request.finish({ error: { code: 'FAILED_TO_VERIFY_AUTHENTICATION' } });
    expect(await stopped).toBe(false);
    expect(request.log.signedIn).toBe(0);
  });

  test('is not adopted when it outlasts the bound', async () => {
    const request = fetchingOptions({ boundMs: 30 });
    const autofill = startPasskeyAutofill(request.value);
    await tick();
    const stopped = autofill.stop();
    await tick(60);
    expect(await stopped).toBe(false);
    request.verify();
    request.finish({ error: null });
    await tick(20);
    expect(request.log.signedIn).toBe(0);
  });

  test('is not adopted when it never starts: the cancel aborts the ceremony', async () => {
    const request = fetchingOptions();
    const autofill = startPasskeyAutofill(request.value);
    await tick();
    const stopped = autofill.stop();
    request.finish({ error: { code: 'ERROR_CEREMONY_ABORTED' } });
    expect(await stopped).toBe(false);
    expect(request.log.signedIn).toBe(0);
  });
});

describe('a passkey click that lands while the autofill request fetches its options', () => {
  test('runs no ceremony of its own when the verification starts and succeeds', async () => {
    const request = fetchingOptions();
    startPasskeyAutofill(request.value);
    await tick();
    let ceremonies = 0;
    const click = ceremonyAfterAutofill(async () => { ceremonies++; return { error: null }; });
    await tick(20);
    request.verify();
    request.finish({ error: null });
    expect(await click).toEqual({ adopted: true });
    expect(ceremonies).toBe(0);
    expect(request.log.signedIn).toBe(1);
    expect(await supersedePasskeyAutofill()).toBe(false);
  });

  test('runs its own ceremony once when the cancel aborts the autofill ceremony', async () => {
    const request = fetchingOptions();
    startPasskeyAutofill(request.value);
    await tick();
    let ceremonies = 0;
    const click = ceremonyAfterAutofill(async () => { ceremonies++; return { error: null }; });
    await tick(20);
    request.finish({ error: { code: 'ERROR_CEREMONY_ABORTED' } });
    expect(await click).toEqual({ adopted: false, result: { error: null } });
    expect(ceremonies).toBe(1);
    expect(request.log.signedIn).toBe(0);
  });
});
