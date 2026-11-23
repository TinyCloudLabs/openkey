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

function deps(overrides: Partial<AutofillDeps> = {}) {
  const log = { signedIn: 0, cancelled: 0, signInCalls: 0 };
  const value: AutofillDeps = {
    supported: async () => true,
    signIn: async () => {
      log.signInCalls++;
      return { error: null };
    },
    cancel: () => { log.cancelled++; },
    onSignedIn: () => { log.signedIn++; },
    retryEveryMs: 5,
    boundMs: 500,
    ...overrides,
  };
  return { log, value };
}

/** An autofill request whose server verification is in flight until `finish` is called. */
function verifying(overrides: Partial<AutofillDeps> = {}) {
  const gate = Promise.withResolvers<Result>();
  const { log, value } = deps({ signIn: ({ onVerify }) => { onVerify(); return gate.promise; }, ...overrides });
  return { log, value, finish: (result: Result) => gate.resolve(result) };
}

describe('a passkey click while the autofill sign-in is being verified', () => {
  test('adopts that sign-in: onSignedIn fires once and the click runs no ceremony', async () => {
    const request = verifying();
    startPasskeyAutofill(request.value);
    await tick();
    let ceremonies = 0;
    const click = ceremonyAfterAutofill(async () => { ceremonies++; return { error: null }; });
    await tick(20);
    request.finish({ error: null });
    expect(await click).toEqual({ adopted: true });
    expect(ceremonies).toBe(0);
    expect(request.log.signedIn).toBe(1);
    expect(request.log.cancelled).toBe(0);
  });

  test('a verification that fails is not adopted: the click runs its own ceremony and onSignedIn never fires', async () => {
    const request = verifying();
    startPasskeyAutofill(request.value);
    await tick();
    let ceremonies = 0;
    const click = ceremonyAfterAutofill(async () => { ceremonies++; return { error: null }; });
    request.finish({ error: { code: 'FAILED_TO_VERIFY_AUTHENTICATION' } });
    expect(await click).toEqual({ adopted: false, result: { error: null } });
    expect(ceremonies).toBe(1);
    expect(request.log.signedIn).toBe(0);
  });

  test('a verification that outlasts the bound is not adopted late: the click signs in once', async () => {
    const request = verifying({ boundMs: 30 });
    startPasskeyAutofill(request.value);
    await tick();
    let ceremonies = 0;
    const outcome = await ceremonyAfterAutofill(async () => { ceremonies++; return { error: null }; });
    expect(outcome).toEqual({ adopted: false, result: { error: null } });
    request.finish({ error: null });
    await tick(20);
    expect(ceremonies).toBe(1);
    expect(request.log.signedIn).toBe(0);
  });
});

describe('a passkey click before the autofill verification starts', () => {
  test('cancels the autofill ceremony and runs its own once', async () => {
    const gate = Promise.withResolvers<Result>();
    const { log, value } = deps({ signIn: () => gate.promise });
    startPasskeyAutofill(value);
    await tick();
    let ceremonies = 0;
    const click = ceremonyAfterAutofill(async () => { ceremonies++; return { error: null }; });
    await tick(20);
    expect(ceremonies).toBe(0);
    expect(log.cancelled).toBeGreaterThanOrEqual(1);
    gate.resolve({ error: { code: 'ERROR_CEREMONY_ABORTED' } });
    expect(await click).toEqual({ adopted: false, result: { error: null } });
    expect(ceremonies).toBe(1);
    expect(log.signedIn).toBe(0);
  });

  test('a verification that starts after the stop ends the cancelling and is not adopted', async () => {
    const gate = Promise.withResolvers<Result>();
    let onVerify!: () => void;
    const { log, value } = deps({ signIn: (hooks) => { onVerify = hooks.onVerify; return gate.promise; } });
    const autofill = startPasskeyAutofill(value);
    await tick();
    const stopped = autofill.stop();
    await tick(20);
    expect(log.cancelled).toBeGreaterThan(1);
    onVerify();
    const atVerify = log.cancelled;
    await tick(30);
    expect(log.cancelled).toBe(atVerify);
    gate.resolve({ error: null });
    expect(await stopped).toBe(false);
    expect(log.signedIn).toBe(0);
  });

  test('with no autofill running the click runs its own ceremony', async () => {
    let ceremonies = 0;
    const outcome = await ceremonyAfterAutofill(async () => { ceremonies++; return 'done'; });
    expect(outcome).toEqual({ adopted: false, result: 'done' });
    expect(ceremonies).toBe(1);
  });
});

describe('an autofill request that replaces one with a sign-in in flight', () => {
  test('does not start: the older request reported the sign-in', async () => {
    const older = verifying();
    startPasskeyAutofill(older.value);
    await tick();
    const newer = deps();
    startPasskeyAutofill(newer.value);
    await tick(20);
    older.finish({ error: null });
    await tick(20);
    expect(older.log.signedIn).toBe(1);
    expect(newer.log.signInCalls).toBe(0);
    expect(newer.log.signedIn).toBe(0);
    expect(await supersedePasskeyAutofill()).toBe(false);
  });
});
