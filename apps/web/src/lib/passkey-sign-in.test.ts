// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { PASSKEY_FALLBACK_COPY } from './passkey-fallback-copy';
import {
  accountHasNoPasskeys,
  enrolmentDecision,
  isCeremonyAborted,
  isNoPasskeyError,
  startPasskeyAutofill,
  supersedePasskeyAutofill,
  type AutofillDeps,
} from './passkey-sign-in';

const tick = (ms = 0) => new Promise((resolve) => setTimeout(resolve, ms));

describe('isNoPasskeyError', () => {
  test('recognises the client error better-auth returns for a NotAllowedError', () => {
    expect(isNoPasskeyError({ code: 'ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY', message: 'auth cancelled', status: 400 })).toBe(true);
  });

  test('recognises a thrown NotAllowedError', () => {
    const thrown = new Error('The operation either timed out or was not allowed.');
    thrown.name = 'NotAllowedError';
    expect(isNoPasskeyError(thrown)).toBe(true);
  });

  test('leaves every other failure as a failure', () => {
    expect(isNoPasskeyError({ code: 'AUTH_CANCELLED' })).toBe(false);
    expect(isNoPasskeyError({ code: 'ERROR_CEREMONY_ABORTED' })).toBe(false);
    expect(isNoPasskeyError({ code: 'ERROR_INVALID_RP_ID' })).toBe(false);
    expect(isNoPasskeyError({ status: 401, message: 'Passkey not found' })).toBe(false);
    expect(isNoPasskeyError(new Error('network'))).toBe(false);
    expect(isNoPasskeyError(null)).toBe(false);
    expect(isNoPasskeyError(undefined)).toBe(false);
    expect(isNoPasskeyError('NotAllowedError')).toBe(false);
  });
});

describe('isCeremonyAborted', () => {
  test('recognises the abort codes', () => {
    expect(isCeremonyAborted({ code: 'ERROR_CEREMONY_ABORTED' })).toBe(true);
    const aborted = new Error('aborted');
    aborted.name = 'AbortError';
    expect(isCeremonyAborted(aborted)).toBe(true);
    expect(isCeremonyAborted({ code: 'ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY' })).toBe(false);
  });
});

describe('enrolmentDecision', () => {
  test('offers the passkey after the no-passkey fallback, native or not, without asking the account', () => {
    expect(enrolmentDecision({ passkeysSupported: true, native: true, afterNoPasskey: true })).toBe('offer');
    expect(enrolmentDecision({ passkeysSupported: true, native: false, afterNoPasskey: true })).toBe('offer');
  });

  test('keeps the existing behaviour for every other path', () => {
    expect(enrolmentDecision({ passkeysSupported: true, native: false, afterNoPasskey: false })).toBe('check');
    expect(enrolmentDecision({ passkeysSupported: true, native: true, afterNoPasskey: false })).toBe('skip');
  });

  test('never prompts a client without WebAuthn', () => {
    expect(enrolmentDecision({ passkeysSupported: false, native: false, afterNoPasskey: false })).toBe('skip');
    expect(enrolmentDecision({ passkeysSupported: false, native: true, afterNoPasskey: true })).toBe('skip');
  });
});

describe('accountHasNoPasskeys', () => {
  test('is true only for a successful empty list', () => {
    expect(accountHasNoPasskeys({ data: [] })).toBe(true);
    expect(accountHasNoPasskeys({ data: [{ id: 'p' }] })).toBe(false);
    expect(accountHasNoPasskeys({ data: [], error: { message: 'x' } })).toBe(false);
    expect(accountHasNoPasskeys({ data: null })).toBe(false);
    expect(accountHasNoPasskeys(null)).toBe(false);
  });
});

describe('fallback copy', () => {
  test('holds the exact words', () => {
    expect(PASSKEY_FALLBACK_COPY.message).toBe('No passkey was used. Sign in with an email code, and OpenKey offers to add a passkey to this device.');
    expect(PASSKEY_FALLBACK_COPY.emailButton).toBe('Use an email code');
  });
});

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

describe('startPasskeyAutofill', () => {
  test('a verified autofill sign-in is reported once', async () => {
    const { log, value } = deps();
    startPasskeyAutofill(value);
    await tick();
    expect(log.signInCalls).toBe(1);
    expect(log.signedIn).toBe(1);
  });

  test('does not start where the browser has no autofill', async () => {
    const { log, value } = deps({ supported: async () => false });
    startPasskeyAutofill(value);
    await tick();
    expect(log.signInCalls).toBe(0);
    expect(log.signedIn).toBe(0);
  });

  test('a refused or aborted request is silent', async () => {
    const aborted = deps({ signIn: async () => ({ error: { code: 'ERROR_CEREMONY_ABORTED' } }) });
    startPasskeyAutofill(aborted.value);
    await tick();
    const rejected = deps({ signIn: async () => { throw new Error('boom'); } });
    startPasskeyAutofill(rejected.value);
    await tick();
    expect(aborted.log.signedIn).toBe(0);
    expect(rejected.log.signedIn).toBe(0);
  });

  test('stop aborts the pending ceremony and a late success changes nothing', async () => {
    const gate = Promise.withResolvers<{ error: null }>();
    const { log, value } = deps({ signIn: () => gate.promise });
    const autofill = startPasskeyAutofill(value);
    await tick();
    const stopped = autofill.stop();
    expect(log.cancelled).toBeGreaterThanOrEqual(1);
    gate.resolve({ error: null });
    await stopped;
    expect(log.signedIn).toBe(0);
  });

  test('stop keeps cancelling until the request settles, then stops cancelling', async () => {
    const gate = Promise.withResolvers<{ error: null }>();
    const { log, value } = deps({ signIn: () => gate.promise });
    const autofill = startPasskeyAutofill(value);
    await tick();
    const stopped = autofill.stop();
    const first = log.cancelled;
    await tick(40);
    expect(log.cancelled).toBeGreaterThan(first);
    gate.resolve({ error: null });
    await stopped;
    const settledAt = log.cancelled;
    await tick(40);
    expect(log.cancelled).toBe(settledAt);
  });

  test('stop resolves only after the request settled, and returns the same promise when repeated', async () => {
    const gate = Promise.withResolvers<{ error: null }>();
    const { value } = deps({ signIn: () => gate.promise });
    const autofill = startPasskeyAutofill(value);
    await tick();
    let resolved = false;
    const stopped = autofill.stop();
    void stopped.then(() => { resolved = true; });
    expect(autofill.stop()).toBe(stopped);
    await tick(20);
    expect(resolved).toBe(false);
    gate.resolve({ error: null });
    await stopped;
    expect(resolved).toBe(true);
  });

  test('a hung request holds the stop only for the bound, then cancelling ends', async () => {
    const gate = Promise.withResolvers<{ error: null }>();
    const { log, value } = deps({ signIn: () => gate.promise, boundMs: 40 });
    const autofill = startPasskeyAutofill(value);
    await tick();
    await autofill.stop();
    const atBound = log.cancelled;
    expect(atBound).toBeGreaterThan(1);
    await tick(40);
    expect(log.cancelled).toBe(atBound);
    gate.resolve({ error: null });
    await tick();
    expect(log.signedIn).toBe(0);
  });

  // A model of the browser's one-ceremony rule: starting a ceremony aborts the current one, and `cancel`
  // aborts the current one. The autofill sign-in only starts its ceremony after a slow options request.
  function browser(optionsDelayMs: number) {
    const events: string[] = [];
    let current: { name: string; abort: () => void } | null = null;
    const begin = (name: string) => {
      if (current) {
        events.push(`${current.name} aborted by ${name}`);
        current.abort();
      }
      const gate = Promise.withResolvers<never>();
      const mine = { name, abort: () => gate.reject(new Error('aborted')) };
      current = mine;
      events.push(`${name} started`);
      return gate.promise;
    };
    const cancel = () => {
      if (!current) return;
      events.push(`${current.name} cancelled`);
      current.abort();
      current = null;
    };
    const signIn = async () => {
      await tick(optionsDelayMs);
      await begin('autofill');
      return { error: null };
    };
    return { events, begin, cancel, signIn };
  }

  test('a modal ceremony started after superseding waits for a slow options request and is never aborted by it', async () => {
    const fake = browser(40);
    const { log, value } = deps({ signIn: fake.signIn, cancel: fake.cancel });
    startPasskeyAutofill(value);
    await tick();
    await supersedePasskeyAutofill();
    // The autofill ceremony started late, was cancelled while pending, and the request has settled.
    expect(fake.events).toEqual(['autofill started', 'autofill cancelled']);
    void fake.begin('modal').catch(() => {});
    await tick(60);
    expect(fake.events).toEqual(['autofill started', 'autofill cancelled', 'modal started']);
    expect(log.signedIn).toBe(0);
  });

  test('superseding resolves only after the autofill request settled', async () => {
    const gate = Promise.withResolvers<{ error: null }>();
    const { value } = deps({ signIn: () => gate.promise });
    startPasskeyAutofill(value);
    await tick();
    let proceeded = false;
    const waiting = supersedePasskeyAutofill().then(() => { proceeded = true; });
    await tick(20);
    expect(proceeded).toBe(false);
    gate.resolve({ error: null });
    await waiting;
    expect(proceeded).toBe(true);
  });

  test('superseding with nothing running resolves at once', async () => {
    await supersedePasskeyAutofill();
  });

  test('a newer request starts only after the older one settled', async () => {
    const fake = browser(40);
    const old = deps({ signIn: fake.signIn, cancel: fake.cancel });
    startPasskeyAutofill(old.value);
    await tick();
    const fresh = deps({ signIn: async () => { fake.events.push('fresh signIn'); return { error: null }; } });
    startPasskeyAutofill(fresh.value);
    await tick(100);
    expect(fake.events).toEqual(['autofill started', 'autofill cancelled', 'fresh signIn']);
    expect(old.log.signedIn).toBe(0);
    expect(fresh.log.signedIn).toBe(1);
  });

  test('stop after the request finished cancels nothing', async () => {
    const { log, value } = deps();
    const autofill = startPasskeyAutofill(value);
    await tick();
    await autofill.stop();
    expect(log.cancelled).toBe(0);
  });
});
