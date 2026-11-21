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
    retryForMs: 200,
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
    autofill.stop();
    expect(log.cancelled).toBeGreaterThanOrEqual(1);
    gate.resolve({ error: null });
    await tick();
    expect(log.signedIn).toBe(0);
  });

  test('stop before the ceremony exists keeps aborting until the request settles', async () => {
    const gate = Promise.withResolvers<{ error: null }>();
    const { log, value } = deps({ signIn: () => gate.promise });
    const autofill = startPasskeyAutofill(value);
    await tick();
    autofill.stop();
    const first = log.cancelled;
    await tick(40);
    expect(log.cancelled).toBeGreaterThan(first);
    gate.resolve({ error: null });
    await tick(20);
    const settledAt = log.cancelled;
    await tick(40);
    expect(log.cancelled).toBe(settledAt);
  });

  test('superseding by a modal ceremony aborts once and never cancels the modal later', async () => {
    const gate = Promise.withResolvers<{ error: null }>();
    const { log, value } = deps({ signIn: () => gate.promise });
    startPasskeyAutofill(value);
    await tick();
    supersedePasskeyAutofill();
    expect(log.cancelled).toBe(1);
    await tick(40);
    expect(log.cancelled).toBe(1);
    gate.resolve({ error: null });
    await tick();
    expect(log.signedIn).toBe(0);
  });

  test('a newer request replaces the older one', async () => {
    const gate = Promise.withResolvers<{ error: null }>();
    const old = deps({ signIn: () => gate.promise });
    startPasskeyAutofill(old.value);
    await tick();
    const fresh = deps();
    startPasskeyAutofill(fresh.value);
    await tick();
    expect(old.log.cancelled).toBe(1);
    gate.resolve({ error: null });
    await tick();
    expect(old.log.signedIn).toBe(0);
    expect(fresh.log.signedIn).toBe(1);
  });

  test('stop is idempotent after the request finished', async () => {
    const { log, value } = deps();
    const autofill = startPasskeyAutofill(value);
    await tick();
    autofill.stop();
    expect(log.cancelled).toBe(0);
  });
});
