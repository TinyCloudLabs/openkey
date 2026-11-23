// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { ceremonyAfterAutofill, startPasskeyAutofill, type AutofillDeps } from './passkey-sign-in';

const tick = (ms = 0) => new Promise((resolve) => setTimeout(resolve, ms));

describe('a request that replaces one whose sign-in is adopted', () => {
  test('its stop resolves true, so a click runs no ceremony of its own', async () => {
    const gate = Promise.withResolvers<{ error?: unknown }>();
    let signedIn = 0;
    const base = { supported: async () => true, cancel: () => {}, onSignedIn: () => { signedIn++; }, retryEveryMs: 5, boundMs: 500 };
    const a: AutofillDeps = { ...base, signIn: ({ onVerify }) => { onVerify(); return gate.promise; } };
    const b: AutofillDeps = { ...base, signIn: async () => ({ error: null }) };
    startPasskeyAutofill(a);
    await tick();
    startPasskeyAutofill(b);
    let ceremonies = 0;
    const click = ceremonyAfterAutofill(async () => { ceremonies++; return { error: null }; });
    await tick(20);
    gate.resolve({ error: null });
    expect(await click).toEqual({ adopted: true });
    expect(ceremonies).toBe(0);
    expect(signedIn).toBe(1);
  });
});
