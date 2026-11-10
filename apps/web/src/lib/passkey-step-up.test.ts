// TC-1198: the step-up prompt opens only on the API's typed refusal, and every
// step-up request rides the cookie session (the API refuses bearer step-ups).
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterEach, expect, test } from 'bun:test';
import { passkeyStepUpMethods, sendPasskeyStepUpCode, verifyPasskeyStepUpCode } from './passkey-step-up';

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

test('reads the accepted methods from a typed step-up refusal only', () => {
  expect(passkeyStepUpMethods({ code: 'PASSKEY_STEP_UP_REQUIRED', methods: ['passkey', 'email'] })).toEqual(['passkey', 'email']);
  expect(passkeyStepUpMethods({ code: 'PASSKEY_STEP_UP_REQUIRED', methods: ['email', 'sms'] })).toEqual(['email']);
  expect(passkeyStepUpMethods({ code: 'PASSKEY_STEP_UP_REQUIRED' })).toEqual([]);
  // Older APIs and unrelated failures keep their own error handling.
  expect(passkeyStepUpMethods({ code: 'FAILED_TO_VERIFY_REGISTRATION', message: 'nope' })).toBeNull();
  expect(passkeyStepUpMethods(null)).toBeNull();
  expect(passkeyStepUpMethods(undefined)).toBeNull();
});

test('email step-up requests carry the purpose on the cookie session, with no Authorization header', async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return Response.json({ status: true });
  }) as typeof fetch;
  await sendPasskeyStepUpCode('passkey_remove');
  await verifyPasskeyStepUpCode('passkey_register', '123456');
  expect(calls.map(({ url }) => url)).toEqual(['/api/account/step-up/email-otp/send', '/api/account/step-up/email-otp/verify']);
  expect(calls.map(({ init }) => JSON.parse(String(init.body)))).toEqual([{ purpose: 'passkey_remove' }, { purpose: 'passkey_register', code: '123456' }]);
  for (const { init } of calls) {
    expect(init.credentials).toBe('include');
    expect(new Headers(init.headers).has('authorization')).toBe(false);
  }
});

test('a refused code surfaces a message instead of continuing', async () => {
  globalThis.fetch = (async () => Response.json({ error: 'Invalid' }, { status: 400 })) as unknown as typeof fetch;
  await expect(verifyPasskeyStepUpCode('passkey_register', '000000')).rejects.toThrow('Incorrect or expired code');
});
