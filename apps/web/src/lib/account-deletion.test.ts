// Account deletion from Settings: the flow appears only for an API with the
// deletion step-up, picks the step-up the API will accept, and every request
// is a cookie request with the deletion purpose.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  DELETE_CONFIRMATION,
  DeletionError,
  deleteAccount,
  loadDeletionSupport,
  parseDeletionSupport,
  relayForwardingMessage,
  requiredMethod,
  sendDeletionCode,
  verifyDeletionCode,
  verifyDeletionPasskey,
} from './account-deletion';

const API = 'https://api.openkey.test';

function fetchSequence(...answers: Array<[number, unknown]>) {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const impl = (async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    const [status, body] = answers[Math.min(calls.length - 1, answers.length - 1)]!;
    return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

const user = (extra: Record<string, unknown> = {}) => ({
  user: { email: 'a@example.test', emailVerified: true, _count: { ethereumKeys: 2, passkeys: 0 }, emailUndeliverable: false, ...extra },
});

function expectCookieOnly(init: RequestInit | undefined) {
  expect(init?.credentials).toBe('include');
  const headers = new Headers(init?.headers);
  expect(headers.has('authorization')).toBe(false);
}

describe('parseDeletionSupport', () => {
  test('an API without the deletion step-up (no emailUndeliverable) hides the flow', () => {
    const { user: { emailUndeliverable: _, ...old } } = user();
    expect(parseDeletionSupport({ user: old })).toEqual({ supported: false });
    expect(parseDeletionSupport(null)).toEqual({ supported: false });
    expect(parseDeletionSupport({ user: null })).toEqual({ supported: false });
  });

  test('a passkey-less account deletes with an email code', () => {
    expect(parseDeletionSupport(user())).toEqual({
      supported: true,
      account: { email: 'a@example.test', keys: 2, method: 'email', emailUndeliverable: false, passkeyStepUpAvailable: false },
    });
  });

  test('before the passkey step-up ships, a passkey account needs a passkey it cannot give', () => {
    const support = parseDeletionSupport(user({ _count: { ethereumKeys: 1, passkeys: 1 } }));
    expect(support.supported && support.account.method).toBe('passkey');
    expect(support.supported && support.account.passkeyStepUpAvailable).toBe(false);
  });

  test('stepUpPasskeys decides the method once the API reports it', () => {
    const withPasskey = parseDeletionSupport(user({ _count: { passkeys: 1 }, stepUpPasskeys: 1 }));
    expect(withPasskey.supported && withPasskey.account).toMatchObject({ method: 'passkey', passkeyStepUpAvailable: true });
    const noStepUp = parseDeletionSupport(user({ _count: { passkeys: 1 }, stepUpPasskeys: 0 }));
    expect(noStepUp.supported && noStepUp.account.method).toBe('email');
  });

  test('loadDeletionSupport reads /api/account with the cookie', async () => {
    const { impl, calls } = fetchSequence([200, user({ emailUndeliverable: true })]);
    const support = await loadDeletionSupport(API, impl);
    expect(calls[0]!.url).toBe(`${API}/api/account`);
    expectCookieOnly(calls[0]!.init);
    expect(support.supported && support.account.emailUndeliverable).toBe(true);
  });
});

describe('email code step-up', () => {
  test('send and verify carry the delete_account purpose', async () => {
    const { impl, calls } = fetchSequence([200, { status: true }]);
    await sendDeletionCode(API, impl);
    await verifyDeletionCode(API, '123456', impl);
    expect(calls.map((call) => call.url)).toEqual([
      `${API}/api/account/step-up/email-otp/send`,
      `${API}/api/account/step-up/email-otp/verify`,
    ]);
    expect(JSON.parse(calls[0]!.init!.body as string)).toEqual({ purpose: 'delete_account' });
    expect(JSON.parse(calls[1]!.init!.body as string)).toEqual({ purpose: 'delete_account', code: '123456' });
    calls.forEach((call) => expectCookieOnly(call.init));
  });

  test('a passkey account asking for a code is switched to the passkey', async () => {
    const { impl } = fetchSequence([403, { error: 'x', code: 'passkey_step_up_required' }]);
    const error = await sendDeletionCode(API, impl).catch((cause) => cause);
    expect(requiredMethod(error)).toBe('passkey');
  });

  test('a wrong code is reported as such', async () => {
    const { impl } = fetchSequence([400, { error: 'Invalid or expired account verification code' }]);
    const error = await verifyDeletionCode(API, '000000', impl).catch((cause) => cause);
    expect(error).toBeInstanceOf(DeletionError);
    expect(error.message).toContain('wrong or expired');
  });

  test('email delivery down says so', async () => {
    const { impl } = fetchSequence([503, { error: 'Email delivery unavailable' }]);
    const error = await sendDeletionCode(API, impl).catch((cause) => cause);
    expect(error.message).toContain('could not send email');
  });
});

describe('passkey step-up', () => {
  test('verifies on the current cookie session and never handles a session token', async () => {
    const { impl, calls } = fetchSequence(
      [200, { challengeToken: 'ct', options: { challenge: 'c', allowCredentials: [] } }],
      [200, { status: true }],
    );
    const seen: unknown[] = [];
    await verifyDeletionPasskey(API, impl, (async (opts: unknown) => { seen.push(opts); return { id: 'cred' }; }) as never);
    expect(seen).toEqual([{ optionsJSON: { challenge: 'c', allowCredentials: [] } }]);
    expect(calls.map((call) => call.url)).toEqual([
      `${API}/api/account/step-up/passkey/options`,
      `${API}/api/account/step-up/passkey/verify`,
    ]);
    expect(JSON.parse(calls[1]!.init!.body as string)).toEqual({ challengeToken: 'ct', response: { id: 'cred' } });
    calls.forEach((call) => expectCookieOnly(call.init));
  });

  test('an API without the passkey step-up is reported unavailable, not as a failure to retry', async () => {
    const { impl } = fetchSequence([404, { error: 'Not Found' }]);
    const error = await verifyDeletionPasskey(API, impl, (async () => ({})) as never).catch((cause) => cause);
    expect(error.code).toBe('passkey_step_up_unavailable');
  });

  test('a cancelled prompt sends nothing to verify', async () => {
    const { impl, calls } = fetchSequence([200, { challengeToken: 'ct', options: {} }]);
    const error = await verifyDeletionPasskey(API, impl, (async () => { throw new Error('NotAllowedError'); }) as never).catch((cause) => cause);
    expect(error.code).toBe('passkey_cancelled');
    expect(calls).toHaveLength(1);
  });
});

describe('deleteAccount', () => {
  test('sends the exact typed confirmation with the cookie', async () => {
    const { impl, calls } = fetchSequence([200, { success: true, keysDeleted: 3 }]);
    expect(await deleteAccount(API, impl)).toEqual({ keysDeleted: 3 });
    expect(calls[0]!.url).toBe(`${API}/api/account/delete`);
    expect(calls[0]!.init!.method).toBe('POST');
    expect(JSON.parse(calls[0]!.init!.body as string)).toEqual({ confirmation: DELETE_CONFIRMATION });
    expect(DELETE_CONFIRMATION).toBe('DELETE MY ACCOUNT');
    expectCookieOnly(calls[0]!.init);
  });

  test('an expired step-up names the method to redo', async () => {
    for (const [code, method] of [['passkey_step_up_required', 'passkey'], ['email_step_up_required', 'email']] as const) {
      const { impl } = fetchSequence([403, { error: 'x', code }]);
      expect(requiredMethod(await deleteAccount(API, impl).catch((cause) => cause))).toBe(method);
    }
  });

  test('a response without success is never shown as deleted', async () => {
    const { impl } = fetchSequence([200, {}]);
    await expect(deleteAccount(API, impl)).rejects.toBeInstanceOf(DeletionError);
  });
});

test('the relay message tells the user to turn Apple forwarding back on', () => {
  const message = relayForwardingMessage('x@privaterelay.appleid.com');
  expect(message).toContain('x@privaterelay.appleid.com');
  expect(message).toContain('turn email forwarding back on');
});
