import { describe, expect, test } from 'bun:test';

import { embedCreateAccount, embedSendEmailOtp, embedVerifyEmailOtp } from '../apps/web/src/lib/embed-passkey';

describe('embedded email OTP', () => {
  test('sends the sign-in OTP inline', async () => {
    let request: { url: string; init?: RequestInit } | undefined;
    const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
      request = { url: String(url), init };
      return new Response('{}', { status: 200 });
    }) as typeof fetch;

    await embedSendEmailOtp('person@example.test', fetchImpl);

    expect(request?.url).toEndWith('/api/auth/email-otp/send-verification-otp');
    expect(request?.init?.method).toBe('POST');
    expect(JSON.parse(String(request?.init?.body))).toEqual({
      email: 'person@example.test',
      type: 'sign-in',
    });
  });

  test('verifies the OTP, persists the bearer token, and returns it', async () => {
    let persisted = '';
    const fetchImpl = (async () => new Response(
      JSON.stringify({ user: { id: 'user-1' } }),
      { status: 200, headers: { 'set-auth-token': 'session-token-1' } },
    )) as typeof fetch;

    const result = await embedVerifyEmailOtp(
      'person@example.test',
      '123456',
      fetchImpl,
      (value) => { persisted = value; },
    );

    expect(result).toEqual({ sessionToken: 'session-token-1' });
    expect(persisted).toBe('session-token-1');
  });

  test('does not accept a successful response without an embedded token', async () => {
    const fetchImpl = (async () => new Response('{}', { status: 200 })) as typeof fetch;
    await expect(embedVerifyEmailOtp(
      'person@example.test',
      '123456',
      fetchImpl,
      () => {},
    )).rejects.toThrow('no embedded session token');
  });

  test('a verified code for a new email returns the sign-up token and signs nobody in', async () => {
    let persisted = '';
    const fetchImpl = (async () => new Response(
      JSON.stringify({ code: 'NEW_ACCOUNT_CONFIRMATION_REQUIRED', message: 'No OpenKey account exists for this email.', signupToken: 'signup-1' }),
      { status: 403 },
    )) as typeof fetch;

    const result = await embedVerifyEmailOtp('new@example.test', '123456', fetchImpl, (value) => { persisted = value; });

    expect(result).toEqual({ signupToken: 'signup-1' });
    expect(persisted).toBe('');
  });

  test('creating the confirmed account persists its session; a refusal persists nothing', async () => {
    let persisted = '';
    let request: { url: string; init?: RequestInit } | undefined;
    const created = (async (url: string | URL | Request, init?: RequestInit) => {
      request = { url: String(url), init };
      return new Response(JSON.stringify({ token: 'raw' }), { status: 200, headers: { 'set-auth-token': 'session-token-2' } });
    }) as typeof fetch;

    expect(await embedCreateAccount('new@example.test', 'signup-1', created, (value) => { persisted = value; })).toBe('session-token-2');
    expect(persisted).toBe('session-token-2');
    expect(request?.url).toEndWith('/api/auth/sign-up/email-otp');
    expect(JSON.parse(String(request?.init?.body))).toEqual({ email: 'new@example.test', signupToken: 'signup-1' });

    persisted = '';
    const refused = (async () => new Response(
      JSON.stringify({ code: 'INVALID_SIGNUP_TOKEN', message: 'This confirmation has expired. Request a new code to create your account.' }),
      { status: 400 },
    )) as typeof fetch;
    await expect(embedCreateAccount('new@example.test', 'signup-1', refused, (value) => { persisted = value; }))
      .rejects.toThrow('This confirmation has expired');
    expect(persisted).toBe('');
  });
});
