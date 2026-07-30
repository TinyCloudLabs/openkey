import { describe, expect, test } from 'bun:test';

import { embedSendEmailOtp, embedVerifyEmailOtp } from '../apps/web/src/lib/embed-passkey';

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

    const token = await embedVerifyEmailOtp(
      'person@example.test',
      '123456',
      fetchImpl,
      (value) => { persisted = value; },
    );

    expect(token).toBe('session-token-1');
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
});
