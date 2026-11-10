// TC-1232: the popup callback's URL and the continuation answers map to one
// screen each, and an answer that does not match its redirect is refused.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  APPLE_EMAIL_REQUIRED_MESSAGE,
  APPLE_RELAY_NOTICE,
  accountExistsMessage,
  confirmSocialContinuation,
  isAppleRelayEmail,
  loadSocialContinuation,
  parseSocialCallback,
  relayNotice,
  socialErrorMessage,
  socialPopupReturnUrl,
} from './social-continuation';

const ORIGIN = 'https://openkey.so';
const callback = (query: string) => parseSocialCallback(new URL(`${ORIGIN}/auth/social/callback?${query}`));

function fetchReturning(status: number, body: unknown) {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const impl = (async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

describe('parseSocialCallback', () => {
  test('a start names the provider and its action', () => {
    expect(callback('provider=apple')).toEqual({ kind: 'start', provider: 'apple', action: null });
    expect(callback('provider=google&action=link')).toEqual({ kind: 'start', provider: 'google', action: 'link' });
    expect(callback('provider=apple&action=signup')).toEqual({ kind: 'start', provider: 'apple', action: 'signup' });
    expect(callback('provider=apple&action=delete')).toEqual({ kind: 'start', provider: 'apple', action: null });
  });

  test('an unknown provider never starts anything', () => {
    expect(callback('provider=facebook').kind).toBe('complete');
  });

  test('a choice needs both its outcome and its continuation', () => {
    expect(callback('via=apple&error=new_account&continuation=tok')).toEqual({
      kind: 'continuation', provider: 'apple', outcome: 'new_account', token: 'tok', signupIntent: false,
    });
    expect(callback('via=apple&signup=1&error=account_exists&continuation=tok')).toMatchObject({
      kind: 'continuation', outcome: 'account_exists', signupIntent: true,
    });
    // Without the token the confirmation cannot be shown, so it is an expired one.
    expect(callback('via=apple&error=new_account')).toEqual({ kind: 'error', provider: 'apple', code: 'continuation_expired' });
  });

  test('other errors keep their code; apple_email_required is always Apple', () => {
    expect(callback('error=apple_email_required')).toEqual({ kind: 'error', provider: 'apple', code: 'apple_email_required' });
    expect(callback('via=google&error=access_denied')).toEqual({ kind: 'error', provider: 'google', code: 'access_denied' });
    expect(callback('via=evil&error=unable_to_get_user_info')).toEqual({ kind: 'error', provider: null, code: 'unable_to_get_user_info' });
  });

  test('no error is a completed sign-in', () => {
    expect(callback('via=apple')).toEqual({ kind: 'complete', provider: 'apple' });
  });
});

describe('socialPopupReturnUrl', () => {
  test('names the provider, and carries sign-up intent only from register', () => {
    expect(socialPopupReturnUrl(ORIGIN, 'apple', null)).toBe(`${ORIGIN}/auth/social/callback?via=apple`);
    expect(socialPopupReturnUrl(ORIGIN, 'apple', 'signup')).toBe(`${ORIGIN}/auth/social/callback?via=apple&signup=1`);
    expect(socialPopupReturnUrl(ORIGIN, 'google', 'link')).toBe(`${ORIGIN}/auth/social/callback?via=google`);
  });
});

describe('socialErrorMessage', () => {
  test.each([
    ['apple', 'apple_email_required', APPLE_EMAIL_REQUIRED_MESSAGE],
    ['apple', 'account_not_linked', 'An OpenKey account already uses this email. Sign in to it and add Apple in Settings.'],
    ['apple', 'user_cancelled_authorize', 'Apple sign-in was cancelled.'],
    ['google', 'access_denied', 'Google sign-in was cancelled.'],
    ['apple', 'account_already_linked_to_different_user', 'This Apple account is already linked to another OpenKey account.'],
    ['apple', 'unable_to_link_account', 'OpenKey could not link Apple. Verify a new email code in Settings and try again.'],
    ['apple', 'continuation_expired', 'This Apple confirmation expired. Start sign-in again.'],
    ['apple', 'invalid_code', 'Apple could not complete sign-in. Please try again.'],
    [null, 'invalid_code', 'The provider could not complete sign-in. Please try again.'],
  ] as const)('%s %s', (provider: 'apple' | 'google' | null, code: string, message: string) => {
    expect(socialErrorMessage(provider, code)).toBe(message);
  });

  test('never echoes the code it was given', () => {
    expect(socialErrorMessage('apple', '<script>alert(1)</script>')).not.toContain('script');
  });
});

describe('relay copy (R4) and account exists (R3)', () => {
  test('a relay is the signed flag or the relay domain, for Apple only', () => {
    expect(isAppleRelayEmail('X@PrivateRelay.AppleID.com')).toBe(true);
    expect(isAppleRelayEmail('privaterelay.appleid.com@example.test')).toBe(false);
    expect(relayNotice({ provider: 'apple', email: 'a@example.test', isPrivateEmail: true })).toBe(APPLE_RELAY_NOTICE);
    expect(relayNotice({ provider: 'apple', email: 'a@privaterelay.appleid.com', isPrivateEmail: false })).toBe(APPLE_RELAY_NOTICE);
    expect(relayNotice({ provider: 'apple', email: 'a@example.test', isPrivateEmail: false })).toBeNull();
    expect(relayNotice({ provider: 'google', email: 'a@privaterelay.appleid.com', isPrivateEmail: true })).toBeNull();
  });

  test('account exists names the email and the provider', () => {
    expect(accountExistsMessage('apple', 'sam@example.test')).toBe(
      'An OpenKey account already uses sam@example.test. Sign in to it and verify with an email code to add Apple in Settings.',
    );
  });
});

describe('loadSocialContinuation', () => {
  const input = { token: 'tok', outcome: 'new_account', provider: 'apple' } as const;

  test('reads the display data, and sends the native query when there is one', async () => {
    const { impl, calls } = fetchReturning(200, {
      outcome: 'new_account', providerId: 'apple', email: 'r@privaterelay.appleid.com', name: 'R', isPrivateEmail: true,
    });
    const loaded = await loadSocialContinuation({ ...input, oauthQuery: 'client_id=exo&sig=s' }, impl);
    expect(loaded).toEqual({ token: 'tok', outcome: 'new_account', provider: 'apple', email: 'r@privaterelay.appleid.com', isPrivateEmail: true });
    const url = new URL(calls[0]!.url, ORIGIN);
    expect(url.pathname).toBe('/api/auth/social/continuation');
    expect(url.searchParams.get('continuation')).toBe('tok');
    expect(url.searchParams.get('oauthQuery')).toBe('client_id=exo&sig=s');
    expect(calls[0]!.init?.credentials).toBe('include');
  });

  test('a missing isPrivateEmail is false', async () => {
    const { impl } = fetchReturning(200, { outcome: 'new_account', providerId: 'google', email: 'g@example.test' });
    expect((await loadSocialContinuation({ ...input, provider: null }, impl)).isPrivateEmail).toBe(false);
  });

  test('a refused binding (another cookie, request or an expired token) is an expired confirmation', async () => {
    const { impl } = fetchReturning(400, { message: 'Invalid continuation' });
    await expect(loadSocialContinuation(input, impl)).rejects.toThrow('This Apple confirmation expired. Start sign-in again.');
  });

  test.each([
    ['another outcome', { outcome: 'account_exists', providerId: 'apple', email: 'a@example.test' }],
    ['another provider', { outcome: 'new_account', providerId: 'google', email: 'a@example.test' }],
    ['an unknown provider', { outcome: 'new_account', providerId: 'facebook', email: 'a@example.test' }],
    ['no email', { outcome: 'new_account', providerId: 'apple', email: '' }],
  ])('%s is refused, never shown', async (_label: string, body: unknown) => {
    const { impl } = fetchReturning(200, body);
    await expect(loadSocialContinuation(input, impl)).rejects.toThrow('Apple could not complete sign-in. Please try again.');
  });
});

describe('confirmSocialContinuation', () => {
  test('returns the session token and posts the bound native query', async () => {
    const { impl, calls } = fetchReturning(200, { token: 'session-1', user: {} });
    expect(await confirmSocialContinuation({ token: 'tok', provider: 'apple', oauthQuery: 'client_id=exo' }, impl)).toBe('session-1');
    expect(JSON.parse(String(calls[0]!.init?.body))).toEqual({ continuation: 'tok', oauthQuery: 'client_id=exo' });
    expect(calls[0]!.init?.method).toBe('POST');
  });

  test('the web confirm sends no oauthQuery', async () => {
    const { impl, calls } = fetchReturning(200, { token: 'session-1' });
    await confirmSocialContinuation({ token: 'tok', provider: 'apple' }, impl);
    expect(JSON.parse(String(calls[0]!.init?.body))).toEqual({ continuation: 'tok' });
  });

  test.each([
    [{ code: 'ACCOUNT_ALREADY_EXISTS' }, 'An OpenKey account already uses this email. Sign in to it and add Apple in Settings.'],
    [{ code: 'ACCOUNT_ALREADY_LINKED' }, 'This Apple account is already linked to an OpenKey account. Sign in with Apple instead.'],
    [{ message: 'Invalid continuation' }, 'Could not create your account. Start Apple sign-in again.'],
  ])('maps %o', async (body: unknown, message: string) => {
    const { impl } = fetchReturning(400, body);
    await expect(confirmSocialContinuation({ token: 'tok', provider: 'apple' }, impl)).rejects.toThrow(message);
  });

  test('a 200 without a token is not a session', async () => {
    const { impl } = fetchReturning(200, {});
    await expect(confirmSocialContinuation({ token: 'tok', provider: 'google' }, impl)).rejects.toThrow('Start Google sign-in again');
  });
});
