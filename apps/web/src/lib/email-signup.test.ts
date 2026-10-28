// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  keepsSignupToken,
  newAccountNeedsChallenge,
  newAccountSignupToken,
} from './email-signup';

describe('newAccountSignupToken', () => {
  test('returns the token from a new-account answer', () => {
    expect(
      newAccountSignupToken({ code: 'NEW_ACCOUNT_CONFIRMATION_REQUIRED', signupToken: 'tok' }),
    ).toBe('tok');
  });

  test('returns null for other codes and missing tokens', () => {
    expect(newAccountSignupToken({ code: 'INVALID_OTP', signupToken: 'tok' })).toBeNull();
    expect(newAccountSignupToken({ code: 'NEW_ACCOUNT_CONFIRMATION_REQUIRED' })).toBeNull();
    expect(newAccountSignupToken(null)).toBeNull();
  });
});

describe('newAccountNeedsChallenge', () => {
  test('keeps the check unless the API explicitly skips it', () => {
    expect(newAccountNeedsChallenge({ turnstileRequired: true })).toBe(true);
    expect(newAccountNeedsChallenge({})).toBe(true);
    expect(newAccountNeedsChallenge(null)).toBe(true);
  });

  test('skips the check only for turnstileRequired: false', () => {
    expect(newAccountNeedsChallenge({ turnstileRequired: false })).toBe(false);
  });
});

describe('keepsSignupToken', () => {
  test('keeps the token for the three retryable codes', () => {
    expect(keepsSignupToken({ code: 'TURNSTILE_REQUIRED' })).toBe(true);
    expect(keepsSignupToken({ code: 'TURNSTILE_FAILED' })).toBe(true);
    expect(keepsSignupToken({ code: 'REGISTRATION_PAUSED' })).toBe(true);
  });

  test('drops the token for spent, invalid, or existing-account errors', () => {
    expect(keepsSignupToken({ code: 'INVALID_SIGNUP_TOKEN' })).toBe(false);
    expect(keepsSignupToken({ code: 'ACCOUNT_ALREADY_EXISTS' })).toBe(false);
    expect(keepsSignupToken({ code: 'constructor' })).toBe(false);
    expect(keepsSignupToken(undefined)).toBe(false);
  });
});
