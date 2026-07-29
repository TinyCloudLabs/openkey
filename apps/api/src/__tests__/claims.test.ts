import { describe, expect, test } from 'bun:test';
import { buildEmailClaims } from '../claims';

describe('buildEmailClaims', () => {
  const user = { email: 'alice@example.com', emailVerified: true };

  test('returns standard and compatibility verified claims when email scope is present', () => {
    const result = buildEmailClaims(user, ['openid', 'email']);
    expect(result).toEqual({
      email: 'alice@example.com',
      email_verified: true,
      emailVerified: true,
    });
  });

  test('returns emailVerified: false when user email is not verified', () => {
    const unverifiedUser = { email: 'bob@example.com', emailVerified: false };
    const result = buildEmailClaims(unverifiedUser, ['email']);
    expect(result).toEqual({
      email: 'bob@example.com',
      email_verified: false,
      emailVerified: false,
    });
  });

  test('returns empty object when email scope is absent', () => {
    const result = buildEmailClaims(user, ['openid']);
    expect(result).toEqual({});
  });

  test('returns empty object when only keys scope is present', () => {
    const result = buildEmailClaims(user, ['keys']);
    expect(result).toEqual({});
  });

  test('returns only email claims when both email + keys scopes are present', () => {
    const result = buildEmailClaims(user, ['openid', 'email', 'keys']);
    expect(result).toEqual({
      email: 'alice@example.com',
      email_verified: true,
      emailVerified: true,
    });
  });

  test('keeps standard and compatibility booleans identical', () => {
    for (const emailVerified of [true, false]) {
      const claims = buildEmailClaims({ email: 'same@example.com', emailVerified }, ['email']);
      expect(claims.email_verified).toBe(claims.emailVerified);
    }
  });

  test('returns empty object when scopes array is empty', () => {
    const result = buildEmailClaims(user, []);
    expect(result).toEqual({});
  });
});
