import { describe, expect, test } from 'bun:test';
import { buildEmailClaims } from '../claims';

describe('buildEmailClaims', () => {
  const user = { email: 'alice@example.com', emailVerified: true };

  test('returns email + emailVerified when email scope is present', () => {
    const result = buildEmailClaims(user, ['openid', 'email']);
    expect(result).toEqual({
      email: 'alice@example.com',
      emailVerified: true,
    });
  });

  test('returns emailVerified: false when user email is not verified', () => {
    const unverifiedUser = { email: 'bob@example.com', emailVerified: false };
    const result = buildEmailClaims(unverifiedUser, ['email']);
    expect(result).toEqual({
      email: 'bob@example.com',
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
      emailVerified: true,
    });
  });

  test('returns empty object when scopes array is empty', () => {
    const result = buildEmailClaims(user, []);
    expect(result).toEqual({});
  });
});
