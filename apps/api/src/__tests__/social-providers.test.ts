import { describe, expect, test } from 'bun:test';
import {
  decodeJwt,
  decodeProtectedHeader,
  exportPKCS8,
  generateKeyPair,
  SignJWT,
} from 'jose';

import {
  configuredSocialProviderIds,
  generateAppleClientSecret,
  resolveAppleUserInfo,
  socialProviderTrustedOrigins,
} from '../social-providers';

describe('social provider configuration', () => {
  test('advertises only fully configured providers', () => {
    expect(configuredSocialProviderIds({})).toEqual([]);
    expect(configuredSocialProviderIds({
      GOOGLE_CLIENT_ID: 'google-id',
      GOOGLE_CLIENT_SECRET: 'google-secret',
    })).toEqual(['google']);
    expect(configuredSocialProviderIds({
      APPLE_CLIENT_ID: 'apple-id',
      APPLE_TEAM_ID: 'team-id',
      APPLE_KEY_ID: 'key-id',
    })).toEqual([]);
    expect(configuredSocialProviderIds({
      GOOGLE_CLIENT_ID: 'google-id',
      GOOGLE_CLIENT_SECRET: 'google-secret',
      APPLE_CLIENT_ID: 'apple-id',
      APPLE_TEAM_ID: 'team-id',
      APPLE_KEY_ID: 'key-id',
      APPLE_PRIVATE_KEY: 'private-key',
    })).toEqual(['google', 'apple']);
  });

  test('trusts Apple only when Apple is configured', () => {
    expect(socialProviderTrustedOrigins('https://openkey.test', {})).toEqual([
      'https://openkey.test',
    ]);
    expect(socialProviderTrustedOrigins('https://openkey.test', {
      APPLE_CLIENT_ID: 'apple-id',
      APPLE_TEAM_ID: 'team-id',
      APPLE_KEY_ID: 'key-id',
      APPLE_PRIVATE_KEY: 'private-key',
    })).toEqual([
      'https://openkey.test',
      'https://appleid.apple.com',
    ]);
  });

  test('allows the explicitly configured console origin for session-bearing auth calls', () => {
    expect(socialProviderTrustedOrigins('https://openkey.test', {
      CONSOLE_ORIGIN: 'https://console.openkey.test',
    })).toEqual([
      'https://openkey.test',
      'https://console.openkey.test',
    ]);
  });

  test('does not widen auth trust to unrelated CORS origins', () => {
    expect(socialProviderTrustedOrigins('https://openkey.test', {
      CORS_ORIGIN: 'https://openkey.test,https://preview.openkey.test',
      TEE_MODE: 'production',
    })).toEqual([
      'https://openkey.test',
      'https://console.openkey.so',
    ]);
  });

  test('generates an ES256 Apple secret below the six-month maximum and accepts escaped newlines', async () => {
    const { privateKey } = await generateKeyPair('ES256', { extractable: true });
    const pem = await exportPKCS8(privateKey);
    const now = 1_800_000_000;
    const token = await generateAppleClientSecret(
      'services.openkey.test',
      'TEAM123',
      'KEY123',
      pem.replace(/\n/g, '\\n'),
      now,
    );

    expect(decodeProtectedHeader(token)).toMatchObject({ alg: 'ES256', kid: 'KEY123' });
    expect(decodeJwt(token)).toMatchObject({
      iss: 'TEAM123',
      sub: 'services.openkey.test',
      aud: 'https://appleid.apple.com',
      iat: now,
      exp: now + 180 * 24 * 60 * 60,
    });
    expect((decodeJwt(token).exp ?? 0) - now).toBeLessThan(15_777_000);
  });

  test('recovers Apple email from the persisted provider account on later callbacks', async () => {
    const idToken = await new SignJWT({ sub: 'apple-user-1' })
      .setProtectedHeader({ alg: 'HS256' })
      .sign(new TextEncoder().encode('test-only-secret-test-only-secret'));
    const lookups: string[] = [];

    const result = await resolveAppleUserInfo(
      { idToken },
      async (providerAccountId) => {
        lookups.push(providerAccountId);
        return {
          email: 'relay@example.test',
          name: 'Existing Apple User',
          image: null,
        };
      },
    );

    expect(lookups).toEqual(['apple-user-1']);
    expect(result?.user).toMatchObject({
      id: 'apple-user-1',
      email: 'relay@example.test',
      emailVerified: true,
      name: 'Existing Apple User',
    });
  });

  test('uses first-authorization Apple identity data without a persistence lookup', async () => {
    const idToken = await new SignJWT({
      sub: 'apple-user-2',
      email: 'first@example.test',
      email_verified: 'true',
    })
      .setProtectedHeader({ alg: 'HS256' })
      .sign(new TextEncoder().encode('test-only-secret-test-only-secret'));
    let lookupCalled = false;

    const result = await resolveAppleUserInfo(
      {
        idToken,
        user: { name: { firstName: 'First', lastName: 'User' } },
      },
      async () => {
        lookupCalled = true;
        return null;
      },
    );

    expect(lookupCalled).toBe(false);
    expect(result?.user).toMatchObject({
      email: 'first@example.test',
      emailVerified: true,
      name: 'First User',
    });
  });
});
