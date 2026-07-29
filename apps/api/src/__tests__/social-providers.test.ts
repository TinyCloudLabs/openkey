import { describe, expect, test } from 'bun:test';
import { decodeJwt, decodeProtectedHeader, exportPKCS8, generateKeyPair } from 'jose';

import {
  configuredSocialProviderIds,
  generateAppleClientSecret,
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
});
