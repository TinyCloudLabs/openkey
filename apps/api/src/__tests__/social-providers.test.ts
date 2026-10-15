import { createHash, randomBytes } from 'node:crypto';
import { describe, expect, test } from 'bun:test';
import {
  createLocalJWKSet,
  decodeProtectedHeader,
  exportJWK,
  exportPKCS8,
  generateKeyPair,
  jwtVerify,
  SignJWT,
} from 'jose';

import * as socialProviderModule from '../social-providers';
import {
  configuredSocialProviderIds,
  createSocialProviders,
  generateAppleClientSecret,
  socialProviderTrustedOrigins,
} from '../social-providers';

const appleTestKey = generateKeyPair('ES256', { extractable: true })
  .then(async ({ privateKey, publicKey }) => ({
    pem: await exportPKCS8(privateKey),
    publicKey,
  }));

async function signAppleIdToken(
  claims: Record<string, unknown>,
  options: { issuer?: string; audience?: string; issuedAt?: number; expiresAt?: number } = {},
) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuer(options.issuer ?? 'https://appleid.apple.com')
    .setAudience(options.audience ?? 'services.openkey.test')
    .setIssuedAt(options.issuedAt ?? now)
    .setExpirationTime(options.expiresAt ?? now + 300)
    .sign(new TextEncoder().encode('test-only-secret-test-only-secret'));
}

type AppleTokens = {
  idToken?: string;
  user?: {
    email?: string;
    name?: { firstName?: string; lastName?: string };
  };
};
type AppleProfile = {
  user: {
    id: string;
    email?: string;
    emailVerified: boolean;
    name?: string;
  };
  data?: unknown;
};
type PersistedAppleUser = {
  email: string;
  name: string | null;
  image: string | null;
};

async function appleGetUserInfo(
  findPersistedUser: (providerAccountId: string) => Promise<PersistedAppleUser | null>
    = async () => null,
) {
  const providers = createSocialProviders({
    APPLE_SIGN_IN_ENABLED: 'true',
    APPLE_CLIENT_ID: 'services.openkey.test',
    APPLE_TEAM_ID: 'team-id',
    APPLE_KEY_ID: 'key-id',
    APPLE_PRIVATE_KEY: (await appleTestKey).pem,
  }, findPersistedUser);
  const apple = await (providers.apple as () => Promise<{
    getUserInfo: (tokens: AppleTokens) => Promise<AppleProfile | null>;
  }>)();
  return apple.getUserInfo;
}

const nativeTestKey = generateKeyPair('RS256', { extractable: true })
  .then(async ({ privateKey, publicKey }) => ({
    privateKey,
    jwks: createLocalJWKSet({
      keys: [{ ...await exportJWK(publicKey), kid: 'apple-test-key', alg: 'RS256', use: 'sig' }],
    }),
  }));

const verifyAppleNativeIdToken = (socialProviderModule as typeof socialProviderModule & {
  verifyAppleNativeIdToken: (
    token: string,
    options: {
      jwks: unknown;
      audience: string;
      serverNonce: string;
      requestUri: string;
      consumeNonce: (requestUri: string, nonceHash: string) => Promise<boolean>;
    },
  ) => Promise<{ sub: string; email?: string }>;
}).verifyAppleNativeIdToken;

async function nativeVerifierFixture() {
  const { privateKey, jwks } = await nativeTestKey;
  const serverNonce = randomBytes(32).toString('base64url');
  const nonceHash = createHash('sha256').update(serverNonce).digest('hex');
  const requestUri = 'urn:ietf:params:oauth:request_uri:apple-test';
  const unusedNonces = new Set([`${requestUri}:${nonceHash}`]);
  const options = {
    jwks,
    audience: 'xyz.tinycloud.exo',
    serverNonce,
    requestUri,
    consumeNonce: async (uri: string, hash: string) =>
      unusedNonces.delete(`${uri}:${hash}`),
  };
  async function sign(
    claims: Record<string, unknown> = {},
    override: {
      issuer?: string;
      audience?: string;
      issuedAt?: number;
      expiresAt?: number;
      kid?: string;
    } = {},
  ) {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({
      sub: 'native-apple-user',
      email: 'native@example.test',
      email_verified: true,
      nonce_supported: true,
      nonce: nonceHash,
      ...claims,
    })
      .setProtectedHeader({ alg: 'RS256', kid: override.kid ?? 'apple-test-key' })
      .setIssuer(override.issuer ?? 'https://appleid.apple.com')
      .setAudience(override.audience ?? 'xyz.tinycloud.exo')
      .setIssuedAt(override.issuedAt ?? now)
      .setExpirationTime(override.expiresAt ?? now + 300)
      .sign(privateKey);
  }
  return { options, sign, nonceHash };
}

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
    })).toEqual(['google']);
    expect(configuredSocialProviderIds({
      GOOGLE_CLIENT_ID: 'google-id',
      GOOGLE_CLIENT_SECRET: 'google-secret',
      APPLE_SIGN_IN_ENABLED: 'true',
      APPLE_CLIENT_ID: 'apple-id',
      APPLE_TEAM_ID: 'team-id',
      APPLE_KEY_ID: 'key-id',
      APPLE_PRIVATE_KEY: 'private-key',
    })).toEqual(['google', 'apple']);
  });

  test('keeps a fully configured Apple provider disabled unless the flag is true', () => {
    const credentials = {
      APPLE_CLIENT_ID: 'apple-id',
      APPLE_TEAM_ID: 'team-id',
      APPLE_KEY_ID: 'key-id',
      APPLE_PRIVATE_KEY: 'private-key',
    };
    expect(configuredSocialProviderIds({ ...credentials, APPLE_SIGN_IN_ENABLED: 'false' }))
      .toEqual([]);
    expect(createSocialProviders({ ...credentials, APPLE_SIGN_IN_ENABLED: 'false' }))
      .not.toHaveProperty('apple');
    expect(socialProviderTrustedOrigins('https://openkey.test', credentials)).toEqual([
      'https://openkey.test',
    ]);
    expect(socialProviderTrustedOrigins('https://openkey.test', {
      ...credentials,
      APPLE_SIGN_IN_ENABLED: 'true',
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

  test('generates an ES256 Apple secret with client_id claims and at most five minutes of validity', async () => {
    const now = 1_800_000_000;
    const token = await generateAppleClientSecret(
      'services.openkey.test',
      'TEAM123',
      'KEY123',
      (await appleTestKey).pem.replace(/\n/g, '\\n'),
      now,
    );
    const { payload } = await jwtVerify(token, (await appleTestKey).publicKey, {
      issuer: 'TEAM123',
      audience: 'https://appleid.apple.com',
      currentDate: new Date(now * 1000),
    });

    expect(decodeProtectedHeader(token)).toMatchObject({ alg: 'ES256', kid: 'KEY123' });
    expect(payload).toMatchObject({
      iss: 'TEAM123',
      sub: 'services.openkey.test',
      aud: 'https://appleid.apple.com',
      iat: now,
    });
    expect((payload.exp ?? 0) - now).toBeGreaterThan(0);
    expect((payload.exp ?? 0) - now).toBeLessThanOrEqual(300);
  });

  test('recovers a linked Apple email without marking it verified when a later token omits email', async () => {
    const idToken = await signAppleIdToken({ sub: 'apple-user-1' });
    const lookups: string[] = [];
    const getUserInfo = await appleGetUserInfo(async (providerAccountId) => {
      lookups.push(providerAccountId);
      return {
        email: 'relay@example.test',
        name: 'Existing Apple User',
        image: null,
      };
    });

    const result = await getUserInfo({ idToken });

    expect(lookups).toEqual(['apple-user-1']);
    expect(result?.user).toMatchObject({
      id: 'apple-user-1',
      email: 'relay@example.test',
      emailVerified: false,
      name: 'Existing Apple User',
    });
  });

  for (const verified of [true, 'true'] as const) {
    test(`uses only signed verified Apple email (${String(verified)}) without a persistence lookup`, async () => {
      const idToken = await signAppleIdToken({
        sub: 'apple-user-2',
        email: 'first@example.test',
        email_verified: verified,
      });
      let lookupCalled = false;
      const getUserInfo = await appleGetUserInfo(async () => {
        lookupCalled = true;
        return null;
      });

      const result = await getUserInfo({
        idToken,
        user: {
          email: 'spoofed@example.test',
          name: { firstName: 'First', lastName: 'User' },
        },
      });

      expect(lookupCalled).toBe(false);
      expect(result?.user).toMatchObject({
        id: 'apple-user-2',
        email: 'first@example.test',
        emailVerified: true,
        name: 'First User',
      });
    });
  }

  for (const privateEmail of [true, 'true'] as const) {
    test(`normalizes signed private-email claim (${String(privateEmail)})`, async () => {
      const idToken = await signAppleIdToken({
        sub: 'relay-apple-user',
        email: 'relay@privaterelay.appleid.com',
        email_verified: true,
        is_private_email: privateEmail,
      });
      const getUserInfo = await appleGetUserInfo();

      const result = await getUserInfo({ idToken });

      expect(result?.data).toMatchObject({ is_private_email: true });
    });
  }

  test('ignores unsigned user.email when the ID token has no email', async () => {
    const idToken = await signAppleIdToken({ sub: 'unlinked-apple-user' });
    const getUserInfo = await appleGetUserInfo();

    const result = await getUserInfo({
      idToken,
      user: {
        email: 'victim@example.test',
        name: { firstName: 'Apple', lastName: 'User' },
      },
    });

    expect(result?.user).toMatchObject({
      id: 'unlinked-apple-user',
      emailVerified: false,
      name: 'Apple User',
    });
    expect(result?.user).not.toHaveProperty('email');
  });

  for (const verified of [false, 'false', undefined] as const) {
    test(`does not expose an unverified Apple email to new-account creation (${String(verified)})`, async () => {
      const idToken = await signAppleIdToken({
        sub: 'unlinked-apple-user',
        email: 'unverified@example.test',
        ...(verified === undefined ? {} : { email_verified: verified }),
      });
      const getUserInfo = await appleGetUserInfo();

      const result = await getUserInfo({ idToken });

      expect(result?.user).toMatchObject({
        id: 'unlinked-apple-user',
        emailVerified: false,
      });
      expect(result?.user).not.toHaveProperty('email');
    });
  }

  for (const [claim, options] of [
    ['issuer', { issuer: 'https://attacker.example.test' }],
    ['audience', { audience: 'other-services-id' }],
    ['expiry', { expiresAt: Math.floor(Date.now() / 1000) - 1 }],
    ['issued-at', { issuedAt: Math.floor(Date.now() / 1000) - 601 }],
  ] as const) {
    test(`rejects Apple web token with wrong ${claim}`, async () => {
      const idToken = await signAppleIdToken({
        sub: 'apple-user-3',
        email: 'signed@example.test',
        email_verified: true,
      }, options);
      const getUserInfo = await appleGetUserInfo();

      expect(await getUserInfo({ idToken })).toBeNull();
    });
  }
});

describe('Apple native token verifier (not a live sign-in endpoint)', () => {
  test('accepts an RS256 token from the injected Apple JWKS with a server-bound nonce', async () => {
    const { options, sign } = await nativeVerifierFixture();
    const token = await sign();

    expect(await verifyAppleNativeIdToken(token, options)).toMatchObject({
      sub: 'native-apple-user',
      email: 'native@example.test',
    });
  });

  for (const [claim, override] of [
    ['issuer', { issuer: 'https://attacker.example.test' }],
    ['Services ID audience', { audience: 'services.openkey.test' }],
    ['production-excluded dev bundle audience', { audience: 'xyz.tinycloud.exo.dev' }],
    ['expired token', { expiresAt: Math.floor(Date.now() / 1000) - 1 }],
    ['stale issued-at', { issuedAt: Math.floor(Date.now() / 1000) - 601 }],
    ['unknown signing kid', { kid: 'missing-key' }],
  ] as const) {
    test(`rejects native token with wrong ${claim}`, async () => {
      const { options, sign } = await nativeVerifierFixture();
      await expect(verifyAppleNativeIdToken(await sign({}, override), options)).rejects.toThrow();
    });
  }

  test('rejects native tokens without a matching server nonce', async () => {
    const { options, sign } = await nativeVerifierFixture();
    await expect(verifyAppleNativeIdToken(await sign({ nonce: undefined }), options))
      .rejects.toThrow();
    await expect(verifyAppleNativeIdToken(await sign({ nonce: 'client-chosen' }), options))
      .rejects.toThrow();
  });

  test('rejects native tokens that report nonce unsupported', async () => {
    const { options, sign } = await nativeVerifierFixture();
    await expect(verifyAppleNativeIdToken(await sign({ nonce_supported: false }), options))
      .rejects.toThrow();
  });

  test('rejects HS256 even when the JWT is correctly signed with a symmetric key', async () => {
    const { options, nonceHash } = await nativeVerifierFixture();
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({ sub: 'native-apple-user', nonce: nonceHash })
      .setProtectedHeader({ alg: 'HS256', kid: 'apple-test-key' })
      .setIssuer('https://appleid.apple.com')
      .setAudience('xyz.tinycloud.exo')
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(new TextEncoder().encode('test-only-secret-test-only-secret'));

    await expect(verifyAppleNativeIdToken(token, options)).rejects.toThrow();
  });

  test('rejects a token with alg none', async () => {
    const { options, sign } = await nativeVerifierFixture();
    const validToken = await sign();
    const [, payload] = validToken.split('.');
    const unsignedHeader = Buffer.from(JSON.stringify({ alg: 'none', kid: 'apple-test-key' }))
      .toString('base64url');

    await expect(verifyAppleNativeIdToken(`${unsignedHeader}.${payload}.`, options))
      .rejects.toThrow();
  });

  test('binds nonce consumption to the PAR request_uri and refuses replay', async () => {
    const { options, sign } = await nativeVerifierFixture();
    const token = await sign();

    await expect(verifyAppleNativeIdToken(token, {
      ...options,
      requestUri: 'urn:ietf:params:oauth:request_uri:other',
    })).rejects.toThrow();
    expect(await verifyAppleNativeIdToken(token, options)).toMatchObject({
      sub: 'native-apple-user',
    });
    await expect(verifyAppleNativeIdToken(token, options)).rejects.toThrow();
  });
});
