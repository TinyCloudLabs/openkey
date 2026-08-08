import { describe, expect, test } from 'bun:test';
import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { parseSetCookieHeader } from 'better-auth/cookies';
import { crossSubDomainCookieOptions } from '../auth-options';
import { socialProviderTrustedOrigins } from '../social-providers';

describe('production console session options', () => {
  test('shares API-issued sessions with both production browser surfaces', () => {
    expect(crossSubDomainCookieOptions(false)).toEqual({
      enabled: true,
      domain: '.openkey.so',
    });
    expect(socialProviderTrustedOrigins('https://openkey.so', {
      CORS_ORIGIN: 'https://openkey.so',
      TEE_MODE: 'production',
    })).toContain('https://console.openkey.so');
  });

  test('does not apply the production domain attribute to local development', () => {
    expect(crossSubDomainCookieOptions(true)).toEqual({ enabled: false });
  });

  test('keeps an account-host session valid when the console host calls the API', async () => {
    const auth = betterAuth({
      baseURL: 'https://api.openkey.so/api/auth',
      secret: 'better-auth-secret-that-is-long-enough-for-a-runtime-test',
      database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
      emailAndPassword: { enabled: true },
      trustedOrigins: socialProviderTrustedOrigins('https://openkey.so', {
        CORS_ORIGIN: 'https://openkey.so',
        TEE_MODE: 'production',
      }),
      advanced: {
        crossSubDomainCookies: crossSubDomainCookieOptions(false),
      },
    });

    const signUpResponse = await auth.handler(new Request('https://api.openkey.so/api/auth/sign-up/email', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'https://openkey.so',
      },
      body: JSON.stringify({
        name: 'Runtime Test',
        email: 'runtime@example.test',
        password: 'correct horse battery staple',
      }),
    }));
    const sessionCookieName = '__Secure-better-auth.session_token';
    const sessionCookie = parseSetCookieHeader(signUpResponse.headers.get('set-cookie') ?? '')
      .get(sessionCookieName);

    expect(signUpResponse.status).toBe(200);
    expect(sessionCookie?.domain).toBe('.openkey.so');
    expect(sessionCookie?.secure).toBe(true);

    const consoleSessionResponse = await auth.handler(new Request('https://api.openkey.so/api/auth/get-session', {
      headers: {
        cookie: `${sessionCookieName}=${sessionCookie?.value}`,
        origin: 'https://console.openkey.so',
      },
    }));

    expect(consoleSessionResponse.status).toBe(200);
    expect((await consoleSessionResponse.json()).user.email).toBe('runtime@example.test');
  });
});
