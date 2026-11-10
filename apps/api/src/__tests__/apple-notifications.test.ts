import { describe, expect, spyOn, test } from 'bun:test';
import { Hono } from 'hono';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';
import {
  appleEmailTransition,
  appleEventTimeMs,
  appleWebhookAudience,
  createAppleWebhookHandler,
  isStaleAppleRevocation,
  verifyAppleNotification,
} from '../services/apple-notifications';
import { APPLE_REVOKE_RETRIES, revokeStoredAppleTokens } from '../services/apple-revocation';

const AUDIENCE = 'so.openkey';
const KID = 'apple-notification-test';
const keys = (async () => {
  const apple = await generateKeyPair('RS256', { extractable: true });
  const other = await generateKeyPair('RS256', { extractable: true });
  const jwk: JWK = { ...await exportJWK(apple.publicKey), kid: KID, alg: 'RS256', use: 'sig' };
  return { apple, other, jwks: createLocalJWKSet({ keys: [jwk] }) };
})();

const nowSeconds = () => Math.floor(Date.now() / 1000);

async function notification(
  events: unknown,
  options: { issuer?: string; audience?: string; iat?: number; jti?: string | null; key?: 'apple' | 'other'; kid?: string } = {},
) {
  const { apple, other } = await keys;
  const jwt = new SignJWT({ events, ...(options.jti === null ? {} : { jti: options.jti ?? crypto.randomUUID() }) })
    .setProtectedHeader({ alg: 'RS256', kid: options.kid ?? KID })
    .setIssuer(options.issuer ?? 'https://appleid.apple.com')
    .setAudience(options.audience ?? AUDIENCE)
    .setIssuedAt(options.iat ?? nowSeconds());
  return jwt.sign(options.key === 'other' ? other.privateKey : apple.privateKey);
}

async function verify(payload: unknown) {
  return verifyAppleNotification(payload, { jwks: (await keys).jwks, audience: AUDIENCE });
}

const event = (type: string, overrides: Record<string, unknown> = {}) => ({
  type, sub: 'apple-sub', event_time: nowSeconds(), ...overrides,
});

describe('Apple notification JWS verification', () => {
  test('accepts Apple\'s documented payload with events as a JSON string, in seconds', async () => {
    const at = nowSeconds();
    const verified = await verify(await notification(JSON.stringify({ type: 'consent-revoked', sub: 's1', event_time: at }), { jti: 'j1' }));
    expect(verified).toEqual({ jti: 'j1', rawType: 'consent-revoked', type: 'consent-revoked', sub: 's1', eventTimeMs: at * 1000 });
  });

  test('accepts events as an object and event_time in milliseconds', async () => {
    const ms = Date.now();
    const verified = await verify(await notification(event('email-disabled', { event_time: ms })));
    expect(verified?.type).toBe('email-disabled');
    expect(verified?.eventTimeMs).toBe(ms);
  });

  test.each(['account-deleted', 'account-delete'])('normalises %s to account-deleted', async (type) => {
    const verified = await verify(await notification(event(type)));
    expect(verified?.type).toBe('account-deleted');
    expect(verified?.rawType).toBe(type);
  });

  test('an unknown type verifies but is not acted on', async () => {
    expect((await verify(await notification(event('something-new'))))?.type).toBeNull();
  });

  test.each([
    ['another signing key', { key: 'other' as const }],
    ['an unknown kid', { kid: 'unknown-kid' }],
    ['a wrong issuer', { issuer: 'https://evil.example' }],
    ['a wrong audience (the Services ID)', { audience: 'so.openkey.signin' }],
    ['an iat older than 24 hours', { iat: nowSeconds() - 24 * 3600 - 60 }],
    ['an iat in the future', { iat: nowSeconds() + 3600 }],
    ['no jti', { jti: null }],
  ])('rejects %s', async (_name, options) => {
    expect(await verify(await notification(event('consent-revoked'), options))).toBeNull();
  });

  test('rejects alg none and HS256 tokens', async () => {
    const body = Buffer.from(JSON.stringify({
      iss: 'https://appleid.apple.com', aud: AUDIENCE, iat: nowSeconds(), jti: 'x', events: event('consent-revoked'),
    })).toString('base64url');
    const none = `${Buffer.from(JSON.stringify({ alg: 'none', kid: KID })).toString('base64url')}.${body}.`;
    expect(await verify(none)).toBeNull();
    const hs = await new SignJWT({ jti: 'x', events: event('consent-revoked') })
      .setProtectedHeader({ alg: 'HS256', kid: KID })
      .setIssuer('https://appleid.apple.com').setAudience(AUDIENCE).setIssuedAt()
      .sign(new TextEncoder().encode('shared-secret-shared-secret-shared'));
    expect(await verify(hs)).toBeNull();
  });

  test.each([
    ['event_time more than a day before iat', { event_time: nowSeconds() - 24 * 3600 - 60 }],
    ['event_time more than a day after iat (milliseconds)', { event_time: Date.now() + 24 * 3600_000 + 60_000 }],
    ['a missing event_time', { event_time: undefined }],
    ['a missing sub', { sub: undefined }],
  ])('rejects %s', async (_name, overrides) => {
    expect(await verify(await notification(event('consent-revoked', overrides)))).toBeNull();
  });

  test('rejects events that are not an object', async () => {
    expect(await verify(await notification('not json'))).toBeNull();
    expect(await verify(await notification([event('consent-revoked')]))).toBeNull();
    expect(await verify('not-a-jws')).toBeNull();
    expect(await verify(undefined)).toBeNull();
  });
});

describe('Apple notification ordering', () => {
  test('event_time below 1e12 is seconds, otherwise milliseconds', () => {
    expect(appleEventTimeMs(1508184845)).toBe(1508184845000);
    expect(appleEventTimeMs(1508184845123)).toBe(1508184845123);
    expect(appleEventTimeMs('1508184845')).toBe(1508184845000);
    expect(appleEventTimeMs(-1)).toBeNull();
    expect(appleEventTimeMs(1.5)).toBeNull();
  });

  test('a revocation before the latest restoration is stale; equal or later applies', () => {
    const restored = new Date(1_700_000_000_000);
    expect(isStaleAppleRevocation(restored, restored.getTime() - 1)).toBe(true);
    expect(isStaleAppleRevocation(restored, restored.getTime())).toBe(false);
    expect(isStaleAppleRevocation(null, 1)).toBe(false);
  });

  test('email events follow their own watermark; at equal time disabled wins in either order', () => {
    const t = 1_700_000_000_000;
    const initial = { appleEmailEventAt: null, appleEmailUndeliverable: false };
    const disabledFirst = appleEmailTransition(initial, true, t)!;
    expect(disabledFirst.appleEmailUndeliverable).toBe(true);
    expect(appleEmailTransition(disabledFirst, false, t)).toBeNull();

    const enabledFirst = appleEmailTransition(initial, false, t)!;
    expect(enabledFirst.appleEmailUndeliverable).toBe(false);
    expect(appleEmailTransition(enabledFirst, true, t)?.appleEmailUndeliverable).toBe(true);

    expect(appleEmailTransition(disabledFirst, false, t + 1)?.appleEmailUndeliverable).toBe(false);
    expect(appleEmailTransition(disabledFirst, false, t - 1)).toBeNull();
  });
});

describe('Apple webhook endpoint', () => {
  const env = {
    APPLE_SIGN_IN_ENABLED: 'true', APPLE_CLIENT_ID: 'so.openkey.signin', APPLE_TEAM_ID: 'TEAM',
    APPLE_KEY_ID: 'KEY', APPLE_PRIVATE_KEY: 'unused', APPLE_WEBHOOK_AUDIENCE: AUDIENCE,
  };

  test('is configured only with Apple sign-in enabled and an audience', () => {
    expect(appleWebhookAudience(env)).toBe(AUDIENCE);
    expect(appleWebhookAudience({ ...env, APPLE_SIGN_IN_ENABLED: 'false' })).toBeNull();
    expect(appleWebhookAudience({ ...env, APPLE_WEBHOOK_AUDIENCE: '' })).toBeNull();
    expect(appleWebhookAudience({ ...env, APPLE_KEY_ID: '' })).toBeNull();
  });

  async function app(environment: NodeJS.ProcessEnv) {
    const processed: unknown[] = [];
    const database = { $transaction: async () => { processed.push(true); return 'revoked'; } };
    const router = new Hono();
    router.post('/api/webhooks/apple', createAppleWebhookHandler({
      database: database as never, jwks: (await keys).jwks, env: environment,
    }));
    return { router, processed };
  }
  const post = (router: Hono, body: unknown) => router.request('/api/webhooks/apple', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });

  test('is not found while Apple is disabled, without reading the body', async () => {
    const { router, processed } = await app({ ...env, APPLE_SIGN_IN_ENABLED: 'false' });
    expect((await post(router, { payload: await notification(event('consent-revoked')) })).status).toBe(404);
    expect(processed).toHaveLength(0);
  });

  test('answers 400 for a bad signature and 200 after processing a valid one', async () => {
    const { router, processed } = await app(env);
    expect((await post(router, { payload: await notification(event('consent-revoked'), { key: 'other' }) })).status).toBe(400);
    expect((await post(router, { nope: true })).status).toBe(400);
    expect(processed).toHaveLength(0);
    expect((await post(router, { payload: await notification(event('consent-revoked')) })).status).toBe(200);
    expect(processed).toHaveLength(1);
  });
});

describe('stored Apple token revocation', () => {
  test('retries a failing revoke three times, then logs without the token, and never throws', async () => {
    const calls: Array<[string, string]> = [];
    const writes: string[] = [];
    const stdout = spyOn(process.stdout, 'write').mockImplementation(((chunk: string) => { writes.push(String(chunk)); return true; }) as never);
    try {
      const failures = await revokeStoredAppleTokens([
        { refreshToken: 'encrypted-a', appleClientId: 'so.openkey.signin' },
        { refreshToken: 'encrypted-b', appleClientId: 'xyz.tinycloud.home' },
      ], {
        decrypt: async (data) => `plain-${data}`,
        revoke: async (token, clientId) => { calls.push([token!, clientId!]); return token === 'plain-encrypted-b'; },
        sleep: async () => {},
      });
      expect(failures).toBe(1);
    } finally {
      stdout.mockRestore();
    }
    expect(calls.filter(([token]) => token === 'plain-encrypted-a')).toHaveLength(1 + APPLE_REVOKE_RETRIES);
    expect(calls).toContainEqual(['plain-encrypted-b', 'xyz.tinycloud.home']);
    const failure = writes.filter((line) => line.includes('auth_apple_revoke_failed'));
    expect(failure).toHaveLength(1);
    expect(failure[0]).not.toContain('plain-encrypted-a');
    expect(failure[0]).not.toContain('encrypted-a');
  });

  test('a token with no stored issuing client is reported, not sent', async () => {
    let sent = 0;
    const stdout = spyOn(process.stdout, 'write').mockImplementation((() => true) as never);
    try {
      expect(await revokeStoredAppleTokens([{ refreshToken: 'x', appleClientId: null }], {
        decrypt: async () => 'plain', revoke: async () => { sent += 1; return true; }, sleep: async () => {},
      })).toBe(1);
    } finally {
      stdout.mockRestore();
    }
    expect(sent).toBe(0);
  });
});
