import { afterEach, beforeEach, expect, test } from 'bun:test';
import { mockModules } from './mock-module';

await mockModules({});
// Query-string import: each test file gets its own module instance (mock-module.ts).
const { verifyTurnstileToken, turnstileConfigProblem, TURNSTILE_ACTION } = await import('../services/turnstile?tc1632-turnstile' as string);

const env = { TURNSTILE_SECRET_KEY: 'secret-under-test' } as NodeJS.ProcessEnv;
const realFetch = globalThis.fetch;
let calls: Array<{ url: string; body: URLSearchParams }> = [];

function stubSiteverify(respond: () => Response | Promise<Response>) {
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), body: init?.body as URLSearchParams });
    return respond();
  }) as typeof fetch;
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

beforeEach(() => {
  calls = [];
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

test('a verified token for the sign-up action succeeds and posts the secret and token', async () => {
  stubSiteverify(() => json({ success: true, action: TURNSTILE_ACTION, hostname: 'openkey.so' }));
  expect(await verifyTurnstileToken('token-1', env)).toBe('success');
  expect(calls).toHaveLength(1);
  expect(calls[0]!.url).toBe('https://challenges.cloudflare.com/turnstile/v0/siteverify');
  expect(calls[0]!.body.get('secret')).toBe('secret-under-test');
  expect(calls[0]!.body.get('response')).toBe('token-1');
});

test('a verified token minted for a different action is rejected', async () => {
  stubSiteverify(() => json({ success: true, action: 'sign-in' }));
  expect(await verifyTurnstileToken('token-1', env)).toBe('rejected');
});

test('a verified token that reports no action succeeds (Cloudflare test keys do not echo action)', async () => {
  stubSiteverify(() => json({ success: true, hostname: 'example.com' }));
  expect(await verifyTurnstileToken('token-1', env)).toBe('success');
});

test('with an expected hostname set, a verified token from that hostname succeeds', async () => {
  stubSiteverify(() => json({ success: true, action: TURNSTILE_ACTION, hostname: 'openkey.so' }));
  expect(await verifyTurnstileToken('token-1', { ...env, TURNSTILE_EXPECTED_HOSTNAME: 'openkey.so' } as NodeJS.ProcessEnv)).toBe('success');
});

test('with an expected hostname set, a verified token from another hostname is rejected', async () => {
  stubSiteverify(() => json({ success: true, action: TURNSTILE_ACTION, hostname: 'example.com' }));
  expect(await verifyTurnstileToken('token-1', { ...env, TURNSTILE_EXPECTED_HOSTNAME: 'openkey.so' } as NodeJS.ProcessEnv)).toBe('rejected');
});

test('with an expected hostname set, a verified token that reports no hostname is rejected', async () => {
  stubSiteverify(() => json({ success: true, action: TURNSTILE_ACTION }));
  expect(await verifyTurnstileToken('token-1', { ...env, TURNSTILE_EXPECTED_HOSTNAME: 'openkey.so' } as NodeJS.ProcessEnv)).toBe('rejected');
});

test('a token Cloudflare refuses is rejected, not treated as unavailable', async () => {
  stubSiteverify(() => json({ success: false, 'error-codes': ['invalid-input-response'] }));
  expect(await verifyTurnstileToken('token-1', env)).toBe('rejected');
});

test('a failed check with no error codes is rejected', async () => {
  stubSiteverify(() => json({ success: false }));
  expect(await verifyTurnstileToken('token-1', env)).toBe('rejected');
});

test('a token longer than the widget limit is rejected without calling Cloudflare', async () => {
  stubSiteverify(() => json({ success: true, action: TURNSTILE_ACTION }));
  expect(await verifyTurnstileToken('t'.repeat(2049), env)).toBe('rejected');
  expect(calls).toHaveLength(0);
});

test('a token at the length limit is still sent to Cloudflare', async () => {
  stubSiteverify(() => json({ success: true, action: TURNSTILE_ACTION }));
  expect(await verifyTurnstileToken('t'.repeat(2048), env)).toBe('success');
  expect(calls).toHaveLength(1);
});

test('an error code this service does not recognise is a rejection, not unavailable', async () => {
  stubSiteverify(() => json({ success: false, 'error-codes': ['something-new'] }));
  expect(await verifyTurnstileToken('token-1', env)).toBe('rejected');
});

test('a missing or invalid secret on our side is unavailable, not a visitor failure', async () => {
  stubSiteverify(() => json({ success: false, 'error-codes': ['invalid-input-secret'] }));
  expect(await verifyTurnstileToken('token-1', env)).toBe('unavailable');
  stubSiteverify(() => json({ success: false, 'error-codes': ['missing-input-secret'] }));
  expect(await verifyTurnstileToken('token-1', env)).toBe('unavailable');
});

test('no configured secret is unavailable without calling Cloudflare', async () => {
  stubSiteverify(() => json({ success: true, action: TURNSTILE_ACTION }));
  expect(await verifyTurnstileToken('token-1', {} as NodeJS.ProcessEnv)).toBe('unavailable');
  expect(calls).toHaveLength(0);
});

test('a network failure is unavailable', async () => {
  stubSiteverify(() => {
    throw new TypeError('fetch failed');
  });
  expect(await verifyTurnstileToken('token-1', env)).toBe('unavailable');
});

test('an HTTP error from Cloudflare is unavailable', async () => {
  stubSiteverify(() => json({ success: false }, 503));
  expect(await verifyTurnstileToken('token-1', env)).toBe('unavailable');
});

test('a non-JSON response is unavailable', async () => {
  stubSiteverify(() => new Response('<html>', { status: 200 }));
  expect(await verifyTurnstileToken('token-1', env)).toBe('unavailable');
});

// Production: a published test secret would accept any token, so it is refused before any request.
test('production refuses a published Cloudflare test secret without calling Cloudflare', async () => {
  const prodTestSecret = { TURNSTILE_SECRET_KEY: '1x0000000000000000000000000000000AA', TURNSTILE_EXPECTED_HOSTNAME: 'openkey.so', NODE_ENV: 'production' } as NodeJS.ProcessEnv;
  stubSiteverify(() => json({ success: true, action: TURNSTILE_ACTION, hostname: 'openkey.so' }));
  expect(await verifyTurnstileToken('token-1', prodTestSecret)).toBe('unavailable');
  expect(calls).toHaveLength(0);
});

test('production without an expected hostname is unavailable without calling Cloudflare', async () => {
  const prodNoHost = { TURNSTILE_SECRET_KEY: 'secret-under-test', NODE_ENV: 'production' } as NodeJS.ProcessEnv;
  stubSiteverify(() => json({ success: true, action: TURNSTILE_ACTION, hostname: 'openkey.so' }));
  expect(await verifyTurnstileToken('token-1', prodNoHost)).toBe('unavailable');
  expect(calls).toHaveLength(0);
});

test('production requires the sign-up action: an absent action is rejected', async () => {
  const prod = { TURNSTILE_SECRET_KEY: 'secret-under-test', TURNSTILE_EXPECTED_HOSTNAME: 'openkey.so', NODE_ENV: 'production' } as NodeJS.ProcessEnv;
  stubSiteverify(() => json({ success: true, hostname: 'openkey.so' }));
  expect(await verifyTurnstileToken('token-1', prod)).toBe('rejected');
});

test('production rejects a token issued for another hostname', async () => {
  const prod = { TURNSTILE_SECRET_KEY: 'secret-under-test', TURNSTILE_EXPECTED_HOSTNAME: 'openkey.so', NODE_ENV: 'production' } as NodeJS.ProcessEnv;
  stubSiteverify(() => json({ success: true, action: TURNSTILE_ACTION, hostname: 'evil.example' }));
  expect(await verifyTurnstileToken('token-1', prod)).toBe('rejected');
});

test('an over-long token is rejected without calling Cloudflare', async () => {
  stubSiteverify(() => json({ success: true, action: TURNSTILE_ACTION }));
  expect(await verifyTurnstileToken('x'.repeat(2049), env)).toBe('rejected');
  expect(calls).toHaveLength(0);
});

test('bad-request from Cloudflare is a visitor failure, not an unavailable check', async () => {
  stubSiteverify(() => json({ success: false, 'error-codes': ['bad-request'] }));
  expect(await verifyTurnstileToken('token-1', env)).toBe('rejected');
});

test('each siteverify call carries an idempotency key', async () => {
  stubSiteverify(() => json({ success: true, action: TURNSTILE_ACTION }));
  await verifyTurnstileToken('token-1', env);
  expect(calls[0]!.body.get('idempotency_key')).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
});

test('the client address is forwarded as remoteip only when known', async () => {
  stubSiteverify(() => json({ success: true, action: TURNSTILE_ACTION }));
  await verifyTurnstileToken('token-1', env, '203.0.113.7');
  expect(calls[0]!.body.get('remoteip')).toBe('203.0.113.7');
  await verifyTurnstileToken('token-2', env);
  expect(calls[1]!.body.get('remoteip')).toBeNull();
});

test('the boot check reports a missing secret, a refused test secret, and a missing production hostname', () => {
  expect(turnstileConfigProblem({} as NodeJS.ProcessEnv)).toBe('missing_secret');
  expect(turnstileConfigProblem({ TURNSTILE_SECRET_KEY: 'secret-under-test' } as NodeJS.ProcessEnv)).toBeNull();
  expect(
    turnstileConfigProblem({ TURNSTILE_SECRET_KEY: '2x0000000000000000000000000000000AA', NODE_ENV: 'production' } as NodeJS.ProcessEnv),
  ).toBe('test_secret');
  expect(turnstileConfigProblem({ TURNSTILE_SECRET_KEY: 'secret-under-test', NODE_ENV: 'production' } as NodeJS.ProcessEnv)).toBe('missing_hostname');
  expect(
    turnstileConfigProblem({ TURNSTILE_SECRET_KEY: 'secret-under-test', TURNSTILE_EXPECTED_HOSTNAME: 'openkey.so', NODE_ENV: 'production' } as NodeJS.ProcessEnv),
  ).toBeNull();
});
