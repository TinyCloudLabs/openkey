import { describe, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { emailOTP } from 'better-auth/plugins';
import { EMAIL_OTP_ADDRESS_LIMIT_OFF, mountEmailOtpRateLimit } from '../middleware/email-otp-rate-limit';

const ORIGIN = 'https://api.test';
const SEND = '/api/auth/email-otp/send-verification-otp';
const LIMITED_PATHS = [
  SEND,
  '/api/auth/email-otp/check-verification-otp',
  '/api/auth/email-otp/verify-email',
  '/api/auth/sign-in/email-otp',
];

function realAuth() {
  const mailed: string[] = [];
  const auth = betterAuth({
    baseURL: `${ORIGIN}/api/auth`,
    secret: 'better-auth-secret-that-is-long-enough-for-a-runtime-test',
    database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
    logger: { disabled: true },
    rateLimit: { enabled: true, customRules: EMAIL_OTP_ADDRESS_LIMIT_OFF },
    plugins: [emailOTP({ sendVerificationOTP: async ({ email }) => { mailed.push(email); } })],
  });
  return { auth, mailed };
}

/** The production assembly: the limiter, then Better Auth's handler, which records every request it receives. */
function assembled() {
  const { auth, mailed } = realAuth();
  const handled: string[] = [];
  const app = new Hono();
  mountEmailOtpRateLimit(app, 'production', () => 1_700_000_000_000);
  app.on(['POST', 'GET'], '/api/auth/*', (c) => {
    handled.push(new URL(c.req.url).pathname);
    return auth.handler(c.req.raw);
  });
  return { app, auth, handled, mailed };
}

function request(path: string, contentType: string | null, body: string): Request {
  const headers: Record<string, string> = { origin: ORIGIN };
  if (contentType !== null) headers['content-type'] = contentType;
  return new Request(`${ORIGIN}${path}`, { method: 'POST', headers, body });
}

const JSON_BODY = JSON.stringify({ email: 'shape@example.test', type: 'sign-in', otp: '000000' });
const FORM_BODY = 'email=shape%40example.test&type=sign-in&otp=000000';
const NOT_JSON: Array<[string | null, string]> = [
  ['application/x-www-form-urlencoded', FORM_BODY],
  ['multipart/form-data; boundary=x', FORM_BODY],
  ['text/plain', JSON_BODY],
  [null, FORM_BODY],
  // Better Auth's router admits this (its base contains application/json) and parses the body as a form.
  ['text/application/json; x=application/x-www-form-urlencoded', FORM_BODY],
];

describe('email-code limiter and request bodies that are not JSON', () => {
  test('a non-JSON body on any limited path is refused before Better Auth, however often it is sent', async () => {
    const { app, handled, mailed } = assembled();
    for (const path of LIMITED_PATHS) {
      for (const [contentType, body] of NOT_JSON) {
        for (let attempt = 0; attempt < 12; attempt += 1) {
          const response = await app.fetch(request(path, contentType, body));
          expect(response.status, `${path} ${contentType}`).toBe(415);
        }
      }
    }
    expect(handled).toEqual([]);
    expect(mailed).toEqual([]);
  });

  test('the refusal matches Better Auth\'s own answer to a body that is not JSON', async () => {
    const { app } = assembled();
    const { auth } = realAuth();
    for (const [contentType, body] of NOT_JSON.slice(0, 4)) {
      const ours = await app.fetch(request(SEND, contentType, body));
      const theirs = await auth.handler(request(SEND, contentType, body));
      expect(theirs.status).toBe(415);
      expect(ours.status).toBe(theirs.status);
      expect(ours.statusText).toBe(theirs.statusText);
      expect(ours.headers.get('content-type')).toBe(theirs.headers.get('content-type'));
      expect(await ours.text()).toBe(await theirs.text());
    }
  });

  test('a JSON body with a charset parameter is accepted and counted', async () => {
    const { app, mailed } = assembled();
    const statuses = [];
    for (let attempt = 0; attempt < 4; attempt += 1) {
      statuses.push((await app.fetch(request(SEND, 'Application/JSON; charset=utf-8', JSON_BODY))).status);
    }
    expect(statuses).toEqual([200, 200, 200, 429]);
    expect(mailed).toHaveLength(3);
  });
});

describe('email-code limiter and path variants', () => {
  test('variants Better Auth does not route never reach an email-code endpoint', async () => {
    const { app, handled, mailed } = assembled();
    const variants = [
      '/api/auth//email-otp/send-verification-otp',
      '/api/auth/email-otp//send-verification-otp',
      '/api/auth/email-otp%2Fsend-verification-otp',
      '/api/auth/email-otp%2fsend-verification-otp',
      '/api/auth/EMAIL-OTP/send-verification-otp',
      '/api/auth/email-otp/Send-Verification-OTP',
      '/API/AUTH/email-otp/send-verification-otp',
      '/api/auth/email-otp/send-verification-%6ftp',
      '/api/auth/email-otp/send-verification-otp;x',
      '/api/auth//sign-in/email-otp',
      '/api/auth/SIGN-IN/email-otp',
      '/api/auth/sign-in%2Femail-otp',
    ];
    for (const variant of variants) {
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const status = (await app.fetch(request(variant, 'application/json', JSON_BODY))).status;
        // 404 from the router, or Better Auth's address limit on `/sign-in*` (3 per 10 s) answering first; an
        // endpoint would have answered 200 (send) or 400 (wrong code).
        expect([404, 429], variant).toContain(status);
      }
    }
    expect(mailed).toEqual([]);
    // Hono itself does not route the upper-case base path to Better Auth.
    expect(handled).not.toContain('/API/AUTH/email-otp/send-verification-otp');
  });

  test('a trailing slash and dot segments are counted against the same keys as the canonical path', async () => {
    const { app, mailed } = assembled();
    // Better Auth answers 404 to the trailing slash, but the attempt still counts.
    expect((await app.fetch(request(`${SEND}/`, 'application/json', JSON_BODY))).status).toBe(404);
    // The URL parser resolves dot segments before either Hono or Better Auth sees the path.
    expect((await app.fetch(request('/api/auth/x/../email-otp/send-verification-otp', 'application/json', JSON_BODY))).status).toBe(200);
    expect((await app.fetch(request(SEND, 'application/json', JSON_BODY))).status).toBe(200);
    expect((await app.fetch(request('/api/auth/x/%2e%2e/email-otp/send-verification-otp', 'application/json', JSON_BODY))).status).toBe(429);
    expect((await app.fetch(request(SEND, 'application/json', JSON_BODY))).status).toBe(429);
    expect(mailed).toHaveLength(2);
  });
});
