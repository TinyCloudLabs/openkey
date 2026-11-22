import { describe, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { emailOTP } from 'better-auth/plugins';
import { EMAIL_OTP_ADDRESS_LIMIT_OFF, mountEmailOtpRateLimit } from '../middleware/email-otp-rate-limit';

const ORIGIN = 'https://api.test';
const SEND = '/api/auth/email-otp/send-verification-otp';
const LIMITED_PATHS: Array<[string, number, Record<string, string>]> = [
  [SEND, 3, { type: 'sign-in' }],
  ['/api/auth/email-otp/check-verification-otp', 10, { type: 'sign-in', otp: '000000' }],
  ['/api/auth/email-otp/verify-email', 10, { otp: '000000' }],
  ['/api/auth/sign-in/email-otp', 10, { otp: '000000' }],
];

function post(path: string, body: Record<string, string>, forwardedFor?: string): Request {
  const headers: Record<string, string> = { 'content-type': 'application/json', origin: ORIGIN };
  if (forwardedFor) headers['x-forwarded-for'] = forwardedFor;
  return new Request(`${ORIGIN}${path}`, { method: 'POST', headers, body: JSON.stringify(body) });
}

/** Assembled the way index.ts does it: the limiter is mounted, then the auth handler is registered. */
function assembled(nodeEnv: string | undefined) {
  const handled: string[] = [];
  const app = new Hono();
  mountEmailOtpRateLimit(app, nodeEnv, () => 1_700_000_000_000);
  app.on(['POST', 'GET'], '/api/auth/*', (c) => {
    handled.push(new URL(c.req.url).pathname);
    return c.json({ success: true });
  });
  return { app, handled };
}

describe('mounting the email-code limiter', () => {
  test('with NODE_ENV=production every email-code path is limited before the auth handler', async () => {
    for (const [path, max, fields] of LIMITED_PATHS) {
      const { app, handled } = assembled('production');
      const statuses: number[] = [];
      let last: Response | undefined;
      for (let attempt = 0; attempt <= max; attempt += 1) {
        last = await app.fetch(post(path, { email: 'mounted@example.test', ...fields }, `203.0.113.${attempt}`));
        statuses.push(last.status);
      }
      expect(statuses, path).toEqual([...Array(max).fill(200), 429]);
      expect(last!.headers.get('X-Retry-After'), path).toBe('60');
      expect(await last!.text(), path).toBe('{"message":"Too many requests. Please try again later."}');
      // The refused request never reached the handler.
      expect(handled, path).toEqual(Array(max).fill(path));
    }
  });

  test('outside production the email-code paths are not limited', async () => {
    for (const nodeEnv of ['test', 'development', undefined]) {
      const { app, handled } = assembled(nodeEnv);
      for (let attempt = 0; attempt < 12; attempt += 1) {
        const response = await app.fetch(post(SEND, { email: 'unmounted@example.test', type: 'sign-in' }));
        expect(response.status, String(nodeEnv)).toBe(200);
      }
      expect(handled).toHaveLength(12);
    }
  });

  test('with NODE_ENV=production a refused send reaches neither Better Auth nor the mailer', async () => {
    const mailed: string[] = [];
    const auth = betterAuth({
      baseURL: `${ORIGIN}/api/auth`,
      secret: 'better-auth-secret-that-is-long-enough-for-a-runtime-test',
      database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
      logger: { disabled: true },
      rateLimit: { enabled: true, customRules: EMAIL_OTP_ADDRESS_LIMIT_OFF },
      plugins: [emailOTP({ sendVerificationOTP: async ({ email }) => { mailed.push(email); } })],
    });
    const app = new Hono();
    mountEmailOtpRateLimit(app, 'production', () => 1_700_000_000_000);
    app.on(['POST', 'GET'], '/api/auth/*', (c) => auth.handler(c.req.raw));

    const statuses: number[] = [];
    for (let attempt = 0; attempt < 4; attempt += 1) {
      statuses.push((await app.fetch(post(SEND, { email: 'mailer@example.test', type: 'sign-in' }))).status);
    }
    expect(statuses).toEqual([200, 200, 200, 429]);
    expect(mailed).toEqual(Array(3).fill('mailer@example.test'));
  });
});
