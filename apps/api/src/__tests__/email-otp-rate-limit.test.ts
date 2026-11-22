import { describe, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { emailOTP } from 'better-auth/plugins';
import { createEmailOtpRateLimit, EMAIL_OTP_ADDRESS_LIMIT_OFF } from '../middleware/email-otp-rate-limit';

const ORIGIN = 'https://api.test';
const SEND = '/api/auth/email-otp/send-verification-otp';
const SIGN_IN = '/api/auth/sign-in/email-otp';

function clock(start = 1_700_000_000_000) {
  let at = start;
  return { now: () => at, advance: (seconds: number) => { at += seconds * 1000; } };
}

/** The limiter in front of a handler that records each request it receives. */
function limitedApp(now: () => number) {
  const received: Array<{ path: string; email: unknown }> = [];
  const app = new Hono();
  app.use('/api/auth/*', createEmailOtpRateLimit({ basePath: '/api/auth', now }));
  app.post('/api/auth/*', async (c) => {
    const body = await c.req.json<{ email?: unknown }>().catch(() => null);
    received.push({ path: new URL(c.req.url).pathname, email: body?.email });
    return c.json({ success: true });
  });
  return { app, received };
}

function post(path: string, body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(`${ORIGIN}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: ORIGIN, ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

function send(app: Hono, email: unknown, headers: Record<string, string> = {}) {
  return app.fetch(post(SEND, { email, type: 'sign-in' }, headers));
}

function authWith(rateLimit: Parameters<typeof betterAuth>[0]['rateLimit'], users: Array<Record<string, unknown>> = []) {
  return betterAuth({
    baseURL: `${ORIGIN}/api/auth`,
    secret: 'better-auth-secret-that-is-long-enough-for-a-runtime-test',
    database: memoryAdapter({ user: users, session: [], account: [], verification: [] }),
    logger: { disabled: true },
    rateLimit,
    plugins: [emailOTP({ sendVerificationOTP: async () => {} })],
  });
}

describe('email-code rate limit keyed on the target email', () => {
  test('rotating or omitting x-forwarded-for does not get past the per-email limit', async () => {
    const { app, received } = limitedApp(clock().now);
    const statuses = [];
    const headerSets: Array<Record<string, string>> = [{ 'x-forwarded-for': '203.0.113.1' }, { 'x-forwarded-for': '203.0.113.2, 10.0.0.1' }, {}, { 'x-forwarded-for': '203.0.113.4' }];
    for (const headers of headerSets) {
      statuses.push((await send(app, 'person@example.test', headers)).status);
    }
    expect(statuses).toEqual([200, 200, 200, 429]);
    expect(received).toHaveLength(3);
  });

  test('many emails from one address and one header all pass', async () => {
    const { app } = limitedApp(clock().now);
    for (let index = 0; index < 50; index += 1) {
      const response = await send(app, `person${index}@example.test`, { 'x-forwarded-for': '198.51.100.9' });
      expect(response.status).toBe(200);
    }
  });

  test('case and surrounding whitespace variants of one email share a key', async () => {
    const { app, received } = limitedApp(clock().now);
    const statuses = [];
    for (const email of ['Person@Example.test', 'person@example.test ', ' PERSON@EXAMPLE.TEST', 'person@example.test']) {
      statuses.push((await send(app, email)).status);
    }
    expect(statuses).toEqual([200, 200, 200, 429]);
    // Better Auth receives the body exactly as sent.
    expect(received.map(({ email }) => email)).toEqual(['Person@Example.test', 'person@example.test ', ' PERSON@EXAMPLE.TEST']);
  });

  test('one email gets at most 10 sends an hour, and recovers after the hour', async () => {
    const time = clock();
    const { app } = limitedApp(time.now);
    let accepted = 0;
    for (let minute = 0; minute < 6; minute += 1) {
      for (let attempt = 0; attempt < 3; attempt += 1) {
        if ((await send(app, 'hourly@example.test')).status === 200) accepted += 1;
      }
      time.advance(61);
    }
    expect(accepted).toBe(10);
    const refused = await send(app, 'hourly@example.test');
    expect(refused.status).toBe(429);
    expect(Number(refused.headers.get('X-Retry-After'))).toBeGreaterThan(60);
    time.advance(60 * 60);
    expect((await send(app, 'hourly@example.test')).status).toBe(200);
  });

  test('sign-in attempts are limited per email on their own counter', async () => {
    const { app } = limitedApp(clock().now);
    for (let attempt = 0; attempt < 3; attempt += 1) expect((await send(app, 'both@example.test')).status).toBe(200);
    const statuses = [];
    for (let attempt = 0; attempt < 11; attempt += 1) {
      statuses.push((await app.fetch(post(SIGN_IN, { email: 'both@example.test', otp: '000000' }, { 'x-forwarded-for': `203.0.113.${attempt}` }))).status);
    }
    expect(statuses).toEqual([...Array(10).fill(200), 429]);
  });

  test('the shared ceiling refuses a new email once reached and recovers after the window', async () => {
    const time = clock();
    const { app } = limitedApp(time.now);
    for (let index = 0; index < 120; index += 1) {
      expect((await send(app, `ceiling${index}@example.test`)).status).toBe(200);
    }
    const refused = await send(app, 'fresh@example.test', { 'x-forwarded-for': '192.0.2.77' });
    expect(refused.status).toBe(429);
    expect(refused.headers.get('X-Retry-After')).toBe('60');
    time.advance(60);
    expect((await send(app, 'fresh@example.test')).status).toBe(200);
  });

  test('a body without a usable email counts only against the shared ceiling and reaches the handler', async () => {
    const time = clock();
    const { app, received } = limitedApp(time.now);
    for (let index = 0; index < 5; index += 1) {
      expect((await app.fetch(post(SEND, 'not json'))).status).toBe(200);
      expect((await send(app, 42)).status).toBe(200);
    }
    expect(received).toHaveLength(10);
    for (let index = 0; index < 110; index += 1) await app.fetch(post(SEND, {}));
    expect((await send(app, 'new@example.test')).status).toBe(429);
  });

  test('the refusal is Better Auth\'s own 429, the same for an email with and without an account', async () => {
    // Better Auth's limiter with its defaults, reached from one address.
    const plain = authWith({ enabled: true });
    let native: Response | undefined;
    for (let attempt = 0; attempt < 4; attempt += 1) {
      native = await plain.handler(post(SEND, { email: 'native@example.test', type: 'sign-in' }, { 'x-forwarded-for': '198.51.100.250' }));
    }
    expect(native!.status).toBe(429);

    const now = new Date();
    const auth = authWith({ enabled: true, customRules: EMAIL_OTP_ADDRESS_LIMIT_OFF }, [
      { id: 'user-1', email: 'member@example.test', name: 'Member', emailVerified: true, createdAt: now, updatedAt: now },
    ]);
    const app = new Hono();
    app.use('/api/auth/*', createEmailOtpRateLimit({ basePath: '/api/auth', now: clock().now }));
    app.on(['POST', 'GET'], '/api/auth/*', (c) => auth.handler(c.req.raw));

    const fourth = async (email: string) => {
      let response: Response | undefined;
      for (let attempt = 0; attempt < 4; attempt += 1) response = await send(app, email);
      return response!;
    };
    const member = await fourth('member@example.test');
    const stranger = await fourth('stranger@example.test');

    for (const response of [member, stranger]) {
      expect(response.status).toBe(native!.status);
      expect(response.statusText).toBe(native!.statusText);
      expect(response.headers.get('content-type')).toBe(native!.headers.get('content-type'));
      expect(response.headers.get('X-Retry-After')).toBe('60');
    }
    const nativeBody = await native!.text();
    expect(nativeBody).toBe('{"message":"Too many requests. Please try again later."}');
    expect(await member.text()).toBe(nativeBody);
    expect(await stranger.text()).toBe(nativeBody);
  });
});

describe('Better Auth address-keyed limit on the email-code endpoints', () => {
  test('is off: sends from one shared address are never refused by it', async () => {
    const auth = authWith({ enabled: true, customRules: EMAIL_OTP_ADDRESS_LIMIT_OFF });
    for (let index = 0; index < 8; index += 1) {
      // No x-forwarded-for: every caller shares one address, as behind the gateway.
      const sent = await auth.handler(post(SEND, { email: `shared${index}@example.test`, type: 'sign-in' }));
      expect(sent.status).toBe(200);
      const checked = await auth.handler(post('/api/auth/email-otp/check-verification-otp', { email: `shared${index}@example.test`, type: 'sign-in', otp: '000000' }));
      expect(checked.status).not.toBe(429);
      const signedIn = await auth.handler(post(SIGN_IN, { email: `shared${index}@example.test`, otp: '000000' }));
      expect(signedIn.status).not.toBe(429);
      const verified = await auth.handler(post('/api/auth/email-otp/verify-email', { email: `shared${index}@example.test`, otp: '000000' }));
      expect(verified.status).not.toBe(429);
    }
  });

  test('a first send from an address that made no other request passes even after others used the shared address', async () => {
    const auth = authWith({ enabled: true, customRules: EMAIL_OTP_ADDRESS_LIMIT_OFF });
    for (let index = 0; index < 5; index += 1) {
      await auth.handler(post(SEND, { email: `busy${index}@example.test`, type: 'sign-in' }, { 'x-forwarded-for': '198.51.100.31' }));
    }
    const first = await auth.handler(post(SEND, { email: 'first@example.test', type: 'sign-in' }, { 'x-forwarded-for': '198.51.100.31' }));
    expect(first.status).toBe(200);
  });
});
