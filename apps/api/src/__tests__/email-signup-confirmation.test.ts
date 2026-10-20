import { afterAll, afterEach, beforeAll, beforeEach, expect, test } from 'bun:test';
import type { PrismaClient } from '@openkey/db';
import { mockModules } from './mock-module';

// The gate runs as plain functions: createAuthEndpoint returns the handler, the
// Better Auth cookie and DB helpers are stubbed, and the request context is
// controlled per test (it carries the QA header).
let requestHeaders: Record<string, string> | null = null;
await mockModules({
  '@better-auth/core/context': () => ({
    getCurrentAuthContext: async () => ({
      request: requestHeaders ? new Request('http://localhost/api/auth/sign-in/email-otp', { headers: requestHeaders }) : undefined,
    }),
  }),
  'better-auth/api': (actual) => ({ ...actual, createAuthEndpoint: (_path: string, _opts: unknown, handler: unknown) => handler }),
  'better-auth/cookies': () => ({ setSessionCookie: async () => {} }),
  'better-auth/db': () => ({ parseUserOutput: (_options: unknown, user: unknown) => user }),
});

// Query-string import: each test file gets its own module instance (mock-module.ts).
const { emailSignupConfirmation, ACCOUNT_ALREADY_EXISTS, INVALID_SIGNUP_TOKEN, REGISTRATION_PAUSED, TURNSTILE_FAILED, TURNSTILE_REQUIRED } = await import(
  '../services/email-signup-confirmation?tc1632-gate' as string
);

type Row = { id: string; identifier: string; value: string; expiresAt: Date };
type Where = {
  id?: string;
  identifier?: string | { startsWith: string };
  expiresAt?: { lte?: Date; gt?: Date };
};
type ErrorBody = { code: string; message?: string; signupToken?: string; turnstileRequired?: boolean };
type Confirmed = { token: string; user: { email: string } };
type Before = (user: { email: string }, context: { path?: string } | null) => Promise<void>;

let rows: Row[] = [];
let users: Array<{ id: string; email: string }> = [];
let nextId = 0;

function matches(row: Row, where: Where): boolean {
  if (where.id !== undefined && row.id !== where.id) return false;
  const identifier = where.identifier;
  if (typeof identifier === 'string' && row.identifier !== identifier) return false;
  if (identifier && typeof identifier === 'object' && !row.identifier.startsWith(identifier.startsWith)) return false;
  if (where.expiresAt?.lte && !(row.expiresAt <= where.expiresAt.lte)) return false;
  if (where.expiresAt?.gt && !(row.expiresAt > where.expiresAt.gt)) return false;
  return true;
}

// In-memory stand-in for the Prisma verification table; only the calls the gate makes.
const database = {
  verification: {
    async create({ data }: { data: Row }) {
      rows.push(data);
      return data;
    },
    async findFirst({ where }: { where: Where }) {
      return rows.find((row) => matches(row, where)) ?? null;
    },
    async deleteMany({ where }: { where: Where }) {
      const before = rows.length;
      rows = rows.filter((row) => !matches(row, where));
      return { count: before - rows.length };
    },
  },
};

const internalAdapter = {
  async findUserByEmail(email: string) {
    return users.find((user) => user.email === email) ?? null;
  },
  async createUser({ email }: { email: string }) {
    const user = { id: `user-${++nextId}`, email };
    users.push(user);
    return user;
  },
  async createSession(userId: string) {
    return { id: `session-${userId}`, token: `token-${userId}`, userId };
  },
};

// Plugin built against the in-memory fake; the fake covers only the methods the gate calls.
const plugin = emailSignupConfirmation(database as unknown as PrismaClient);
type PluginInit = { options: { databaseHooks: { user: { create: { before: Before } } } } };
const initialized = plugin.init() as unknown as PluginInit;
const before = initialized.options.databaseHooks.user.create.before;
const endpoints = plugin.endpoints as unknown as Record<string, (ctx: unknown) => Promise<unknown>>;

function confirm(body: Record<string, unknown>): Promise<unknown> {
  return endpoints.signUpEmailOtp!({ body, context: { internalAdapter, options: {} }, json: (value: unknown) => value });
}

function isErrorBody(value: unknown): value is ErrorBody {
  return typeof value === 'object' && value !== null && 'code' in value && typeof value.code === 'string';
}

// Thrown Better Auth APIError → its body; anything else (or no throw) fails the test.
async function errorOf(run: () => Promise<unknown>): Promise<ErrorBody> {
  try {
    await run();
  } catch (error: unknown) {
    const body = typeof error === 'object' && error !== null && 'body' in error ? error.body : undefined;
    if (isErrorBody(body)) return body;
    throw error;
  }
  throw new Error('expected the call to throw');
}

// Runs the sign-in OTP create hook for a brand-new email and returns the issued token.
async function issueToken(email: string): Promise<{ signupToken: string; turnstileRequired: boolean }> {
  const body = await errorOf(() => before({ email }, { path: '/sign-in/email-otp' }));
  if (typeof body.signupToken !== 'string' || typeof body.turnstileRequired !== 'boolean') throw new Error('hook refusal lacks token fields');
  return { signupToken: body.signupToken, turnstileRequired: body.turnstileRequired };
}

const realFetch = globalThis.fetch;
let siteverifyCalls = 0;
let siteverifyResponse: () => Response = () => new Response('{}', { status: 200 });

beforeAll(() => {
  const stub = async () => {
    siteverifyCalls++;
    return siteverifyResponse();
  };
  globalThis.fetch = Object.assign(stub, { preconnect: realFetch.preconnect });
});

afterAll(() => {
  globalThis.fetch = realFetch;
});

const originalEnv = { ...process.env };

beforeEach(() => {
  rows = [];
  users = [];
  nextId = 0;
  siteverifyCalls = 0;
  requestHeaders = null;
  siteverifyResponse = () => new Response(JSON.stringify({ success: true, action: 'email-signup' }), { status: 200 });
  process.env.TURNSTILE_SECRET_KEY = 'turnstile-secret';
  process.env.OPENKEY_QA_REGISTRATION_SECRET = 'qa-current-secret';
  process.env.OPENKEY_QA_REGISTRATION_SECRET_PREVIOUS = 'qa-previous-secret';
});

afterEach(() => {
  process.env = { ...originalEnv };
});

const QA = { 'x-openkey-qa-registration': 'qa-current-secret' };
const PATTERN_LIKE_EMAIL = 'qaabcdefghijklmno@mailinator.com';

test('a new email without the QA secret is challenged with a single-use token', async () => {
  const issued = await issueToken('new@example.com');
  expect(issued.turnstileRequired).toBe(true);
  expect(issued.signupToken.length).toBeGreaterThan(0);
  expect(rows).toHaveLength(1);
  expect(rows[0]!.value).toBe('email-signup');
});

test('the QA secret marks the token exempt and the challenge is reported as not required', async () => {
  requestHeaders = QA;
  const issued = await issueToken('new@example.com');
  expect(issued.turnstileRequired).toBe(false);
  expect(rows[0]!.value).toBe('email-signup-qa');
});

test('the previous QA secret is honored during rotation', async () => {
  requestHeaders = { 'x-openkey-qa-registration': 'qa-previous-secret' };
  expect((await issueToken('new@example.com')).turnstileRequired).toBe(false);
});

test('a wrong QA secret is indistinguishable from none: challenged', async () => {
  requestHeaders = { 'x-openkey-qa-registration': 'wrong' };
  const issued = await issueToken('new@example.com');
  expect(issued.turnstileRequired).toBe(true);
  expect(rows[0]!.value).toBe('email-signup');
});

test('an email matching a test-account pattern is still challenged without the secret', async () => {
  const issued = await issueToken(PATTERN_LIKE_EMAIL);
  expect(issued.turnstileRequired).toBe(true);
  const reply = await errorOf(() => confirm({ email: PATTERN_LIKE_EMAIL, signupToken: issued.signupToken }));
  expect(reply.code).toBe(TURNSTILE_REQUIRED);
  expect(users).toHaveLength(0);
});

test('the QA header on a non-OTP path issues no token', async () => {
  requestHeaders = QA;
  await before({ email: 'new@example.com' }, { path: '/sign-up/email-otp' });
  expect(rows).toHaveLength(0);
});

test('a confirmation without a Turnstile token is refused and does not spend the token', async () => {
  const { signupToken } = await issueToken('new@example.com');
  const reply = await errorOf(() => confirm({ email: 'new@example.com', signupToken }));
  expect(reply.code).toBe(TURNSTILE_REQUIRED);
  expect(siteverifyCalls).toBe(0);
  expect(rows).toHaveLength(1);
  expect(users).toHaveLength(0);
});

test('a rejected Turnstile token is refused and leaves the sign-up token usable for a retry', async () => {
  const { signupToken } = await issueToken('new@example.com');
  siteverifyResponse = () => new Response(JSON.stringify({ success: false, 'error-codes': ['invalid-input-response'] }), { status: 200 });
  const reply = await errorOf(() => confirm({ email: 'new@example.com', signupToken, turnstileToken: 'bad' }));
  expect(reply.code).toBe(TURNSTILE_FAILED);
  expect(rows).toHaveLength(1);
  expect(users).toHaveLength(0);

  siteverifyResponse = () => new Response(JSON.stringify({ success: true, action: 'email-signup' }), { status: 200 });
  const ok = (await confirm({ email: 'new@example.com', signupToken, turnstileToken: 'good' })) as Confirmed;
  expect(ok.user.email).toBe('new@example.com');
  expect(users).toHaveLength(1);
});

test('when Cloudflare cannot be reached, registration pauses and the token is kept', async () => {
  const { signupToken } = await issueToken('new@example.com');
  siteverifyResponse = () => {
    throw new TypeError('fetch failed');
  };
  const reply = await errorOf(() => confirm({ email: 'new@example.com', signupToken, turnstileToken: 'good' }));
  expect(reply.code).toBe(REGISTRATION_PAUSED);
  expect(reply.message).toBe('Sign-ups are paused for a moment. Try again shortly.');
  expect(rows).toHaveLength(1);
  expect(users).toHaveLength(0);
});

test('with no TURNSTILE_SECRET_KEY, challenged registrations fail closed', async () => {
  delete process.env.TURNSTILE_SECRET_KEY;
  const { signupToken } = await issueToken('new@example.com');
  const reply = await errorOf(() => confirm({ email: 'new@example.com', signupToken, turnstileToken: 'good' }));
  expect(reply.code).toBe(REGISTRATION_PAUSED);
  expect(siteverifyCalls).toBe(0);
  expect(users).toHaveLength(0);
});

test('a challenged token with a verified Turnstile token creates the account and spends the token', async () => {
  const { signupToken } = await issueToken('new@example.com');
  const ok = (await confirm({ email: 'new@example.com', signupToken, turnstileToken: 'good' })) as Confirmed;
  expect(ok.token).toBe(`token-${users[0]!.id}`);
  expect(users).toHaveLength(1);
  expect(rows).toHaveLength(0);
  expect(siteverifyCalls).toBe(1);
});

test('the QA-exempt token creates the account without calling Cloudflare', async () => {
  requestHeaders = QA;
  const { signupToken } = await issueToken('new@example.com');
  const ok = (await confirm({ email: 'new@example.com', signupToken })) as Confirmed;
  expect(ok.user.email).toBe('new@example.com');
  expect(siteverifyCalls).toBe(0);
  expect(users).toHaveLength(1);
});

test('a token is bound to its email: another email is refused even when exempt', async () => {
  requestHeaders = QA;
  const { signupToken } = await issueToken('new@example.com');
  const reply = await errorOf(() => confirm({ email: 'other@example.com', signupToken }));
  expect(reply.code).toBe(INVALID_SIGNUP_TOKEN);
  expect(users).toHaveLength(0);
});

test('a spent token cannot create a second account', async () => {
  requestHeaders = QA;
  const { signupToken } = await issueToken('new@example.com');
  await confirm({ email: 'new@example.com', signupToken });
  const reply = await errorOf(() => confirm({ email: 'new@example.com', signupToken }));
  expect(reply.code).toBe(INVALID_SIGNUP_TOKEN);
  expect(users).toHaveLength(1);
});

test('an email that already has an account is refused after the Turnstile check passes', async () => {
  const { signupToken } = await issueToken('new@example.com');
  users.push({ id: 'existing', email: 'new@example.com' });
  const reply = await errorOf(() => confirm({ email: 'new@example.com', signupToken, turnstileToken: 'good' }));
  expect(reply.code).toBe(ACCOUNT_ALREADY_EXISTS);
  expect(siteverifyCalls).toBe(1);
});
