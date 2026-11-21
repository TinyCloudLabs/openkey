import './tinycloud-setup-test-env';

// TC-3657 Bobbie 15:16:27Z + Naomi 15:12:55Z/15:16:50Z: route-level integration tests.
// Exercises the hono router with injected stores + injected session middleware against a
// fake PrismaClient. One test per F that would have failed on d9aa2841, plus Naomi's
// explicit scenarios: replayed ticket, wrong origin, framed request (covered in the widget
// test suite), rate-limit hit, and 503 when config is unset.
//
// The route calls `rejectNonOpenKeySignRequest` + `requireSession` middleware; the test
// router injects simple stand-ins so the tests can exercise the business logic directly.
// Deterministic time: tests pass `getServerTime` instead of relying on wall-clock drift.

import { describe, expect, test } from 'bun:test';
import type { PrismaClient } from '@openkey/db';
import { Hono } from 'hono';
import { randomBytes } from 'node:crypto';
import type { SessionContext } from '../middleware/session';
import {
  createInMemorySetupNonceStore,
  createSetupTicketStore,
} from '../services/tinycloud-setup-ticket';
import {
  createInMemoryTinyCloudSetupLimiter,
} from '../services/tinycloud-setup-rate-limit';
import { createTinyCloudSetupRouter } from './tinycloud-setup';

const USER_ID = 'user_fix_me';
const SESSION_ID = 'session_fix_me';
const ADDRESS = '0x1111111111111111111111111111111111111111';
const OPEN_KEY_ORIGIN = 'http://localhost:5173';
const APP_ORIGIN = 'https://thirdparty.example';

const PRIMARY_KEY = {
  userId: USER_ID,
  address: ADDRESS,
  sealedPrivateKey: 'sealed-bytes',
  sealingContext: null,
};

const CONFIGURED_HOST = {
  host: 'https://node.example',
  did: 'did:key:zTinyCloudBootstrap',
};

type UserVars = SessionContext['Variables']['user'];
type SessionVars = SessionContext['Variables']['session'];

function setSession(c: { set: (key: 'user' | 'session', value: UserVars | SessionVars) => void }) {
  const user: UserVars = { id: USER_ID, email: 'owner@example' };
  const session: SessionVars = { id: SESSION_ID, userId: USER_ID, expiresAt: new Date(2099, 0, 1) };
  c.set('user', user);
  c.set('session', session);
}

/** Minimal PrismaClient the route uses. Only the fields the route actually calls are
 *  implemented; everything else throws, which the tests rely on to catch overreach.
 *  The cast at the end is `as unknown as PrismaClient` because PrismaClient has hundreds
 *  of fields; the route only touches these, and any new call fails loudly at runtime
 *  via the default-throw proxy. */
function fakePrisma(overrides: {
  passkeyApprovalMode?: 'ALWAYS' | 'SENSITIVE' | 'NEVER';
  stepUpPasskeyCount?: number;
} = {}): PrismaClient {
  const passkeyApprovalMode = overrides.passkeyApprovalMode ?? 'NEVER';
  const stepUpPasskeyCount = overrides.stepUpPasskeyCount ?? 0;
  const client = {
    ethereumKey: {
      findFirst: async () => PRIMARY_KEY,
    },
    passkey: {
      count: async () => stepUpPasskeyCount,
      findFirst: async () => null,
      findMany: async () => [],
    },
    user: {
      findUnique: async () => ({ passkeyApprovalMode }),
    },
    verification: {
      findFirst: async () => null,
      deleteMany: async () => ({ count: 0 }),
    },
    $transaction: async (fn: (tx: unknown) => Promise<void>) => fn({}),
  };
  // Route only ever reaches the fields above; the cast documents the fake's scope.
  return client as unknown as PrismaClient;
}

interface BuildRouterOpts {
  passkeyApprovalMode?: 'ALWAYS' | 'SENSITIVE' | 'NEVER';
  stepUpPasskeyCount?: number;
  configuredHost?: string;
  /** If set, exercises the real origin middleware; otherwise skips it. */
  realOrigin?: boolean;
  /** For deterministic time control (F3). Mint and publish both see the same `now()`. */
  getServerTime?: () => Date;
  rateLimits?: { mint: number; publish: number };
}

function buildRouter(opts: BuildRouterOpts = {}) {
  const ticketStore = createSetupTicketStore(randomBytes(32), createInMemorySetupNonceStore());
  const retryAfter = createInMemoryTinyCloudSetupLimiter(opts.rateLimits ?? { mint: 10, publish: 3 });
  const prisma = fakePrisma({
    ...(opts.passkeyApprovalMode ? { passkeyApprovalMode: opts.passkeyApprovalMode } : {}),
    ...(opts.stepUpPasskeyCount !== undefined ? { stepUpPasskeyCount: opts.stepUpPasskeyCount } : {}),
  });
  const app = new Hono<SessionContext>();
  // onError surfaces server exceptions as JSON bodies in test output. Production uses the
  // default hono error handler; tests want visible error messages for debugging.
  app.onError((err, c) => c.json({ error: 'internal', message: String(err instanceof Error ? err.message : err) }, 500));
  app.route('/api/tinycloud-setup', createTinyCloudSetupRouter({
    ticketStore,
    retryAfter,
    prisma,
    configuredHost: opts.configuredHost ?? CONFIGURED_HOST.host,
    ...(opts.getServerTime ? { getServerTime: opts.getServerTime } : {}),
    sessionMiddleware: async (c, next) => { setSession(c); await next(); },
    ...(opts.realOrigin ? {} : { originMiddleware: async (_c, next) => { await next(); } }),
  }));
  return { app, ticketStore, retryAfter, prisma };
}

interface MintResponse {
  ticket: string;
  passkey: { required: boolean; challengeToken?: string; options?: unknown };
  preview: { subject: string; nodeDid: string; nodeOrigin: string; space: string; primarySpaceName: string };
  ttlMs: number;
}

async function mintOk(app: Hono<SessionContext>, origin = APP_ORIGIN): Promise<MintResponse> {
  const response = await app.request('/api/tinycloud-setup/mint-ticket', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ requestingOrigin: origin }),
  });
  expect(response.status).toBe(200);
  return await response.json() as MintResponse;
}

describe('tinycloud-setup router', () => {
  test('mint-ticket returns the preview and a bound ticket under the owner session', async () => {
    const { app } = buildRouter();
    const body = await mintOk(app);
    expect(body.ticket.length).toBeGreaterThan(32);
    expect(body.preview.subject.startsWith('did:pkh:')).toBe(true);
    expect(body.preview.primarySpaceName).toBe('default');
    expect(body.passkey.required).toBe(false);
  });

  test('publish reaches the registry publish path with the ticket consumed (observed via stubbed-registry 502)', async () => {
    // The registry publish call goes out via `fetch`; without a registry mock it 502s and the
    // route surfaces `status: 'unavailable'` with 502. That's enough to show the route didn't
    // stop in the ticket / passkey / limit gates.
    const ticketStore = createSetupTicketStore(randomBytes(32), createInMemorySetupNonceStore());
    const retryAfter = createInMemoryTinyCloudSetupLimiter();
    const prisma = fakePrisma();
    const app = new Hono<SessionContext>().route('/api/tinycloud-setup', createTinyCloudSetupRouter({
      ticketStore, retryAfter, prisma,
      configuredHost: CONFIGURED_HOST.host,
      fetch: (async () => new Response('', { status: 502 })) as unknown as typeof fetch,
      sessionMiddleware: async (c, next) => { setSession(c); await next(); },
      originMiddleware: async (_c, next) => { await next(); },
    }));
    const minted = await mintOk(app);
    const publish = await app.request('/api/tinycloud-setup/publish', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ticket: minted.ticket, requestingOrigin: APP_ORIGIN }),
    });
    expect(publish.status).toBe(502);
    const body = await publish.json() as { status: string };
    expect(body.status).toBe('unavailable');
  });

  // Naomi 15:16:50Z — "add a test for each F that fails on d9aa2841".

  test('F3 regression: publish does NOT fail with record_mismatch when mint and publish run at different wall-clock moments', async () => {
    // On d9aa2841, mint-ticket hashed the payload at time T0 and publish rehashed at T0+Δ
    // (the handlers each called `new Date()`), so the two hashes diverged and every real
    // publish got 403 record_mismatch. The fix carries mintedAt inside the ticket and
    // rebuilds at that timestamp. Here we advance the injected clock between mint and
    // publish without a real sleep.
    let currentMs = 1_700_000_000_000;
    const getServerTime = () => new Date(currentMs);
    const { app } = buildRouter({ getServerTime });
    const minted = await mintOk(app);
    currentMs += 3_000; // 3 seconds elapse between mint and publish, well inside the TTL
    const publish = await app.request('/api/tinycloud-setup/publish', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ticket: minted.ticket, requestingOrigin: APP_ORIGIN }),
    });
    expect(publish.status).not.toBe(403);
    const body = await publish.json().catch(() => ({})) as { error?: string; status?: string };
    expect(body.error).not.toBe('record_mismatch');
  });

  test('F5 regression: unset OPENKEY_SETUP_TICKET_SECRET yields 503 per request, not a boot crash', async () => {
    // The lazy-init path: if deps fail to build (e.g. secret missing), the router catches
    // and returns 503. We simulate by invoking createTinyCloudSetupRouter with a Partial deps
    // missing ticketStore — the lazy resolver falls through to defaultDeps(), which reads
    // the env var and throws when it's absent.
    const prevSecret = process.env.OPENKEY_SETUP_TICKET_SECRET;
    delete process.env.OPENKEY_SETUP_TICKET_SECRET;
    try {
      const app = new Hono<SessionContext>().route('/api/tinycloud-setup', createTinyCloudSetupRouter({
        retryAfter: createInMemoryTinyCloudSetupLimiter(),
        prisma: fakePrisma(),
        sessionMiddleware: async (c, next) => { setSession(c); await next(); },
        originMiddleware: async (_c, next) => { await next(); },
      }));
      const response = await app.request('/api/tinycloud-setup/mint-ticket', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ requestingOrigin: APP_ORIGIN }),
      });
      expect(response.status).toBe(503);
      const body = await response.json() as { error: string };
      expect(body.error).toBe('setup_unavailable');
    } finally {
      if (prevSecret === undefined) delete process.env.OPENKEY_SETUP_TICKET_SECRET;
      else process.env.OPENKEY_SETUP_TICKET_SECRET = prevSecret;
    }
  });

  test('F6 regression: missing Origin header is refused by the real middleware (403)', async () => {
    // With `realOrigin: true` we use the production origin guard; a request with NO Origin
    // header is refused with 403 `Managed-key signing requires an OpenKey browser origin`.
    const { app } = buildRouter({ realOrigin: true });
    const response = await app.request('/api/tinycloud-setup/mint-ticket', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ requestingOrigin: APP_ORIGIN }),
    });
    expect(response.status).toBe(403);
  });

  test('F6 regression: cross-origin Origin header is refused (403); same-site passes', async () => {
    const { app } = buildRouter({ realOrigin: true });
    const foreign = await app.request('/api/tinycloud-setup/mint-ticket', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://attacker.example' },
      body: JSON.stringify({ requestingOrigin: APP_ORIGIN }),
    });
    expect(foreign.status).toBe(403);
    const sameSite = await app.request('/api/tinycloud-setup/mint-ticket', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: OPEN_KEY_ORIGIN },
      body: JSON.stringify({ requestingOrigin: APP_ORIGIN }),
    });
    expect(sameSite.status).toBe(200);
  });

  // Naomi 15:12:55Z — "replayed ticket, wrong origin, framed request, rate-limit hit, 503
  // when config unset". The framed request is covered in the widget tests.

  test('replayed ticket (second publish) fails with 409 already_used', async () => {
    const { app } = buildRouter();
    const minted = await mintOk(app);
    const body = JSON.stringify({ ticket: minted.ticket, requestingOrigin: APP_ORIGIN });
    const first = await app.request('/api/tinycloud-setup/publish', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body,
    });
    // First attempt reaches publish (502 unavailable from the real fetch; sufficient).
    expect([502, 200]).toContain(first.status);
    const replay = await app.request('/api/tinycloud-setup/publish', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body,
    });
    expect(replay.status).toBe(409);
    const replayBody = await replay.json() as { error: string };
    expect(replayBody.error).toBe('already_used');
  });

  test('publish with a different requestingOrigin than the ticket was bound to → 403 origin_mismatch', async () => {
    const { app } = buildRouter();
    const minted = await mintOk(app, APP_ORIGIN);
    const response = await app.request('/api/tinycloud-setup/publish', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ticket: minted.ticket, requestingOrigin: 'https://attacker.example' }),
    });
    expect(response.status).toBe(403);
    const body = await response.json() as { error: string };
    expect(body.error).toBe('origin_mismatch');
  });

  test('rate-limit hit on publish → 429 with retry-after', async () => {
    const { app } = buildRouter({ rateLimits: { mint: 10, publish: 1 } });
    const first = await mintOk(app);
    await app.request('/api/tinycloud-setup/publish', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ticket: first.ticket, requestingOrigin: APP_ORIGIN }),
    });
    const second = await mintOk(app);
    const limited = await app.request('/api/tinycloud-setup/publish', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ticket: second.ticket, requestingOrigin: APP_ORIGIN }),
    });
    expect(limited.status).toBe(429);
    expect(limited.headers.get('retry-after')).toMatch(/^\d+$/);
  });

  test('503 when the bootstrap node config is unset (defaultTinyCloudBootstrapNode returns null)', async () => {
    const prev = process.env.TINYCLOUD_DEFAULT_NODE_DID;
    delete process.env.TINYCLOUD_DEFAULT_NODE_DID;
    try {
      const app = new Hono<SessionContext>().route('/api/tinycloud-setup', createTinyCloudSetupRouter({
        ticketStore: createSetupTicketStore(randomBytes(32), createInMemorySetupNonceStore()),
        retryAfter: createInMemoryTinyCloudSetupLimiter(),
        prisma: fakePrisma(),
        sessionMiddleware: async (c, next) => { setSession(c); await next(); },
        originMiddleware: async (_c, next) => { await next(); },
      }));
      const response = await app.request('/api/tinycloud-setup/mint-ticket', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ requestingOrigin: APP_ORIGIN }),
      });
      expect(response.status).toBe(503);
      const body = await response.json() as { error: string };
      expect(body.error).toBe('setup_unavailable');
    } finally {
      if (prev === undefined) delete process.env.TINYCLOUD_DEFAULT_NODE_DID;
      else process.env.TINYCLOUD_DEFAULT_NODE_DID = prev;
    }
  });

  // F1 (C4): publish without a passkey assertion must be refused when the owner's mode
  // requires one. On d9aa2841 this went through on cookie + ticket + one click.
  test('F1 regression: publish without a passkey assertion → 403 passkey_approval_required when mode is ALWAYS', async () => {
    const { app } = buildRouter({ passkeyApprovalMode: 'ALWAYS', stepUpPasskeyCount: 1 });
    const minted = await mintOk(app);
    const response = await app.request('/api/tinycloud-setup/publish', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ticket: minted.ticket, requestingOrigin: APP_ORIGIN }),
    });
    expect(response.status).toBe(403);
    const body = await response.json() as { error: string };
    expect(body.error).toBe('passkey_approval_required');
  });
});
