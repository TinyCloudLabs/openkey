// The account setup routes reached with the bearer token of an embedded OpenKey session instead of a cookie (the
// setup window opened from the embed carries the embed's token), against the real API on PGlite with the tracked
// migrations. A bearer opens the five setup routes and nothing else: the step-up confirms every approval, each
// request stays with the session that made it, and the owner's attempts are limited per account. Runs in a child
// process: the API reads its relying party, origins and database when loaded. The node and the registry are
// in-process fakes; no request leaves the process.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { serializeSignedCookie } from 'better-call';
import type { PrismaClient } from '@openkey/db';
import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/server';
import { createSoftPasskey, type SoftPasskey } from './soft-passkey';
import { mockModules } from './mock-module';

const root = resolve(import.meta.dir, '../../../..');
const web = 'https://openkey.test';
const node = 'https://node.tinycloud.xyz';

if (process.env.OPENKEY_ACCOUNT_SETUP_BEARER_CHILD !== '1') {
  test('the account setup routes with the bearer of an embedded session', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_ACCOUNT_SETUP_BEARER_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: randomBytes(48).toString('base64url'),
        WEBAUTHN_RP_ID: 'openkey.test',
        WEBAUTHN_ORIGIN: web,
        CORS_ORIGIN: web,
        TINYCLOUD_BOOTSTRAP_HOST: node,
        TINYCLOUD_BOOTSTRAP_ON_SIGN: '',
        TINYCLOUD_BOOTSTRAP_SWEEP: 'off',
        RESEND_API_KEY: '',
        GOOGLE_CLIENT_ID: '',
        GOOGLE_CLIENT_SECRET: '',
      },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ]);
    expect(exitCode, stdout + stderr).toBe(0);
  }, 300_000);
} else {
  const api = 'https://api.openkey.test';
  const nodeDid = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  const TERMS_VERSION = '2026-12-01';
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let secret: string;
  let cookieName: string;
  let tee: typeof import('@openkey/tee');
  let sdk: typeof import('@tinycloud/sdk-core');
  let stepUp: typeof import('../services/account-setup-step-up');
  let codes: typeof import('../services/email-code-storage');
  let budget: typeof import('../services/account-setup-budget');
  let terms: typeof import('../services/terms');
  let bootstrap: typeof import('../services/tinycloud-bootstrap');
  let registryUrl: string;

  // The checked-in terms-release.json, replaced by one object the Terms test rewrites: the API reads it per call.
  const releaseFile: Record<string, unknown> = {};
  function release(version: string | null) {
    Object.assign(releaseFile, {
      version, requiredVersion: null, textSha256: version ? 'a'.repeat(64) : null, whatChanged: null, privacyChanged: false,
    });
  }
  release(null);
  // The mail of the emailed code goes to this list instead of Resend.
  const mailed: { to: string; subject: string; text: string }[] = [];
  process.env.RESEND_API_KEY = 're_test_key';
  await mockModules({
    '../terms-release.json': () => ({ default: releaseFile }),
    resend: () => ({
      Resend: class {
        emails = { send: async (mail: { to: string; subject: string; text: string }) => { mailed.push(mail); return { data: { id: 'mail_1' }, error: null }; } };
      },
    }),
  });

  const originalFetch = globalThis.fetch;
  const puts: Record<string, unknown>[] = [];
  let bootstrapRuns = 0;

  function fakeFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = String(input instanceof Request ? input.url : input);
    if (url === `${node}/info`) return Promise.resolve(Response.json({ nodeId: nodeDid }));
    if (url === `${node}/.well-known/tinycloud/node-keys`) return Promise.resolve(Response.json({ nodeDid }));
    if (url.startsWith(`${registryUrl}/v2/locations/`)) {
      if ((init?.method ?? 'GET') === 'PUT') {
        const record = JSON.parse(String(init!.body)) as Record<string, unknown>;
        puts.push(record);
        return Promise.resolve(Response.json({ record, status: 'created' }, { status: 201 }));
      }
      return Promise.resolve(Response.json({ error: 'location record not found' }, { status: 404 }));
    }
    return Promise.reject(new Error(`External network disabled in this test: ${url}`));
  }

  beforeAll(async () => {
    globalThis.fetch = fakeFetch as typeof fetch;
    directory = await mkdtemp(join(tmpdir(), 'openkey-account-setup-bearer-'));
    const database = new PGlite(directory);
    try {
      const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
        .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
      for (const migration of migrations) {
        await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
      }
    } finally {
      await database.close();
    }
    process.env.DATABASE_URL = `pglite:${directory}`;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    tee = await import('@openkey/tee');
    sdk = await import('@tinycloud/sdk-core');
    registryUrl = sdk.DEFAULT_TINYCLOUD_LOCATION_REGISTRY_URL;
    stepUp = await import('../services/account-setup-step-up');
    codes = await import('../services/email-code-storage');
    budget = await import('../services/account-setup-budget');
    terms = await import('../services/terms');
    bootstrap = await import('../services/tinycloud-bootstrap');
    bootstrap.setTinyCloudBootstrapProbeForTests(async () => {});
    bootstrap.setTinyCloudBootstrapExecutorForTests(async () => { bootstrapRuns += 1; });
    const authModule = await import('../auth');
    prisma = authModule.prisma;
    app = (await import('../index')).default;
    const context = await authModule.auth.$context;
    secret = context.secret;
    cookieName = context.authCookies.sessionToken.name;
  }, 120_000);

  afterAll(async () => {
    globalThis.fetch = originalFetch;
    bootstrap?.setTinyCloudBootstrapProbeForTests();
    bootstrap?.setTinyCloudBootstrapExecutorForTests();
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  beforeEach(() => {
    puts.length = 0;
    bootstrapRuns = 0;
  });

  type Session = { sessionId: string; token: string; cookie: string; bearer: string };
  type Account = Session & { userId: string; keyId: string };

  async function session(userId: string): Promise<Session> {
    const sessionId = randomUUID();
    const token = randomBytes(32).toString('base64url');
    await prisma.session.create({ data: { id: sessionId, userId, token, expiresAt: new Date(Date.now() + 86_400_000) } });
    const cookie = (await serializeSignedCookie(cookieName, token, secret)).split(';')[0]!;
    // A bearer is the signed session token, as `set-auth-token` hands it out.
    return { sessionId, token, cookie, bearer: cookie.slice(cookie.indexOf('=') + 1) };
  }

  async function key(userId: string, canonical = false): Promise<string> {
    const privateKey = tee.generatePrivateKey();
    const sealingContext = randomBytes(32).toString('base64url');
    const sealingKey = await tee.createTeeClient().deriveKey(`openkey/key/${sealingContext}`);
    const created = await prisma.ethereumKey.create({ data: {
      userId, address: tee.getAddressFromPrivateKey(privateKey), publicKey: '0x1', sealedBlob: await tee.seal(privateKey, sealingKey),
      sealingContext, keyType: 'MANAGED', isCanonicalTinyCloud: canonical,
    } });
    return created.id;
  }

  async function account(options: { emailVerified?: boolean } = {}): Promise<Account> {
    const userId = randomUUID();
    await prisma.user.create({ data: {
      id: userId, email: `${userId}@example.test`, name: userId, emailVerified: options.emailVerified ?? true,
    } });
    return { userId, ...await session(userId), keyId: await key(userId, true) };
  }

  const request = (path: string, headers: Record<string, string>, body: unknown = {}) => app.fetch(new Request(`${api}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  }));
  /** What the setup window sends: the embed's bearer, no cookie, the OpenKey Origin. */
  const asBearer = (owner: { bearer: string }) => ({ authorization: `Bearer ${owner.bearer}`, origin: web });
  const asCookie = (owner: { cookie: string }) => ({ cookie: owner.cookie, origin: web });
  const post = (path: string, headers: Record<string, string>, body: unknown = {}) => request(path, headers, body);

  async function json(response: Response, status: number): Promise<Record<string, any>> {
    expect(response.status, await response.clone().text()).toBe(status);
    return await response.json() as Record<string, any>;
  }

  async function prepare(owner: { keyId: string }, headers: Record<string, string>) {
    return json(await post('/api/account-setup/prepare', headers, { keyId: owner.keyId }), 200);
  }

  async function assertion(passkey: SoftPasskey, id: string, headers: Record<string, string>) {
    const offer = await json(await post(`/api/account-setup/${id}/passkey`, headers), 200);
    expect(offer.stepUp).toBe('passkey');
    return { challengeToken: offer.challengeToken as string, response: passkey.assert(offer.options as PublicKeyCredentialRequestOptionsJSON) };
  }

  /** Replaces the mailed code with a known one: the database holds only its keyed hash. */
  async function knownCode(sessionId: string, requestId: string, code: string) {
    const identifier = stepUp.accountSetupCodeIdentifier(sessionId, requestId);
    await prisma.verification.updateMany({ where: { identifier }, data: { value: `${codes.stepUpCodeDigest(identifier, code)}:0` } });
  }

  const budgetUsed = async (userId: string, kind: 'send' | 'verify') =>
    Number((await prisma.verification.findFirst({ where: { identifier: `account-setup-budget:${kind}:${userId}` } }))?.value ?? 0);
  const rowCount = (userId: string) => prisma.accountSetupRequest.count({ where: { userId } });

  const FIVE = ['/api/account-setup/prepare', ...['passkey', 'email-code', 'approve', 'finish'].map((step) => `/api/account-setup/some-id/${step}`)];

  describe('who may ask', () => {
    test('a bearer is refused without the OpenKey Origin on each of the five routes, and no row is made', async () => {
      const owner = await account();
      for (const path of FIVE) {
        for (const origin of [undefined, 'https://app.example', 'null']) {
          const headers: Record<string, string> = { authorization: `Bearer ${owner.bearer}`, ...(origin ? { origin } : {}) };
          const answer = await json(await post(path, headers, { keyId: owner.keyId }), 403);
          expect(answer.error, `${path} ${origin}`).toBe('A same-site browser Origin is required');
        }
      }
      expect(await rowCount(owner.userId)).toBe(0);
    });

    test('a bad bearer next to a valid cookie is refused with no fallback to the cookie, and makes no row', async () => {
      const owner = await account();
      const revoked = await session(owner.userId);
      await prisma.session.delete({ where: { id: revoked.sessionId } });
      for (const authorization of ['Bearer x', `Bearer ${owner.token}`, `Bearer ${revoked.bearer}`, 'Basic eDp5', 'Bearer']) {
        for (const path of FIVE) {
          const answer = await post(path, { cookie: owner.cookie, authorization, origin: web }, { keyId: owner.keyId });
          expect(answer.status, `${path} ${authorization}`).toBe(401);
        }
      }
      expect(await rowCount(owner.userId)).toBe(0);
    });

    test('a valid bearer next to the cookie of another session is the session used, and a cookie alone works', async () => {
      const owner = await account();
      const embed = await session(owner.userId);
      const both = { cookie: owner.cookie, authorization: `Bearer ${embed.bearer}`, origin: web };
      const prepared = await prepare(owner, both);
      expect(await prisma.accountSetupRequest.findUniqueOrThrow({ where: { id: prepared.id } }))
        .toMatchObject({ userId: owner.userId, sessionId: embed.sessionId });
      // The cookie session does not see that row.
      await json(await post(`/api/account-setup/${prepared.id}/passkey`, asCookie(owner)), 404);

      const other = await account();
      const mixed = { cookie: other.cookie, authorization: `Bearer ${owner.bearer}`, origin: web };
      await json(await post('/api/account-setup/prepare', mixed, { keyId: other.keyId }), 404);

      const byCookie = await prepare({ keyId: await key(owner.userId) }, asCookie(owner));
      expect(await prisma.accountSetupRequest.findUniqueOrThrow({ where: { id: byCookie.id } }))
        .toMatchObject({ userId: owner.userId, sessionId: owner.sessionId });
    });

    test('an unsigned, wrongly signed, unknown, expired or revoked bearer is refused and makes no row', async () => {
      const owner = await account();
      const wrongSecret = (await serializeSignedCookie(cookieName, owner.token, `${secret}x`)).split(';')[0]!;
      const unknown = (await serializeSignedCookie(cookieName, randomBytes(32).toString('base64url'), secret)).split(';')[0]!;
      const expired = await session(owner.userId);
      await prisma.session.update({ where: { id: expired.sessionId }, data: { expiresAt: new Date(Date.now() - 1000) } });
      const revoked = await session(owner.userId);
      await prisma.session.delete({ where: { id: revoked.sessionId } });
      const bearers = [
        'x', owner.token, wrongSecret.slice(wrongSecret.indexOf('=') + 1), unknown.slice(unknown.indexOf('=') + 1),
        expired.bearer, revoked.bearer,
      ];
      for (const bearer of bearers) {
        const answer = await post('/api/account-setup/prepare', { authorization: `Bearer ${bearer}`, origin: web }, { keyId: owner.keyId });
        expect(answer.status, bearer).toBe(401);
      }
      expect(await rowCount(owner.userId)).toBe(0);
    });

    test('a session without accepted Terms is refused on a bearer as on a cookie', async () => {
      release(TERMS_VERSION);
      try {
        const owner = await account();
        const body = (headers: Record<string, string>) => post('/api/account-setup/prepare', headers, { keyId: owner.keyId });
        const byBearer = await json(await body(asBearer(owner)), 403);
        const byCookie = await json(await body(asCookie(owner)), 403);
        expect(byBearer).toEqual(byCookie);
        expect(byBearer.error).toBe('terms_required');
        expect(await rowCount(owner.userId)).toBe(0);

        await terms.recordTermsAcceptance(prisma, owner.userId, terms.termsRelease()!, 'test');
        expect(await prepare(owner, asBearer(owner))).toMatchObject({ state: 'ready' });
      } finally {
        release(null);
      }
    });

    test('signing out of the embed revokes the session on the server: the bearer opens no setup route', async () => {
      const owner = await account();
      await createSoftPasskey(prisma, owner.userId, true, web);
      expect(await prepare(owner, asBearer(owner))).toMatchObject({ state: 'ready' });
      const out = await post('/api/auth/sign-out', asBearer(owner));
      expect(out.status).toBe(200);
      expect(await prisma.session.count({ where: { id: owner.sessionId } })).toBe(0);
      expect((await post('/api/account-setup/prepare', asBearer(owner), { keyId: owner.keyId })).status).toBe(401);
    });
  });

  describe('a whole setup with a bearer', () => {
    test('prepare, passkey, approve and finish run on the bearer with no cookie, and answer only what the page needs', async () => {
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      const auth = asBearer(owner);

      const prepared = await prepare(owner, auth);
      // The record the owner approves and where it goes: no address book, no email, no key material, no other row.
      expect(Object.keys(prepared).sort()).toEqual(['expiresAt', 'id', 'nodeUrl', 'record', 'state', 'stepUp']);
      expect(JSON.stringify(prepared)).not.toContain(owner.userId);
      expect(JSON.stringify(prepared)).not.toContain('example.test');
      const row = await prisma.accountSetupRequest.findUniqueOrThrow({ where: { id: prepared.id } });
      expect(row).toMatchObject({ userId: owner.userId, sessionId: owner.sessionId });

      const offer = await json(await post(`/api/account-setup/${prepared.id}/passkey`, auth), 200);
      expect(Object.keys(offer).sort()).toEqual(['challengeToken', 'options', 'stepUp']);
      const proof = { challengeToken: offer.challengeToken, response: passkey.assert(offer.options) };
      expect(await json(await post(`/api/account-setup/${prepared.id}/approve`, auth, { passkeyAssertion: proof }), 200))
        .toEqual({ state: 'published' });
      expect(bootstrapRuns).toBe(1);
      expect(puts).toHaveLength(1);
      expect(await json(await post(`/api/account-setup/${prepared.id}/finish`, auth), 200)).toEqual({ state: 'published' });
    });

    test('the key list the page reads is the bearer route it already was', async () => {
      const owner = await account();
      const answer = await app.fetch(new Request(`${api}/api/keys`, { headers: asBearer(owner) }));
      const body = await json(answer, 200);
      expect(body.keys.map((entry: { id: string }) => entry.id)).toEqual([owner.keyId]);
    });
  });

  describe('a bearer changes nothing without the step-up', () => {
    test('approve with no proof, a passkey assertion for another request or a wrong code is refused and leaves the row open', async () => {
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      const auth = asBearer(owner);
      const first = await prepare(owner, auth);
      const secondKey = await key(owner.userId);
      const second = await prepare({ keyId: secondKey }, auth);
      expect(second.id).not.toBe(first.id);

      const none = await json(await post(`/api/account-setup/${first.id}/approve`, auth, {}), 403);
      expect(none.code).toBe('passkey_approval_required');
      // A genuine assertion of the owner's passkey, for the other request's digest.
      const forSecond = await assertion(passkey, second.id, auth);
      const wrongDigest = await json(await post(`/api/account-setup/${first.id}/approve`, auth, { passkeyAssertion: forSecond }), 403);
      expect(wrongDigest.code).toBe('passkey_approval_invalid');
      // An email code never stands in for a passkey.
      const code = await json(await post(`/api/account-setup/${first.id}/approve`, auth, { emailCode: '123456' }), 403);
      expect(code.code).toBe('passkey_approval_required');
      expect(bootstrapRuns).toBe(0);
      expect(puts).toHaveLength(0);
      expect((await prisma.accountSetupRequest.findUniqueOrThrow({ where: { id: first.id } })).consumedAt).toBeNull();

      // The row stays open: its own assertion approves it.
      const forFirst = await assertion(passkey, first.id, auth);
      expect(await json(await post(`/api/account-setup/${first.id}/approve`, auth, { passkeyAssertion: forFirst }), 200))
        .toEqual({ state: 'published' });
    });

    test('an emailed code is for one request and one session, single use, and ends in five minutes', async () => {
      const owner = await account();
      const auth = asBearer(owner);
      const first = await prepare(owner, auth);
      const second = await prepare({ keyId: await key(owner.userId) }, auth);
      expect(await json(await post(`/api/account-setup/${first.id}/email-code`, auth), 200)).toMatchObject({ sent: true });
      await knownCode(owner.sessionId, first.id, '424242');
      const stored = await prisma.verification.findFirstOrThrow({
        where: { identifier: stepUp.accountSetupCodeIdentifier(owner.sessionId, first.id) },
      });
      const lifetime = stored.expiresAt.getTime() - Date.now();
      expect(lifetime).toBeGreaterThan(4 * 60 * 1000);
      expect(lifetime).toBeLessThanOrEqual(5 * 60 * 1000);

      // Another request, and another session of the same account, do not take the code.
      const other = await session(owner.userId);
      const elsewhere = await json(await post(`/api/account-setup/${second.id}/approve`, auth, { emailCode: '424242' }), 403);
      expect(elsewhere.code).toBe('account_setup_code_ended');
      await json(await post(`/api/account-setup/${first.id}/approve`, asBearer(other), { emailCode: '424242' }), 409);
      const wrong = await json(await post(`/api/account-setup/${first.id}/approve`, auth, { emailCode: '000000' }), 403);
      expect(wrong.code).toBe('account_setup_code_invalid');

      expect(await json(await post(`/api/account-setup/${first.id}/approve`, auth, { emailCode: '424242' }), 200))
        .toEqual({ state: 'published' });
      await json(await post(`/api/account-setup/${first.id}/approve`, auth, { emailCode: '424242' }), 409);
    });

    test('the mailed code names the app the request came from and the node, as hosts', async () => {
      const owner = await account();
      const auth = asBearer(owner);
      mailed.length = 0;
      const named = await json(await post('/api/account-setup/prepare', auth, {
        keyId: owner.keyId, placement: 'tinycloud', requestOrigin: 'https://app.example:8443',
      }), 200);
      await json(await post(`/api/account-setup/${named.id}/email-code`, auth), 200);
      expect(mailed).toHaveLength(1);
      expect(mailed[0]!.to).toBe(`${owner.userId}@example.test`);
      expect(mailed[0]!.subject).toBe('Your code to set up TinyCloud for app.example:8443');
      expect(mailed[0]!.text).toStartWith('app.example:8443 asked OpenKey to set up your TinyCloud account. Your data will be stored on node.tinycloud.xyz.\n\nYour code: ');

      const other = await account();
      mailed.length = 0;
      const unnamed = await json(await post('/api/account-setup/prepare', asBearer(other), { keyId: other.keyId, placement: 'tinycloud' }), 200);
      await json(await post(`/api/account-setup/${unnamed.id}/email-code`, asBearer(other)), 200);
      expect(mailed).toHaveLength(1);
      expect(mailed[0]!.subject).toBe('Your code to set up TinyCloud');
      expect(mailed[0]!.text).toStartWith('An app asked OpenKey to set up your TinyCloud account. Your data will be stored on node.tinycloud.xyz.');
    });

    test('finish answers only for a row this session approved', async () => {
      const owner = await account();
      await createSoftPasskey(prisma, owner.userId, true, web);
      const auth = asBearer(owner);
      const prepared = await prepare(owner, auth);
      await json(await post(`/api/account-setup/${prepared.id}/finish`, auth), 404);
      expect(bootstrapRuns).toBe(0);
    });
  });

  describe('a request stays with the session that made it', () => {
    async function refusedForOthers(rowId: string, others: Record<string, string>[]) {
      for (const headers of others) {
        await json(await post(`/api/account-setup/${rowId}/passkey`, headers), 404);
        await json(await post(`/api/account-setup/${rowId}/email-code`, headers), 404);
        await json(await post(`/api/account-setup/${rowId}/approve`, headers, { emailCode: '000000' }), 409);
        await json(await post(`/api/account-setup/${rowId}/finish`, headers), 404);
      }
    }

    test('a row a cookie session made is closed to a bearer session of the same account, and the reverse', async () => {
      const owner = await account();
      await createSoftPasskey(prisma, owner.userId, true, web);
      const embed = await session(owner.userId);
      const cookieRow = await prepare(owner, asCookie(owner));
      await refusedForOthers(cookieRow.id, [asBearer(embed)]);

      const bearerRow = await prepare({ keyId: await key(owner.userId) }, asBearer(embed));
      await refusedForOthers(bearerRow.id, [asCookie(owner)]);
      // A third session, by bearer, sees neither.
      const third = await session(owner.userId);
      await refusedForOthers(bearerRow.id, [asBearer(third)]);
      await refusedForOthers(cookieRow.id, [asBearer(third)]);
    });

    test('a bearer of another account sees no row', async () => {
      const owner = await account();
      await createSoftPasskey(prisma, owner.userId, true, web);
      const stranger = await account();
      const prepared = await prepare(owner, asBearer(owner));
      await refusedForOthers(prepared.id, [asBearer(stranger)]);
      await json(await post('/api/account-setup/prepare', asBearer(stranger), { keyId: owner.keyId }), 404);
    });
  });

  describe('the owner\'s attempts are limited per account', () => {
    test('wrong attempts across new rows and new sessions share one budget, and a right code stops working once it is spent', async () => {
      const owner = await account();
      let latest: Session = owner;
      for (let attempt = 0; attempt < budget.ACCOUNT_SETUP_BUDGET_LIMITS.verify; attempt += 1) {
        // Each attempt is a new session and a new row, so the per-row and per-session counters restart.
        latest = await session(owner.userId);
        const row = await prepare(owner, asBearer(latest));
        const refused = await json(await post(`/api/account-setup/${row.id}/approve`, asBearer(latest), { emailCode: '000000' }), 403);
        expect(refused.code).toBe('account_setup_code_ended');
      }
      expect(await budgetUsed(owner.userId, 'verify')).toBe(budget.ACCOUNT_SETUP_BUDGET_LIMITS.verify);

      const fresh = await session(owner.userId);
      const row = await prepare(owner, asBearer(fresh));
      await json(await post(`/api/account-setup/${row.id}/email-code`, asBearer(fresh)), 200);
      await knownCode(fresh.sessionId, row.id, '424242');
      const limited = await json(await post(`/api/account-setup/${row.id}/approve`, asBearer(fresh), { emailCode: '424242' }), 429);
      expect(limited).toEqual({ error: 'Too many attempts in the last hour. Wait an hour, then try once more.', code: 'account_setup_rate_limited' });
      // The cookie path of the same account shares the budget.
      const cookieRow = await prepare(owner, asCookie(owner));
      const byCookie = await json(await post(`/api/account-setup/${cookieRow.id}/approve`, asCookie(owner), { emailCode: '424242' }), 429);
      expect(byCookie.code).toBe('account_setup_rate_limited');
      expect(bootstrapRuns).toBe(0);

      // The window ends: the right code approves, and a confirmed attempt costs nothing.
      await prisma.verification.updateMany({
        where: { identifier: `account-setup-budget:verify:${owner.userId}` }, data: { expiresAt: new Date(Date.now() - 1000) },
      });
      await json(await post(`/api/account-setup/${row.id}/approve`, asBearer(fresh), { emailCode: '424242' }), 409);
      const again = await prepare(owner, asBearer(fresh));
      await json(await post(`/api/account-setup/${again.id}/email-code`, asBearer(fresh)), 200);
      await knownCode(fresh.sessionId, again.id, '424242');
      expect(await json(await post(`/api/account-setup/${again.id}/approve`, asBearer(fresh), { emailCode: '424242' }), 200))
        .toEqual({ state: 'published' });
      expect(await budgetUsed(owner.userId, 'verify')).toBe(0);
    });

    test('wrong passkey assertions count against the same budget', async () => {
      const owner = await account();
      const passkey = await createSoftPasskey(prisma, owner.userId, true, web);
      const auth = asBearer(owner);
      const first = await prepare(owner, auth);
      const second = await prepare({ keyId: await key(owner.userId) }, auth);
      for (let attempt = 0; attempt < budget.ACCOUNT_SETUP_BUDGET_LIMITS.verify; attempt += 1) {
        const forSecond = await assertion(passkey, second.id, auth);
        const refused = await json(await post(`/api/account-setup/${first.id}/approve`, auth, { passkeyAssertion: forSecond }), 403);
        expect(refused.code).toBe('passkey_approval_invalid');
      }
      const right = await assertion(passkey, first.id, auth);
      const limited = await json(await post(`/api/account-setup/${first.id}/approve`, auth, { passkeyAssertion: right }), 429);
      expect(limited.code).toBe('account_setup_rate_limited');
      expect(bootstrapRuns).toBe(0);
    });

    test('codes mailed across new rows and new sessions share one budget; a call that mails nothing costs nothing', async () => {
      const owner = await account();
      const first = await prepare(owner, asBearer(owner));
      expect(await json(await post(`/api/account-setup/${first.id}/email-code`, asBearer(owner)), 200)).toMatchObject({ sent: true });
      // The code of this row is live: nothing is mailed, and nothing is spent.
      expect(await json(await post(`/api/account-setup/${first.id}/email-code`, asBearer(owner)), 200)).toMatchObject({ sent: false });
      expect(await budgetUsed(owner.userId, 'send')).toBe(1);

      for (let sent = 1; sent < budget.ACCOUNT_SETUP_BUDGET_LIMITS.send; sent += 1) {
        const next = await session(owner.userId);
        const row = await prepare(owner, asBearer(next));
        expect(await json(await post(`/api/account-setup/${row.id}/email-code`, asBearer(next)), 200)).toMatchObject({ sent: true });
      }
      const last = await session(owner.userId);
      const row = await prepare(owner, asBearer(last));
      const limited = await json(await post(`/api/account-setup/${row.id}/email-code`, asBearer(last)), 429);
      expect(limited).toEqual({ error: 'Too many attempts in the last hour. Wait an hour, then try once more.', code: 'account_setup_rate_limited' });
      expect(await budgetUsed(owner.userId, 'send')).toBe(budget.ACCOUNT_SETUP_BUDGET_LIMITS.send);
      // Another account has its own budget.
      const other = await account();
      const otherRow = await prepare(other, asBearer(other));
      expect(await json(await post(`/api/account-setup/${otherRow.id}/email-code`, asBearer(other)), 200)).toMatchObject({ sent: true });
    });
  });
}
