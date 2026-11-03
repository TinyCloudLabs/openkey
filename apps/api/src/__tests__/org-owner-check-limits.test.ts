import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, setSystemTime, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { createPrismaClient, type PrismaClient } from '@openkey/db';
import { CompactSign, exportJWK, generateKeyPair, type GenerateKeyPairResult } from 'jose';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { getAddress } from 'viem';
import type { Hono } from 'hono';
import type * as OwnerCheckRoutes from '../routes/org-owner-check';
import type * as IssuerJws from '../services/issuer-jws';
import { createOrgRegistrationIntentVerifier } from '../services/org-registration';
import { createSealingContext } from '../services/key-sealing';

// TC-128 / TC-2406: the application-level cap on the issuer-signed owner-check route, and the failure back-off of the
// shared issuer-DID resolver. Real Postgres (PGlite); the issuer DID is a fetch stub whose calls are counted.
// Every clock is injected (the route's `now`, or bun's setSystemTime for the resolver); nothing sleeps.

const root = resolve(import.meta.dir, '../../../..');
const issuer = 'did:web:issuer.credentials.org';
const kid = `${issuer}#controller`;
const AUDIENCE = 'https://api.openkey.so';
const originalFlag = process.env.ORG_KEY_CUSTODY_ENABLED;
const NOW = 1_793_100_000;
const WINDOW_MS = 60_000;

let routes: typeof OwnerCheckRoutes;
let resolver: typeof IssuerJws;
let directory: string;
let db: PrismaClient;
let ocKeys: GenerateKeyPairResult;
let didDocument: Record<string, unknown>;
let didFetches: number;
let didResponse: () => Response;
let didGate: Promise<void> | undefined;
let clock: number;
let prismaAccesses: number;

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), 'openkey-owner-check-limits-'));
  const engine = new PGlite(directory);
  const names = (await readdir(join(root, 'packages/db/prisma/migrations'))).sort();
  for (const name of names.filter((entry) => entry !== 'migration_lock.toml')) {
    await engine.exec(await readFile(join(root, 'packages/db/prisma/migrations', name, 'migration.sql'), 'utf8'));
  }
  await engine.close();
  db = createPrismaClient({ connectionString: `pglite:${directory}` });
  // The query suffix yields a private route instance bound to the real DB exports (same technique as org-owner-check.test.ts).
  routes = await import('../routes/org-owner-check?org-owner-check-limits' as string);
  resolver = await import('../services/issuer-jws?org-owner-check-limits' as string);
});
afterAll(async () => {
  await db?.$disconnect();
  if (directory) await rm(directory, { recursive: true, force: true });
  if (originalFlag === undefined) delete process.env.ORG_KEY_CUSTODY_ENABLED;
  else process.env.ORG_KEY_CUSTODY_ENABLED = originalFlag;
});

beforeEach(async () => {
  process.env.ORG_KEY_CUSTODY_ENABLED = 'true';
  setSystemTime(new Date(NOW * 1000));
  ocKeys = await generateKeyPair('EdDSA', { extractable: true });
  didDocument = { id: issuer, assertionMethod: [kid], verificationMethod: [{ id: kid, controller: issuer, type: 'JsonWebKey2020', publicKeyJwk: await exportJWK(ocKeys.publicKey) }] };
  didFetches = 0;
  didGate = undefined;
  didResponse = () => new Response(JSON.stringify(didDocument), { headers: { 'content-type': 'application/json' } });
  clock = 1_000_000;
  prismaAccesses = 0;
});
afterEach(() => setSystemTime());

const countingPrisma = new Proxy({} as PrismaClient, {
  get(_target, property) {
    if (typeof property === 'string') prismaAccesses += 1;
    return Reflect.get(db, property);
  },
});
async function countedFetch(url: string, init?: RequestInit): Promise<Response> {
  expect(url).toBe('https://issuer.credentials.org/.well-known/did.json');
  expect(init?.redirect).toBe('error');
  didFetches += 1;
  if (didGate) await didGate;
  return didResponse();
}
/** `now` is the route's limiter clock; leave it unset to follow the (bun) system clock the resolver also uses. */
function router(options: { limiterClock?: boolean; limits?: Record<string, number> } = {}): Hono {
  return routes.createOrgOwnerCheckRouter({
    prisma: countingPrisma,
    fetch: countedFetch,
    ...(options.limiterClock ? { now: () => clock } : {}),
    ...(options.limits ? { limits: options.limits } : {}),
  } as Parameters<typeof routes.createOrgOwnerCheckRouter>[0]);
}

type Claims = Record<string, unknown>;
function ownerCheckClaims(keyId: string, account: string, overrides: Claims = {}): Claims {
  return { iss: issuer, aud: AUDIENCE, purpose: 'org-owner-check/v1', keyId, account, jti: randomUUID(), iat: NOW, exp: NOW + 60, ...overrides };
}
async function sign(claims: Claims, header: Record<string, unknown> = {}, key = ocKeys.privateKey): Promise<string> {
  return new CompactSign(new TextEncoder().encode(JSON.stringify(claims))).setProtectedHeader({ alg: 'EdDSA', kid, typ: 'org-owner-check+jwt', ...header }).sign(key);
}
async function ask(app: Hono, token: string | undefined, init: RequestInit = {}) {
  return app.request('/', {
    method: 'POST',
    ...init,
    headers: { origin: 'https://credentials.org', ...(token === undefined ? {} : { authorization: `Bearer ${token}` }), ...(init.headers as Record<string, string> | undefined) },
  });
}
function accessControlHeaders(response: Response): string[] {
  return [...response.headers.keys()].filter((name) => name.toLowerCase().startsWith('access-control-'));
}
async function expectRateLimited(response: Response, retryAfterSeconds?: number) {
  expect(response.status).toBe(429);
  expect(await response.json()).toEqual({ error: 'rate_limited' });
  expect(response.headers.get('retry-after')).toMatch(/^[1-9][0-9]*$/);
  if (retryAfterSeconds !== undefined) expect(response.headers.get('retry-after')).toBe(String(retryAfterSeconds));
  expect(accessControlHeaders(response)).toEqual([]);
}

let sequence = 0;
async function seed() {
  const n = ++sequence;
  const account = `0x${randomBytes(20).toString('hex')}`;
  const keyId = randomUUID();
  const userId = `owner-check-limits-user-${n}`;
  await db.user.create({ data: { id: userId, email: `owner-check-limits-${n}@example.test`, emailVerified: true } });
  await db.ethereumKey.create({ data: {
    id: keyId, custody: 'ORG', userId: null, keyType: 'MANAGED', address: `0x${randomBytes(20).toString('hex')}`, publicKey: 'org',
    sealingContext: createSealingContext(), isCanonicalTinyCloud: false,
  } });
  await db.orgKey.create({ data: { keyId, orgId: `o${'a'.repeat(26)}`, orgName: 'Fixture org', controllerDid: 'did:pkh:eip155:1:0x0' } });
  await db.ethereumKey.create({ data: {
    custody: 'PERSONAL', userId, keyType: 'MANAGED', address: getAddress(account), publicKey: 'personal', sealingContext: createSealingContext(),
  } });
  await db.keyGrant.create({ data: { keyId, role: 'OWNER', granteeUserId: userId, acceptedAt: new Date() } });
  return { keyId, account };
}
async function validToken(seeded: { keyId: string; account: string }, overrides: Claims = {}) {
  return sign(ownerCheckClaims(seeded.keyId, seeded.account, overrides));
}
/** Well-formed token signed by a key the issuer DID does not publish: passes every cheap check, fails the signature. */
async function wrongKeyToken(seeded: { keyId: string; account: string }) {
  const stranger = await generateKeyPair('EdDSA', { extractable: true });
  return sign(ownerCheckClaims(seeded.keyId, seeded.account), {}, stranger.privateKey);
}
async function registrationIntent(): Promise<string> {
  return sign(
    { iss: issuer, aud: AUDIENCE, registrationId: randomUUID(), orgId: `o${'a'.repeat(26)}`, nonce: randomBytes(32).toString('base64url'), handle: 'fixture', displayName: 'Fixture', purpose: 'org-registration/v1', iat: NOW, exp: NOW + 600 },
    { typ: 'org-registration-intent+jwt' },
  );
}
function advance(ms: number) {
  setSystemTime(new Date(Date.now() + ms));
}

describe('issuer DID failure back-off', () => {
  test('50 owner-check requests during a failing DID cause one fetch, not fifty, and every one answers 503', async () => {
    const seeded = await seed();
    didResponse = () => new Response('nope', { status: 500 });
    const app = router();
    const token = await validToken(seeded);
    for (let i = 0; i < 50; i += 1) {
      const response = await ask(app, token);
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({ error: 'issuer_unavailable' });
    }
    expect(didFetches).toBe(1);
  });

  test('50 registration-intent verifications during a failing DID cause one fetch and every one refuses 503', async () => {
    didResponse = () => new Response('nope', { status: 500 });
    const verify = createOrgRegistrationIntentVerifier(countedFetch);
    const intent = await registrationIntent();
    for (let i = 0; i < 50; i += 1) {
      await expect(verify(intent)).rejects.toMatchObject({ status: 503, code: 'registration_issuer_unavailable' });
    }
    expect(didFetches).toBe(1);
  });

  test('every failure kind backs off: a non-2xx status, malformed JSON and a wrong id', async () => {
    const seeded = await seed();
    const token = await validToken(seeded);
    for (const unavailable of [
      () => new Response('nope', { status: 503 }),
      () => new Response('not json'),
      () => new Response(JSON.stringify({ ...didDocument, id: 'did:web:other.example' })),
    ]) {
      didResponse = unavailable;
      didFetches = 0;
      const app = router();
      for (let i = 0; i < 5; i += 1) expect((await ask(app, token)).status).toBe(503);
      expect(didFetches).toBe(1);
    }
  });

  test('the back-off lasts the named window: nothing refetches at 29.999 s, one fetch at 30 s, then it backs off again', async () => {
    const seeded = await seed();
    didResponse = () => new Response('nope', { status: 500 });
    const app = router();
    const token = await validToken(seeded);
    expect((await ask(app, token)).status).toBe(503);
    expect(resolver.ISSUER_DID_FAILURE_BACKOFF_MS).toBe(30_000);
    advance(resolver.ISSUER_DID_FAILURE_BACKOFF_MS - 1);
    for (let i = 0; i < 5; i += 1) expect((await ask(app, token)).status).toBe(503);
    expect(didFetches).toBe(1);
    advance(1);
    expect((await ask(app, token)).status).toBe(503);
    expect(didFetches).toBe(2); // still failing: exactly one more fetch
    for (let i = 0; i < 5; i += 1) expect((await ask(app, token)).status).toBe(503);
    expect(didFetches).toBe(2); // and a fresh window
    advance(resolver.ISSUER_DID_FAILURE_BACKOFF_MS);
    expect((await ask(app, token)).status).toBe(503);
    expect(didFetches).toBe(3);
  });

  test('recovery: once the window ends and the DID is healthy the next request is answered, owner or not', async () => {
    const seeded = await seed();
    const stranger = await seed();
    didResponse = () => new Response('nope', { status: 500 });
    const app = router();
    const token = await validToken(seeded);
    expect((await ask(app, token)).status).toBe(503);
    didResponse = () => new Response(JSON.stringify(didDocument));
    expect((await ask(app, token)).status).toBe(503); // still inside the window: served from the back-off, no fetch
    expect(didFetches).toBe(1);
    advance(resolver.ISSUER_DID_FAILURE_BACKOFF_MS);
    const owner = await ask(app, token);
    expect(owner.status).toBe(200);
    expect(await owner.json()).toEqual({ owner: true });
    const notOwner = await ask(app, await sign(ownerCheckClaims(seeded.keyId, stranger.account, { iat: Date.now() / 1000 | 0, exp: (Date.now() / 1000 | 0) + 60 })));
    expect(await notOwner.json()).toEqual({ owner: false });
    expect(didFetches).toBe(2);
  });

  test('registration verification recovers the same way', async () => {
    didResponse = () => new Response('nope', { status: 500 });
    const verify = createOrgRegistrationIntentVerifier(countedFetch);
    const intent = await registrationIntent();
    await expect(verify(intent)).rejects.toMatchObject({ status: 503 });
    didResponse = () => new Response(JSON.stringify(didDocument));
    await expect(verify(intent)).rejects.toMatchObject({ status: 503 });
    expect(didFetches).toBe(1);
    advance(resolver.ISSUER_DID_FAILURE_BACKOFF_MS);
    expect((await verify(intent)).handle).toBe('fixture');
    expect(didFetches).toBe(2);
  });

  test('503 answers are not authentication failures: they never spend the failed-authentication budget', async () => {
    const seeded = await seed();
    didResponse = () => new Response('nope', { status: 500 });
    const app = router();
    const token = await validToken(seeded);
    for (let i = 0; i < routes.OWNER_CHECK_FAILED_AUTH_PER_MINUTE + 20; i += 1) expect((await ask(app, token)).status).toBe(503);
    didResponse = () => new Response(JSON.stringify(didDocument));
    advance(resolver.ISSUER_DID_FAILURE_BACKOFF_MS);
    expect((await ask(app, await validToken(seeded, { iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 60 }))).status).toBe(200);
  });

  test('a failure never blocks the success path: a cached DID keeps answering known kids while an unknown kid backs off', async () => {
    const seeded = await seed();
    const app = router();
    expect((await ask(app, await validToken(seeded))).status).toBe(200);
    expect(didFetches).toBe(1);
    advance(11_000); // past the forced-refresh interval
    didResponse = () => new Response('nope', { status: 500 });
    const unknown = await sign(ownerCheckClaims(seeded.keyId, seeded.account, { iat: NOW + 11, exp: NOW + 71 }), { kid: `${issuer}#unknown` });
    for (let i = 0; i < 10; i += 1) expect((await ask(app, unknown)).status).toBe(503);
    expect(didFetches).toBe(2); // the one forced refresh failed; the other nine were served from the back-off
    const known = await validToken(seeded, { iat: NOW + 11, exp: NOW + 71 });
    for (let i = 0; i < 10; i += 1) expect((await ask(app, known)).status).toBe(200);
    expect(didFetches).toBe(2);
  });

  test('a healthy DID is unchanged: cached 5 min, one forced refresh per 10 s for an unknown kid, and a rotated key is picked up', async () => {
    const seeded = await seed();
    const app = router();
    for (let i = 0; i < 20; i += 1) expect((await ask(app, await validToken(seeded))).status).toBe(200);
    expect(didFetches).toBe(1);
    const rotated = await generateKeyPair('EdDSA', { extractable: true });
    const rotatedKid = `${issuer}#rotated`;
    didDocument = { id: issuer, assertionMethod: [kid, rotatedKid], verificationMethod: [
      (didDocument.verificationMethod as unknown[])[0],
      { id: rotatedKid, controller: issuer, type: 'JsonWebKey2020', publicKeyJwk: await exportJWK(rotated.publicKey) },
    ] };
    advance(11_000);
    const second = Math.floor(Date.now() / 1000);
    const rotatedToken = await sign(ownerCheckClaims(seeded.keyId, seeded.account, { iat: second, exp: second + 60 }), { kid: rotatedKid }, rotated.privateKey);
    expect((await ask(app, rotatedToken)).status).toBe(200);
    expect(didFetches).toBe(2);
    advance(5 * 60_000);
    const later = Math.floor(Date.now() / 1000);
    expect((await ask(app, await validToken(seeded, { iat: later, exp: later + 60 }))).status).toBe(200);
    expect(didFetches).toBe(3); // the 5 min cache expired
  });

  test('concurrent callers still share one in-flight fetch, and all see the failure', async () => {
    const seeded = await seed();
    let release!: () => void;
    didGate = new Promise<void>((resolveGate) => { release = resolveGate; });
    didResponse = () => new Response('nope', { status: 500 });
    const app = router();
    const token = await validToken(seeded);
    const pending = Array.from({ length: 20 }, () => ask(app, token));
    await Bun.sleep(0);
    release();
    const responses = await Promise.all(pending);
    expect(responses.map((response) => response.status)).toEqual(Array.from({ length: 20 }, () => 503));
    expect(didFetches).toBe(1);
  });
});

describe('global cap on the owner-check route', () => {
  test('the named limits', () => {
    expect(routes.OWNER_CHECK_RATE_LIMIT_PER_MINUTE).toBe(300);
    expect(routes.OWNER_CHECK_FAILED_AUTH_PER_MINUTE).toBe(60);
  });

  test('the cap answers 200 for every request up to the limit and 429 {"error":"rate_limited"} + Retry-After beyond it', async () => {
    const seeded = await seed();
    const app = router({ limiterClock: true });
    const token = await validToken(seeded);
    for (let i = 0; i < routes.OWNER_CHECK_RATE_LIMIT_PER_MINUTE; i += 1) {
      const response = await ask(app, token);
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ owner: true });
    }
    clock += 12_500;
    await expectRateLimited(await ask(app, token), 48);
    await expectRateLimited(await ask(app, token), 48);
    clock += 47_499;
    await expectRateLimited(await ask(app, token), 1);
  });

  test('the cap resets after the window and the window is fixed, not sliding', async () => {
    const seeded = await seed();
    const app = router({ limiterClock: true });
    const token = await validToken(seeded);
    for (let i = 0; i < routes.OWNER_CHECK_RATE_LIMIT_PER_MINUTE; i += 1) await ask(app, token);
    clock += WINDOW_MS - 1;
    expect((await ask(app, token)).status).toBe(429);
    clock += 1;
    for (let i = 0; i < routes.OWNER_CHECK_RATE_LIMIT_PER_MINUTE; i += 1) expect((await ask(app, token)).status).toBe(200);
    expect((await ask(app, token)).status).toBe(429);
  });

  test('an over-cap request does no DID fetch, no DB access, no body read and no token parse', async () => {
    const seeded = await seed();
    const app = router({ limiterClock: true, limits: { perWindow: 2, failedAuthPerWindow: 60 } });
    const token = await validToken(seeded);
    expect((await ask(app, token)).status).toBe(200);
    expect((await ask(app, token)).status).toBe(200);
    const fetchesBefore = didFetches;
    const accessesBefore = prismaAccesses;
    await expectRateLimited(await ask(app, token));
    // A body would answer 400 and a garbage token 401 if either were looked at first.
    await expectRateLimited(await ask(app, token, { body: 'x' }));
    await expectRateLimited(await ask(app, undefined));
    await expectRateLimited(await ask(app, 'not.a.token'));
    didResponse = () => new Response('nope', { status: 500 });
    await expectRateLimited(await ask(app, await validToken(seeded, { jti: randomUUID() })));
    expect(didFetches).toBe(fetchesBefore);
    expect(prismaAccesses).toBe(accessesBefore);
  });

  test('the flag-off 404 precedes the limiter: flag-off requests never answer 429 and never spend the budget', async () => {
    const seeded = await seed();
    const app = router({ limiterClock: true, limits: { perWindow: 3, failedAuthPerWindow: 60 } });
    const token = await validToken(seeded);
    for (const value of ['false', undefined, 'TRUE', '1']) {
      if (value === undefined) delete process.env.ORG_KEY_CUSTODY_ENABLED;
      else process.env.ORG_KEY_CUSTODY_ENABLED = value;
      for (let i = 0; i < 10; i += 1) {
        const response = await ask(app, token);
        expect(response.status).toBe(404);
        expect(accessControlHeaders(response)).toEqual([]);
        expect(response.headers.get('retry-after')).toBeNull();
      }
    }
    expect(didFetches).toBe(0);
    expect(prismaAccesses).toBe(0);
    process.env.ORG_KEY_CUSTODY_ENABLED = 'true';
    for (let i = 0; i < 3; i += 1) expect((await ask(app, token)).status).toBe(200);
    expect((await ask(app, token)).status).toBe(429);
  });

  test('a request below the cap still gets {owner:true|false}', async () => {
    const seeded = await seed();
    const other = await seed();
    const app = router({ limiterClock: true });
    expect(await (await ask(app, await validToken(seeded))).json()).toEqual({ owner: true });
    expect(await (await ask(app, await sign(ownerCheckClaims(seeded.keyId, other.account)))).json()).toEqual({ owner: false });
  });

  test('the limiter holds constant state: a long flood of distinct tokens is counted by two counters, not keyed per request', async () => {
    const app = router({ limiterClock: true, limits: { perWindow: 5, failedAuthPerWindow: 5 } });
    for (let i = 0; i < 500; i += 1) {
      const response = await ask(app, `a.${i}.b`);
      expect(response.status).toBe(i < 5 ? 401 : 429);
    }
    clock += WINDOW_MS;
    expect((await ask(app, 'again')).status).toBe(401);
  });
});

describe('failed-authentication budget', () => {
  test('the named budget is spent by failures only: 60 garbage requests answer 401, the next answers 429 without any DID work', async () => {
    const app = router({ limiterClock: true });
    for (let i = 0; i < routes.OWNER_CHECK_FAILED_AUTH_PER_MINUTE; i += 1) {
      const response = await ask(app, i % 2 === 0 ? undefined : `garbage.${i}.x`);
      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({ error: 'unauthorized' });
    }
    clock += 20_000;
    await expectRateLimited(await ask(app, undefined), 40);
    await expectRateLimited(await ask(app, 'garbage.again.x'), 40);
    expect(didFetches).toBe(0);
    expect(prismaAccesses).toBe(0);
  });

  test('once the budget is spent a well-formed token signed by the wrong key is also answered 429', async () => {
    const seeded = await seed();
    const app = router({ limiterClock: true });
    for (let i = 0; i < routes.OWNER_CHECK_FAILED_AUTH_PER_MINUTE; i += 1) expect((await ask(app, await wrongKeyToken(seeded))).status).toBe(401);
    await expectRateLimited(await ask(app, await wrongKeyToken(seeded)));
  });

  test('a request carrying a valid token still passes while the global cap has room, whatever the flood', async () => {
    const seeded = await seed();
    const app = router({ limiterClock: true });
    for (let i = 0; i < routes.OWNER_CHECK_FAILED_AUTH_PER_MINUTE + 30; i += 1) await ask(app, undefined);
    expect((await ask(app, undefined)).status).toBe(429);
    const response = await ask(app, await validToken(seeded));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ owner: true });
  });

  test('successes do not spend it: after 100 valid requests a garbage request is still 401 and all 60 failures still answer 401', async () => {
    const seeded = await seed();
    const app = router({ limiterClock: true });
    const token = await validToken(seeded);
    for (let i = 0; i < 100; i += 1) expect((await ask(app, token)).status).toBe(200);
    for (let i = 0; i < routes.OWNER_CHECK_FAILED_AUTH_PER_MINUTE; i += 1) expect((await ask(app, undefined)).status).toBe(401);
    expect((await ask(app, undefined)).status).toBe(429);
  });

  test('it resets after its window', async () => {
    const app = router({ limiterClock: true });
    for (let i = 0; i < routes.OWNER_CHECK_FAILED_AUTH_PER_MINUTE + 1; i += 1) await ask(app, undefined);
    expect((await ask(app, undefined)).status).toBe(429);
    clock += WINDOW_MS - 1;
    expect((await ask(app, undefined)).status).toBe(429);
    clock += 1;
    expect((await ask(app, undefined)).status).toBe(401);
  });

  test('failures also spend the global cap: it bounds the whole route, whatever the answer', async () => {
    const app = router({ limiterClock: true, limits: { perWindow: 10, failedAuthPerWindow: 60 } });
    for (let i = 0; i < 10; i += 1) expect((await ask(app, undefined)).status).toBe(401);
    await expectRateLimited(await ask(app, undefined));
  });
});
