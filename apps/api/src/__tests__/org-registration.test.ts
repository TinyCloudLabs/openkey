import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, setSystemTime, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { createPrismaClient, type PrismaClient } from '@openkey/db';
import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { jwt } from 'better-auth/plugins';
import { createMiddleware } from 'hono/factory';
import type { Hono } from 'hono';
import type { SessionContext } from '../middleware/session';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { CompactSign, createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify, SignJWT, type GenerateKeyPairResult, type JWTPayload } from 'jose';
import type * as OrgKeysRoutes from '../routes/org-keys';
import { addPasskey, assertionFor, fakeTee, type PasskeyFixture } from './org-keys-fixtures';

const root = resolve(import.meta.dir, '../../../..');
const origin = 'https://openkey.test';
const rpID = 'openkey.test';
const issuer = 'did:web:issuer.credentials.org';
const kid = `${issuer}#controller`;
const originalFlag = process.env.ORG_KEY_CUSTODY_ENABLED;
const proofAuth = betterAuth({ baseURL: 'https://api.openkey.test', secret: 'registration-local-fixture-9Z1m5H3k7P4r8T2v6B0n', database: memoryAdapter({ user: [], session: [], account: [], verification: [], jwks: [] }), plugins: [jwt()] });
interface IssuedIntent {
  claims: { iss: string; aud: string; registrationId: string; orgId: string; nonce: string; handle: string; displayName: string; purpose: string; iat: number; exp: number };
  body: { intentJws: string; registrationId: string; orgId: string; nonce: string; handle: string; orgName: string };
}
let createRouter: typeof OrgKeysRoutes.createOrgKeysRouter;
let migrationSql: string[];
let directory: string;
let db: PrismaClient;
let passkey: PasskeyFixture;
let actor = { userId: 'registration-owner', sessionId: 'registration-session' };
let ocKeys: GenerateKeyPairResult;
let didDocument: Record<string, unknown>;
let fetchResult: () => Response;
let signProof: (claims: JWTPayload) => Promise<string>;
let completion: (url: string, init: RequestInit) => Promise<Response>;
let completed: Map<string, Record<string, unknown>>;
let deliveredProofs: string[];

beforeAll(async () => {
  const names = (await readdir(join(root, 'packages/db/prisma/migrations'))).sort();
  migrationSql = await Promise.all(names.filter((name) => name !== 'migration_lock.toml').map((name) =>
    readFile(join(root, 'packages/db/prisma/migrations', name, 'migration.sql'), 'utf8')));
  // A private route instance must capture real DB exports, not another file's scoped module fixture.
  ({ createOrgKeysRouter: createRouter } = await import('../routes/org-keys?org-registration-contract' as string));
});

beforeEach(async () => {
  process.env.ORG_KEY_CUSTODY_ENABLED = 'true';
  directory = await mkdtemp(join(tmpdir(), 'openkey-registration-'));
  const engine = new PGlite(directory);
  for (const sql of migrationSql) await engine.exec(sql);
  await engine.close();
  db = createPrismaClient({ connectionString: `pglite:${directory}` });
  actor = { userId: 'registration-owner', sessionId: 'registration-session' };
  await db.user.createMany({ data: [
    { id: actor.userId, email: 'registration-owner@example.test', emailVerified: true },
    { id: 'another-owner', email: 'another-owner@example.test', emailVerified: true },
  ] });
  await db.session.createMany({ data: [
    { id: actor.sessionId, userId: actor.userId, token: 'registration-fixture-session', expiresAt: new Date(Date.now() + 3_600_000), lastPasskeyAt: new Date() },
    { id: 'another-session', userId: actor.userId, token: 'another-registration-fixture-session', expiresAt: new Date(Date.now() + 3_600_000), lastPasskeyAt: new Date() },
    { id: 'another-owner-session', userId: 'another-owner', token: 'another-owner-fixture-session', expiresAt: new Date(Date.now() + 3_600_000), lastPasskeyAt: new Date() },
  ] });
  const state = { passkeys: [] as Record<string, unknown>[] };
  passkey = addPasskey(state, actor.userId);
  const stored = state.passkeys[0]!;
  await db.passkey.create({ data: { id: 'registration-passkey', userId: actor.userId, credentialID: passkey.credentialID, publicKey: stored.publicKey as string, counter: 0, deviceType: 'singleDevice', backedUp: false } });
  ocKeys = await generateKeyPair('EdDSA', { extractable: true });
  didDocument = { id: issuer, assertionMethod: [kid], verificationMethod: [{ id: kid, controller: issuer, type: 'JsonWebKey2020', publicKeyJwk: await exportJWK(ocKeys.publicKey) }] };
  fetchResult = () => new Response(JSON.stringify(didDocument), { headers: { 'content-type': 'application/json' } });
  await proofAuth.api.getJwks();
  signProof = async (claims) => (await proofAuth.api.signJWT({ body: { payload: claims } })).token;
  completed = new Map();
  deliveredProofs = [];
  completion = async (url, init) => {
    if (init.method !== 'POST') return new Response(null, { status: 405 });
    const { ownerProof } = JSON.parse(String(init.body));
    const prior = completed.get(ownerProof);
    if (prior) return new Response(JSON.stringify(prior), { status: 200 });
    const { payload } = await jwtVerify(ownerProof, createLocalJWKSet(await proofAuth.api.getJwks()), { issuer: 'https://api.openkey.so/api/auth', audience: 'https://witness.credentials.org' });
    if (url !== `https://witness.credentials.org/v1/org-registration-intents/${payload.registrationId}/complete`) return new Response(null, { status: 404 });
    const result = { registrationId: payload.registrationId, orgId: payload.orgId, handle: payload.handle, displayName: payload.displayName, controllerDid: payload.controllerDid, issuerDid: `did:web:${payload.orgId}.orgs.credentials.org`, tier: 'free' };
    completed.set(ownerProof, result);
    return new Response(JSON.stringify(result), { status: 201 });
  };
});

afterEach(async () => {
  setSystemTime();
  await db?.$disconnect();
  if (directory) await rm(directory, { recursive: true, force: true });
});
afterAll(() => {
  if (originalFlag === undefined) delete process.env.ORG_KEY_CUSTODY_ENABLED;
  else process.env.ORG_KEY_CUSTODY_ENABLED = originalFlag;
});

function app(authenticated = true) {
  return createRouter({
    prisma: db,
    tee: fakeTee(),
    webauthn: () => ({ rpID, origin }),
    sessionMiddleware: createMiddleware(async (c, next) => {
      if (!authenticated) return c.json({ error: 'Unauthorized' }, 401);
      c.set('user', { id: actor.userId, email: `${actor.userId}@example.test` });
      c.set('session', { id: actor.sessionId, userId: actor.userId, expiresAt: new Date(Date.now() + 3_600_000) });
      await next();
    }),
    registration: {
      fetch: async (url, init) => {
        if (url === 'https://issuer.credentials.org/.well-known/did.json') return fetchResult();
        deliveredProofs.push(JSON.parse(String(init?.body)).ownerProof);
        return completion(url, init!);
      },
      signProof: (claims) => signProof(claims),
    },
  });
}

async function intent(overrides: Record<string, unknown> = {}, header: Record<string, unknown> = {}): Promise<IssuedIntent> {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: issuer, aud: 'https://api.openkey.so', registrationId: randomUUID(), orgId: `o${'a'.repeat(26)}`, nonce: randomBytes(32).toString('base64url'), handle: 'registration-fixture', displayName: 'Exact org 🐙', purpose: 'org-registration/v1', iat: now, exp: now + 600, ...overrides };
  const intentJws = await new SignJWT(claims).setProtectedHeader({ alg: 'EdDSA', kid, typ: 'org-registration-intent+jwt', ...header }).sign(ocKeys.privateKey);
  return { claims, body: { intentJws, registrationId: claims.registrationId, orgId: claims.orgId, nonce: claims.nonce, handle: claims.handle, orgName: claims.displayName } };
}

function post(router: Hono<SessionContext>, body: unknown, requestOrigin = origin) {
  return router.request('/', { method: 'POST', headers: { 'content-type': 'application/json', origin: requestOrigin }, body: JSON.stringify(body) });
}

async function consent(router: Hono<SessionContext>, issued: IssuedIntent, options: Parameters<typeof assertionFor>[2] = {}) {
  const response = await post(router, issued.body);
  expect(response.status).toBe(200);
  const { registrationChallenge } = await response.json();
  const assertion = assertionFor(passkey, registrationChallenge.challenge, { origin, rpID, ...options });
  return { ...issued.body, challengeNonce: registrationChallenge.challengeNonce, assertion };
}

async function complete(router: Hono<SessionContext>, issued: IssuedIntent) {
  return post(router, await consent(router, issued));
}

describe('org registration authenticated intent contract', () => {
  test('missing signed intent cannot create a caller-selected org key', async () => {
    const response = await post(app(), { orgId: 'caller-org', orgName: 'Caller org' });
    expect(response.status).toBe(400);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('flag off remains 404 and cannot create a registration key', async () => {
    process.env.ORG_KEY_CUSTODY_ENABLED = 'false';
    const issued = await intent();
    expect((await post(app(), issued.body)).status).toBe(404);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('a valid intent still requires an authenticated actor', async () => {
    expect((await post(app(false), (await intent()).body)).status).toBe(401);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('challenge is bound to the exact intent and does not create a key', async () => {
    const issued = await intent();
    const router = app();
    const first = await post(router, issued.body);
    expect(first.status).toBe(200);
    const one = (await first.json()).registrationChallenge;
    const two = (await (await post(router, issued.body)).json()).registrationChallenge;
    expect(one.challengeNonce).not.toBe(two.challengeNonce);
    expect(one.challenge).not.toBe(two.challenge);
    expect(await db.ethereumKey.count()).toBe(0);
    const assertion = assertionFor(passkey, one.challenge, { origin, rpID });
    expect((await post(router, { ...issued.body, challengeNonce: two.challengeNonce, assertion })).status).toBe(403);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('new consent sweeps expired challenges but preserves live consent and immutable receipts', async () => {
    const router = app();
    const bound = await intent();
    const approval = await complete(router, bound);
    expect(approval.status).toBe(201);
    const approved = await approval.json();
    const firstProof = deliveredProofs[0];
    const unused = await intent();
    expect((await post(router, unused.body)).status).toBe(200);
    const live = await intent();
    const liveResponse = await post(router, live.body);
    const liveNonce = (await liveResponse.json()).registrationChallenge.challengeNonce;
    await db.orgKeyRegistrationChallenge.updateMany({
      where: { registrationId: { in: [bound.body.registrationId, unused.body.registrationId] } },
      data: { expiresAt: new Date(Date.now() - 1) },
    });
    expect((await post(router, (await intent()).body)).status).toBe(200);
    expect(await db.orgKeyRegistrationChallenge.count({ where: { registrationId: { in: [bound.body.registrationId, unused.body.registrationId] } } })).toBe(0);
    expect((await db.orgKeyRegistrationChallenge.findUniqueOrThrow({ where: { challengeNonce: liveNonce } })).consumedAt).toBeNull();
    const retry = await post(router, bound.body);
    expect(retry.status).toBe(200);
    expect((await retry.json()).key).toEqual(approved.key);
    expect(deliveredProofs[1]).toBe(firstProof);
  });

  test('verified consent creates one OWNER binding and an OC-verifiable exact proof', async () => {
    const issued = await intent();
    const response = await complete(app(), issued);
    expect(response.status).toBe(201);
    const result = await response.json();
    const jwks = await proofAuth.api.getJwks();
    const binding = await db.orgKeyRegistration.findUniqueOrThrow({ where: { registrationId: issued.claims.registrationId } });
    expect(result.registrationProof).toBeUndefined();
    expect(JSON.stringify(result).includes(binding.proof)).toBe(false);
    const verified = await jwtVerify(binding.proof, createLocalJWKSet(jwks), { issuer: 'https://api.openkey.so/api/auth', audience: 'https://witness.credentials.org' });
    expect(verified.protectedHeader).toEqual({ alg: 'EdDSA', kid: jwks.keys[0]!.kid });
    const { iat, exp, jti } = verified.payload;
    expect(jti).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(Number.isInteger(iat) && Number.isInteger(exp)).toBe(true);
    expect(exp).toBe(Math.min(issued.claims.exp, Number(iat) + 300));
    expect(verified.payload).toEqual({ iss: 'https://api.openkey.so/api/auth', aud: 'https://witness.credentials.org', sub: actor.userId, registrationId: issued.claims.registrationId, orgId: issued.claims.orgId, nonce: issued.claims.nonce, handle: issued.claims.handle, displayName: issued.claims.displayName, keyId: result.key.keyId, controllerDid: result.key.controllerDid, purpose: 'org-registration/v1', iat, exp, jti });
    const key = await db.ethereumKey.findUniqueOrThrow({ where: { id: result.key.keyId } });
    expect(key).toMatchObject({ custody: 'ORG', userId: null, isCanonicalTinyCloud: false });
    expect(result.key.controllerDid).toBe(`did:pkh:eip155:1:${key.address}`);
    expect(await db.keyGrant.findUniqueOrThrow({ where: { id: result.key.grantId } })).toMatchObject({ keyId: key.id, role: 'OWNER', granteeUserId: actor.userId, revokedAt: null });
    expect(await db.ethereumKey.count()).toBe(1);
    await expect(jwtVerify(binding.proof, createLocalJWKSet(jwks), { issuer: 'https://api.openkey.so/api/auth', audience: 'https://wrong.example' })).rejects.toThrow();
  });

  test('the actual OC RegistrationService intent and DID vector creates its exact controller binding', async () => {
    // Public synthetic output from RegistrationService::create/config::did_document; no fixture private key.
    setSystemTime(new Date(1_800_000_000_000));
    await db.session.updateMany({ data: { expiresAt: new Date(Date.now() + 3_600_000) } });
    didDocument = { id: issuer, assertionMethod: [kid], verificationMethod: [{ id: kid, controller: issuer, type: 'JsonWebKey2020', publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: '6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw' } }] };
    const issued: IssuedIntent = {
      claims: { iss: issuer, aud: 'https://api.openkey.so', registrationId: '0ad181c0-5eea-4944-80ab-65ac5c68e53d', orgId: 'o7zcifkn2f3h2kareh6n3jxlvbq', nonce: 'Z8M4jtvo7k2rnPGn1hFpQwzyOYpjdREsucYvgd_HXWk', handle: 'synthetic-k2-org', displayName: 'Exact org 🐙', purpose: 'org-registration/v1', iat: 1_800_000_000, exp: 1_800_000_600 },
      body: {
        intentJws: 'eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6aXNzdWVyLmNyZWRlbnRpYWxzLm9yZyNjb250cm9sbGVyIiwidHlwIjoib3JnLXJlZ2lzdHJhdGlvbi1pbnRlbnQrand0In0.eyJhdWQiOiJodHRwczovL2FwaS5vcGVua2V5LnNvIiwiZGlzcGxheU5hbWUiOiJFeGFjdCBvcmcg8J-QmSIsImV4cCI6MTgwMDAwMDYwMCwiaGFuZGxlIjoic3ludGhldGljLWsyLW9yZyIsImlhdCI6MTgwMDAwMDAwMCwiaXNzIjoiZGlkOndlYjppc3N1ZXIuY3JlZGVudGlhbHMub3JnIiwibm9uY2UiOiJaOE00anR2bzdrMnJuUEduMWhGcFF3enlPWXBqZFJFc3VjWXZnZF9IWFdrIiwib3JnSWQiOiJvN3pjaWZrbjJmM2gya2FyZWg2bjNqeGx2YnEiLCJwdXJwb3NlIjoib3JnLXJlZ2lzdHJhdGlvbi92MSIsInJlZ2lzdHJhdGlvbklkIjoiMGFkMTgxYzAtNWVlYS00OTQ0LTgwYWItNjVhYzVjNjhlNTNkIn0.4Yz0CbpnEOdPCozUtPvOsrUCw3HN4cKeDIOzIF-k5TG4nrFdg7jZHoxj19z4FiosJxGznwQt2Es3mbX9WTiwBg',
        registrationId: '0ad181c0-5eea-4944-80ab-65ac5c68e53d', orgId: 'o7zcifkn2f3h2kareh6n3jxlvbq', nonce: 'Z8M4jtvo7k2rnPGn1hFpQwzyOYpjdREsucYvgd_HXWk', handle: 'synthetic-k2-org', orgName: 'Exact org 🐙',
      },
    };
    const response = await complete(app(), issued);
    expect(response.status).toBe(201);
    const result = await response.json();
    const binding = await db.orgKeyRegistration.findUniqueOrThrow({ where: { registrationId: issued.claims.registrationId } });
    const verified = await jwtVerify(binding.proof, createLocalJWKSet(await proofAuth.api.getJwks()), { issuer: 'https://api.openkey.so/api/auth', audience: 'https://witness.credentials.org' });
    expect(verified.payload).toMatchObject({ registrationId: issued.claims.registrationId, orgId: issued.claims.orgId, nonce: issued.claims.nonce, handle: issued.claims.handle, displayName: issued.claims.displayName, sub: actor.userId, controllerDid: result.key.controllerDid });
    expect(await db.ethereumKey.count()).toBe(1);
  });

  test('same intent survives a new DB client and returns immutable key/proof after expiry', async () => {
    const issued = await intent();
    const response = await complete(app(), issued);
    expect(response.status).toBe(201);
    const first = await response.json();
    const original = await db.orgKeyRegistration.findUniqueOrThrow({ where: { registrationId: issued.claims.registrationId } });
    await db.$disconnect();
    db = createPrismaClient({ connectionString: `pglite:${directory}` });
    setSystemTime(new Date((issued.claims.exp + 1) * 1000));
    const replay = await post(app(), issued.body);
    expect(replay.status).toBe(200);
    expect(await replay.json()).toEqual(first);
    expect(await db.ethereumKey.count()).toBe(1);
    expect(await db.keyGrant.count()).toBe(1);
    expect(deliveredProofs.every(proof => proof === original.proof)).toBe(true);
    const stored = await db.orgKeyRegistration.findUniqueOrThrow({ where: { registrationId: issued.claims.registrationId } });
    expect(stored.jti).toBe(original.jti);
    expect(stored.proof === original.proof).toBe(true);
    await expect(jwtVerify(original.proof, createLocalJWKSet(await proofAuth.api.getJwks()), { issuer: 'https://api.openkey.so/api/auth', audience: 'https://witness.credentials.org' })).rejects.toThrow();
  });

  test('another account cannot reuse an existing registration binding', async () => {
    const issued = await intent();
    expect((await complete(app(), issued)).status).toBe(201);
    actor = { userId: 'another-owner', sessionId: 'another-owner-session' };
    expect((await post(app(), issued.body)).status).toBe(409);
    expect(await db.ethereumKey.count()).toBe(1);
  });

  test('a newly signed conflicting tuple cannot reuse an existing registrationId', async () => {
    const issued = await intent();
    expect((await complete(app(), issued)).status).toBe(201);
    const changed = await intent({ ...issued.claims, displayName: 'Different org' });
    expect((await post(app(), changed.body)).status).toBe(409);
    expect(await db.ethereumKey.count()).toBe(1);
  });

  test('K1 F7: no passkey assertion cannot create a key despite session freshness', async () => {
    const issued = await intent();
    const response = await post(app(), issued.body);
    expect(response.status).toBe(200);
    expect((await response.json()).registrationProof).toBeUndefined();
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('a new session cannot consume another session challenge', async () => {
    const issued = await intent();
    const router = app();
    const body = await consent(router, issued);
    actor.sessionId = 'another-session';
    expect((await post(router, body)).status).toBe(403);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('passkey user verification is required', async () => {
    const issued = await intent();
    const router = app();
    expect((await post(router, await consent(router, issued, { userVerified: false }))).status).toBe(403);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('a request from a different origin cannot start owner consent', async () => {
    expect((await post(app(), (await intent()).body, 'https://other.test')).status).toBe(403);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  for (const options of [{ origin: 'https://other.test' }, { rpID: 'other.test' }]) {
    test(`a passkey assertion bound to another relying party is refused: ${JSON.stringify(options)}`, async () => {
      const issued = await intent();
      const router = app();
      expect((await post(router, await consent(router, issued, options))).status).toBe(403);
      expect(await db.ethereumKey.count()).toBe(0);
    });
  }

  test('a passkey belonging to another account cannot approve the intent', async () => {
    const issued = await intent();
    const router = app();
    const body = await consent(router, issued);
    await db.passkey.update({ where: { id: 'registration-passkey' }, data: { userId: 'another-owner' } });
    expect((await post(router, body)).status).toBe(403);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('duplicate request members cannot start registration even when values agree', async () => {
    const issued = await intent();
    const raw = `${JSON.stringify(issued.body).slice(0, -1)},"orgName":${JSON.stringify(issued.body.orgName)}}`;
    const response = await app().request('/', { method: 'POST', headers: { 'content-type': 'application/json', origin }, body: raw });
    expect(response.status).toBe(400);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('an escaped duplicate signed claim cannot bypass exact intent verification', async () => {
    const issued = await intent();
    const raw = `${JSON.stringify(issued.claims).slice(0, -1)},"\\u0061ud":"https://api.openkey.so"}`;
    const token = await new CompactSign(Buffer.from(raw)).setProtectedHeader({ alg: 'EdDSA', kid, typ: 'org-registration-intent+jwt' }).sign(ocKeys.privateKey);
    expect((await post(app(), { ...issued.body, intentJws: token })).status).toBe(400);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('duplicate protected-header members cannot authorize a signed intent', async () => {
    const issued = await intent();
    const header = Buffer.from(`{"alg":"EdDSA","kid":${JSON.stringify(kid)},"typ":"org-registration-intent+jwt","\\u0061lg":"EdDSA"}`).toString('base64url');
    const payload = Buffer.from(JSON.stringify(issued.claims)).toString('base64url');
    const signed = `${header}.${payload}`;
    const signature = Buffer.from(await crypto.subtle.sign('Ed25519', ocKeys.privateKey, Buffer.from(signed))).toString('base64url');
    expect((await post(app(), { ...issued.body, intentJws: `${signed}.${signature}` })).status).toBe(400);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('a caller-supplied controllerDid in the signed intent is refused without a key', async () => {
    const issued = await intent({ controllerDid: 'did:pkh:eip155:1:0x0000000000000000000000000000000000000001' });
    expect((await post(app(), issued.body)).status).toBe(400);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('a caller-supplied controllerDid in the request is refused without a key', async () => {
    const issued = await intent();
    expect((await post(app(), { ...issued.body, controllerDid: 'did:pkh:eip155:1:0x0000000000000000000000000000000000000001' })).status).toBe(400);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('a missing actual OWNER grant rolls back key creation and consent consumption', async () => {
    await db.$executeRawUnsafe(`CREATE FUNCTION registration_fixture_downgrade_owner() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN NEW.role = 'ADMIN'; RETURN NEW; END $$`);
    await db.$executeRawUnsafe(`CREATE TRIGGER registration_fixture_downgrade_owner BEFORE INSERT ON key_grants
      FOR EACH ROW EXECUTE FUNCTION registration_fixture_downgrade_owner()`);
    const issued = await intent();
    const router = app();
    const body = await consent(router, issued);
    const response = await post(router, body);
    expect(response.status).toBe(403);
    expect((await response.json()).registrationProof).toBeUndefined();
    expect(await db.ethereumKey.count()).toBe(0);
    expect(await db.keyGrant.count()).toBe(0);
    expect((await db.passkey.findUniqueOrThrow({ where: { id: 'registration-passkey' } })).counter).toBe(0);
    expect((await db.orgKeyRegistrationChallenge.findUniqueOrThrow({ where: { challengeNonce: body.challengeNonce } })).consumedAt).toBeNull();
  });

  test('simultaneous approvals for one intent persist only one controller and immutable proof', async () => {
    const issued = await intent();
    const router = app();
    const first = await consent(router, issued, { counter: 1 });
    const second = await consent(router, issued, { counter: 2 });
    const responses = await Promise.all([post(router, first), post(router, second)]);
    expect(responses.map((response) => response.status).sort()).toEqual([200, 201]);
    expect(await responses[0]!.json()).toEqual(await responses[1]!.json());
    expect(await db.ethereumKey.count()).toBe(1);
    expect(await db.orgKey.count()).toBe(1);
    expect(await db.keyGrant.count()).toBe(1);
    expect(await db.orgKeyRegistration.count()).toBe(1);
  });

  test('lost OC completion response retries the same persisted proof without another passkey or key', async () => {
    const issued = await intent();
    const router = app();
    const realCompletion = completion;
    completion = async (url, init) => { await realCompletion(url, init); return new Response(null, { status: 503 }); };
    expect((await complete(router, issued)).status).toBe(503);
    const original = await db.orgKeyRegistration.findUniqueOrThrow({ where: { registrationId: issued.claims.registrationId } });
    completion = realCompletion;
    setSystemTime(new Date((issued.claims.exp + 1) * 1000));
    const retried = await post(router, issued.body);
    expect(retried.status).toBe(200);
    expect((await retried.json()).registrationProof).toBeUndefined();
    expect(deliveredProofs.every(proof => proof === original.proof)).toBe(true);
    expect(await db.ethereumKey.count()).toBe(1);
    expect(await db.keyGrant.count()).toBe(1);
    expect(await db.orgKeyRegistration.count()).toBe(1);
  });

  for (const change of [
    { registrationId: '00000000-0000-4000-8000-000000000000' }, { orgId: `o${'b'.repeat(26)}` },
    { handle: 'another-org' }, { displayName: 'Another org' },
    { controllerDid: 'did:pkh:eip155:1:0x0000000000000000000000000000000000000001' },
    { issuerDid: 'did:web:other.example' }, { tier: 'paid' },
  ]) {
    test(`OC cannot confirm a different registration tuple: ${JSON.stringify(change)}`, async () => {
      const issued = await intent();
      const realCompletion = completion;
      completion = async (url, init) => {
        const result = await (await realCompletion(url, init)).json();
        return new Response(JSON.stringify({ ...result, ...change }), { status: 201 });
      };
      const response = await complete(app(), issued);
      expect(response.status).toBe(503);
      expect((await response.json()).registration).toBeUndefined();
      expect(await db.ethereumKey.count()).toBe(1);
      expect(await db.orgKeyRegistration.count()).toBe(1);
    });
  }

  for (const status of [409, 410]) {
    test(`OC terminal ${status} never reports completion or rolls back the persisted key`, async () => {
      completion = async () => new Response(null, { status });
      const response = await complete(app(), await intent());
      expect(response.status).toBe(status);
      expect((await response.json()).registrationProof).toBeUndefined();
      expect(await db.ethereumKey.count()).toBe(1);
      expect(await db.orgKeyRegistration.count()).toBe(1);
    });
  }

  test('OC redirects are not accepted as completion', async () => {
    completion = async () => new Response(null, { status: 302, headers: { location: 'https://other.example' } });
    expect((await complete(app(), await intent())).status).toBe(503);
    expect(await db.orgKeyRegistration.count()).toBe(1);
  });

  test('an expired consent challenge cannot create a key for an otherwise live intent', async () => {
    const issued = await intent();
    const router = app();
    const body = await consent(router, issued);
    setSystemTime(new Date(Date.now() + 301_000));
    expect((await post(router, body)).status).toBe(403);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('a failed proof signer rolls back key, grant, challenge consumption and counter', async () => {
    const issued = await intent();
    const router = app();
    const body = await consent(router, issued);
    const realSigner = signProof;
    signProof = async () => { throw new Error('isolated signer unavailable'); };
    expect((await post(router, body)).status).toBe(503);
    expect(await db.ethereumKey.count()).toBe(0);
    expect(await db.keyGrant.count()).toBe(0);
    expect((await db.passkey.findUniqueOrThrow({ where: { id: 'registration-passkey' } })).counter).toBe(0);
    signProof = realSigner;
    expect((await post(router, body)).status).toBe(201);
    expect(await db.ethereumKey.count()).toBe(1);
  });

  test('a non-EdDSA issuer output fails closed without a durable key', async () => {
    const issued = await intent();
    const router = app();
    const body = await consent(router, issued);
    const realSigner = signProof;
    signProof = async (claims) => {
      const token = await realSigner(claims);
      const parts = token.split('.');
      parts[0] = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'wrong-algorithm' })).toString('base64url');
      return parts.join('.');
    };
    expect((await post(router, body)).status).toBe(503);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  for (const field of ['registrationId', 'orgId', 'nonce', 'handle', 'orgName'] as const) {
    test(`unsigned ${field} substitution cannot change the signed intent`, async () => {
      const issued = await intent();
      expect((await post(app(), { ...issued.body, [field]: `${issued.body[field]}changed` })).status).toBe(400);
      expect(await db.ethereumKey.count()).toBe(0);
    });
  }

  for (const change of [
    { aud: 'https://wrong.example' },
    { iss: 'did:web:wrong.example' },
    { purpose: 'other-purpose' },
    { handle: 'admin' },
    { handle: 'xn--org' },
    { orgId: 'caller-selected' },
    { displayName: 'x'.repeat(257) },
    { displayName: 'a\u202eb' },
    { displayName: '\ud800' },
  ]) {
    test(`invalid signed intent ${JSON.stringify(change)} cannot start registration`, async () => {
      const issued = await intent(change);
      expect((await post(app(), issued.body)).status).toBe(400);
      expect(await db.ethereumKey.count()).toBe(0);
    });
  }

  test('a signature from another key cannot authorize an otherwise exact intent', async () => {
    const issued = await intent();
    const other = await generateKeyPair('EdDSA');
    const token = await new SignJWT(issued.claims).setProtectedHeader({ alg: 'EdDSA', kid, typ: 'org-registration-intent+jwt' }).sign(other.privateKey);
    expect((await post(app(), { ...issued.body, intentJws: token })).status).toBe(403);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('duplicate DID document members fail closed before issuing consent', async () => {
    const issued = await intent();
    fetchResult = () => new Response(`${JSON.stringify(didDocument).slice(0, -1)},"id":${JSON.stringify(issuer)}}`);
    expect((await post(app(), issued.body)).status).toBe(503);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('unknown signing keys refresh the pinned issuer only once per ten seconds', async () => {
    const issued = await intent({}, { kid: `${issuer}#unknown` });
    let fetches = 0;
    fetchResult = () => { fetches += 1; return new Response(JSON.stringify(didDocument)); };
    const router = app();
    expect((await post(router, issued.body)).status).toBe(403);
    expect((await post(router, issued.body)).status).toBe(403);
    expect(fetches).toBe(2); // Initial resolution plus one forced refresh, not a refresh per request.
    setSystemTime(new Date(Date.now() + 10_001));
    expect((await post(router, issued.body)).status).toBe(403);
    expect(fetches).toBe(3);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('unasserted DID verification material cannot authorize an intent', async () => {
    const issued = await intent();
    didDocument.assertionMethod = [];
    expect((await post(app(), issued.body)).status).toBe(403);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('DID redirects fail closed without following another issuer', async () => {
    const issued = await intent();
    fetchResult = () => new Response(null, { status: 302, headers: { location: 'https://other.example/did.json' } });
    expect((await post(app(), issued.body)).status).toBe(503);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('expired new intent is refused without a key or challenge consumption', async () => {
    const now = Math.floor(Date.now() / 1000);
    const issued = await intent({ iat: now - 601, exp: now - 1 });
    expect((await post(app(), issued.body)).status).toBe(410);
    expect(await db.ethereumKey.count()).toBe(0);
  });

  test('future intent can be retried after clock alignment without consumption', async () => {
    const now = Math.floor(Date.now() / 1000);
    const issued = await intent({ iat: now + 10, exp: now + 610 });
    const router = app();
    expect((await post(router, issued.body)).status).toBe(400);
    setSystemTime(new Date((now + 10) * 1000));
    expect((await post(router, issued.body)).status).toBe(200);
    expect(await db.ethereumKey.count()).toBe(0);
  });
});
