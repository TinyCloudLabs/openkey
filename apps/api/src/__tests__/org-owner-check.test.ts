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
import { createOrgRegistrationIntentVerifier } from '../services/org-registration';
import { createSealingContext } from '../services/key-sealing';

// TC-128 OK-1: POST /api/internal/org-owner-check. Real Postgres (PGlite) with the real migrations;
// the OC signer is a throwaway Ed25519 key published through the fetch stub as the issuer DID.

const root = resolve(import.meta.dir, '../../../..');
const issuer = 'did:web:issuer.credentials.org';
const kid = `${issuer}#controller`;
const AUDIENCE = 'https://api.openkey.so';
const originalFlag = process.env.ORG_KEY_CUSTODY_ENABLED;
const NOW = 1_793_100_000;

// A JWS minted exactly as OC-2 will mint it, signed once with a throwaway key whose private half was discarded.
const VECTOR = {
  jws: 'eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6aXNzdWVyLmNyZWRlbnRpYWxzLm9yZyNjb250cm9sbGVyIiwidHlwIjoib3JnLW93bmVyLWNoZWNrK2p3dCJ9.eyJpc3MiOiJkaWQ6d2ViOmlzc3Vlci5jcmVkZW50aWFscy5vcmciLCJhdWQiOiJodHRwczovL2FwaS5vcGVua2V5LnNvIiwicHVycG9zZSI6Im9yZy1vd25lci1jaGVjay92MSIsImtleUlkIjoiMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMGExIiwiYWNjb3VudCI6IjB4MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMSIsImp0aSI6IjVjMWIwYzUyLTZmMGUtNGQ4YS05YTUzLTNmMmEyZjRhOWMxMSIsImlhdCI6MTc5MzAwMDAwMCwiZXhwIjoxNzkzMDAwMDYwfQ.fwwHjIrmrWzpAu4d8HbDQkS-qQ-oPiV8moBWZF2xn0upFVZOEpiI77D8WGKHOtjTxJn40IZDDg3Upy45nSNJBA',
  jwk: { crv: 'Ed25519', kty: 'OKP', x: 'NCQe2YSDdjySX7JYkImfs1DARhv3hB-wTNqOcb5m03E' },
  keyId: '00000000-0000-4000-8000-0000000000a1',
  account: '0x1111111111111111111111111111111111111111',
  iat: 1_793_000_000,
};

let createRouter: typeof OwnerCheckRoutes.createOrgOwnerCheckRouter;
let directory: string;
let db: PrismaClient;
let ocKeys: GenerateKeyPairResult;
let didDocument: Record<string, unknown>;
let didFetches: number;
let didResponse: () => Response;

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), 'openkey-owner-check-'));
  const engine = new PGlite(directory);
  const names = (await readdir(join(root, 'packages/db/prisma/migrations'))).sort();
  for (const name of names.filter((entry) => entry !== 'migration_lock.toml')) {
    await engine.exec(await readFile(join(root, 'packages/db/prisma/migrations', name, 'migration.sql'), 'utf8'));
  }
  await engine.close();
  db = createPrismaClient({ connectionString: `pglite:${directory}` });
  // Dynamic import: the query suffix is what yields a private route instance, which a static import cannot do.
  // It must capture the real DB exports, not another file's scoped module fixture.
  ({ createOrgOwnerCheckRouter: createRouter } = await import('../routes/org-owner-check?org-owner-check-contract' as string));
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
  didResponse = () => new Response(JSON.stringify(didDocument), { headers: { 'content-type': 'application/json' } });
});
afterEach(() => setSystemTime());

function router() {
  return createRouter({
    prisma: db,
    fetch: async (url) => {
      expect(url).toBe('https://issuer.credentials.org/.well-known/did.json');
      didFetches += 1;
      return didResponse();
    },
  });
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

interface Seed {
  accepted?: boolean;
  revoked?: boolean;
  role?: 'OWNER' | 'ADMIN';
  nullGrantee?: boolean;
  ownerKeyType?: 'MANAGED' | 'EXTERNAL';
  ownerKeyArchived?: boolean;
  orgKeyArchived?: boolean;
  storedAddress?: (lower: string) => string;
  keyId?: string;
  account?: string;
}
let sequence = 0;
async function seed(options: Seed = {}) {
  const n = ++sequence;
  const account = options.account ?? `0x${randomBytes(20).toString('hex')}`;
  const keyId = options.keyId ?? randomUUID();
  const userId = `owner-check-user-${n}`;
  await db.user.create({ data: { id: userId, email: `owner-check-${n}@example.test`, emailVerified: true } });
  await db.ethereumKey.create({ data: {
    id: keyId, custody: 'ORG', userId: null, keyType: 'MANAGED', address: `0x${randomBytes(20).toString('hex')}`, publicKey: 'org',
    sealingContext: createSealingContext(), isCanonicalTinyCloud: false, archivedAt: options.orgKeyArchived ? new Date() : null,
  } });
  await db.orgKey.create({ data: { keyId, orgId: `o${'a'.repeat(26)}`, orgName: 'Fixture org', controllerDid: 'did:pkh:eip155:1:0x0' } });
  await db.ethereumKey.create({ data: {
    custody: 'PERSONAL', userId: options.nullGrantee ? null : userId, keyType: options.ownerKeyType ?? 'MANAGED',
    address: (options.storedAddress ?? getAddress)(account), publicKey: 'personal', sealingContext: createSealingContext(),
    archivedAt: options.ownerKeyArchived ? new Date() : null,
  } });
  await db.keyGrant.create({ data: {
    keyId, role: options.role ?? 'OWNER', granteeUserId: options.nullGrantee ? null : userId, invitedEmail: options.nullGrantee ? 'someone@example.test' : null,
    acceptedAt: options.accepted === false ? null : new Date(), revokedAt: options.revoked ? new Date() : null,
  } });
  return { keyId, account, userId };
}

async function answer(response: Response): Promise<unknown> {
  expect(response.status).toBe(200);
  return response.json();
}
async function expectUnauthorized(response: Response) {
  expect(response.status).toBe(401);
  expect(await response.json()).toEqual({ error: 'unauthorized' });
}

describe('the answer', () => {
  test('is true for the managed key of the accepted OWNER, with the exact wire answer', async () => {
    const { keyId, account } = await seed();
    const response = await ask(router(), await sign(ownerCheckClaims(keyId, account)));
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('content-type')).toContain('application/json');
    expect(await response.json()).toEqual({ owner: true });
  });

  test('the OC-2 vector verifies against the published did.json method', async () => {
    await seed({ keyId: VECTOR.keyId, account: VECTOR.account });
    didDocument = { id: issuer, assertionMethod: [kid], verificationMethod: [{ id: kid, controller: issuer, type: 'JsonWebKey2020', publicKeyJwk: VECTOR.jwk }] };
    setSystemTime(new Date((VECTOR.iat + 10) * 1000));
    expect(await answer(await ask(router(), VECTOR.jws))).toEqual({ owner: true });
    setSystemTime(new Date((VECTOR.iat + 61) * 1000));
    await expectUnauthorized(await ask(router(), VECTOR.jws));
  });

  test('4. an EXTERNAL key of the owner answers false', async () => {
    const { keyId, account } = await seed({ ownerKeyType: 'EXTERNAL' });
    expect(await answer(await ask(router(), await sign(ownerCheckClaims(keyId, account))))).toEqual({ owner: false });
  });

  test('5. an archived key answers false and an unarchived one true', async () => {
    const archived = await seed({ ownerKeyArchived: true });
    const live = await seed();
    const app = router();
    expect(await answer(await ask(app, await sign(ownerCheckClaims(archived.keyId, archived.account))))).toEqual({ owner: false });
    expect(await answer(await ask(app, await sign(ownerCheckClaims(live.keyId, live.account))))).toEqual({ owner: true });
  });

  test('an archived ORG key answers false', async () => {
    const { keyId, account } = await seed({ orgKeyArchived: true });
    expect(await answer(await ask(router(), await sign(ownerCheckClaims(keyId, account))))).toEqual({ owner: false });
  });

  test('6. a checksummed stored address is matched by the lowercase claim, and an uppercase-hex store too', async () => {
    const mixed = await seed({ storedAddress: getAddress });
    const upper = await seed({ storedAddress: (lower) => `0x${lower.slice(2).toUpperCase()}` });
    expect(mixed.account).toBe(mixed.account.toLowerCase());
    const app = router();
    expect(await answer(await ask(app, await sign(ownerCheckClaims(mixed.keyId, mixed.account))))).toEqual({ owner: true });
    expect(await answer(await ask(app, await sign(ownerCheckClaims(upper.keyId, upper.account))))).toEqual({ owner: true });
  });

  test('7. the same address in another case under another user answers false', async () => {
    const owner = await seed();
    const stranger = await seed();
    // The claimed account exists only as a MANAGED key of another user, in another case.
    await db.ethereumKey.updateMany({ where: { userId: owner.userId, custody: 'PERSONAL' }, data: { address: `0x${randomBytes(20).toString('hex')}` } });
    await db.ethereumKey.updateMany({ where: { userId: stranger.userId, custody: 'PERSONAL' }, data: { address: `0x${owner.account.slice(2).toUpperCase()}` } });
    expect(await answer(await ask(router(), await sign(ownerCheckClaims(owner.keyId, owner.account))))).toEqual({ owner: false });
  });

  test('8. an unaccepted grant answers false', async () => {
    const { keyId, account } = await seed({ accepted: false });
    expect(await answer(await ask(router(), await sign(ownerCheckClaims(keyId, account))))).toEqual({ owner: false });
  });

  test('a revoked grant answers false', async () => {
    const { keyId, account } = await seed({ revoked: true });
    expect(await answer(await ask(router(), await sign(ownerCheckClaims(keyId, account))))).toEqual({ owner: false });
  });

  test('an ADMIN grant answers false', async () => {
    const { keyId, account } = await seed({ role: 'ADMIN' });
    expect(await answer(await ask(router(), await sign(ownerCheckClaims(keyId, account))))).toEqual({ owner: false });
  });

  test('a null grantee never matches an orphaned personal key with the same address', async () => {
    const { keyId, account } = await seed({ nullGrantee: true });
    expect(await db.ethereumKey.count({ where: { userId: null, custody: 'PERSONAL', address: getAddress(account) } })).toBe(1);
    expect(await answer(await ask(router(), await sign(ownerCheckClaims(keyId, account))))).toEqual({ owner: false });
  });

  test('a non-ORG keyId and an unknown keyId answer false', async () => {
    const { account, userId } = await seed();
    const personal = await db.ethereumKey.findFirstOrThrow({ where: { userId, custody: 'PERSONAL' } });
    const app = router();
    expect(await answer(await ask(app, await sign(ownerCheckClaims(personal.id, account))))).toEqual({ owner: false });
    expect(await answer(await ask(app, await sign(ownerCheckClaims(randomUUID(), account))))).toEqual({ owner: false });
  });

  test('another account of the same org answers false', async () => {
    const { keyId } = await seed();
    expect(await answer(await ask(router(), await sign(ownerCheckClaims(keyId, `0x${randomBytes(20).toString('hex')}`))))).toEqual({ owner: false });
  });

  test('the same JWS sent twice answers the same twice', async () => {
    const { keyId, account } = await seed();
    const app = router();
    const token = await sign(ownerCheckClaims(keyId, account));
    expect(await answer(await ask(app, token))).toEqual({ owner: true });
    expect(await answer(await ask(app, token))).toEqual({ owner: true });
  });
});

describe('authentication', () => {
  test('1. an issued OC credential JWT and an intent JWS are each refused', async () => {
    const { keyId, account } = await seed();
    const credential = await sign(
      { iss: issuer, sub: 'did:web:oabc.orgs.credentials.org', vc: { type: ['VerifiableCredential'] }, jti: randomUUID(), iat: NOW, exp: NOW + 60 },
      { typ: 'vc+jwt' },
    );
    const credentialWithOwnerClaims = await sign(ownerCheckClaims(keyId, account), { typ: 'vc+jwt' });
    const intent = await sign(
      { iss: issuer, aud: AUDIENCE, registrationId: randomUUID(), orgId: `o${'a'.repeat(26)}`, nonce: randomBytes(32).toString('base64url'), handle: 'fixture', displayName: 'Fixture', purpose: 'org-registration/v1', iat: NOW, exp: NOW + 600 },
      { typ: 'org-registration-intent+jwt' },
    );
    const intentWithOwnerClaims = await sign(ownerCheckClaims(keyId, account), { typ: 'org-registration-intent+jwt' });
    const app = router();
    for (const token of [credential, credentialWithOwnerClaims, intent, intentWithOwnerClaims]) await expectUnauthorized(await ask(app, token));
  });

  test('2. an owner-check JWS is refused by the intent verifier', async () => {
    const { keyId, account } = await seed();
    const verify = createOrgRegistrationIntentVerifier(async () => didResponse());
    await expect(verify(await sign(ownerCheckClaims(keyId, account)))).rejects.toMatchObject({ status: 400, code: 'registration_intent_invalid' });
  });

  test('3. expired, exp-iat > 60 and iat > now + 5 are refused; the limits themselves pass', async () => {
    const { keyId, account } = await seed();
    const app = router();
    const refused: Claims[] = [
      { iat: NOW - 61, exp: NOW - 1 },
      { iat: NOW - 60, exp: NOW },
      { iat: NOW, exp: NOW + 61 },
      { iat: NOW - 10, exp: NOW + 51 },
      { iat: NOW + 6, exp: NOW + 30 },
      { iat: NOW, exp: NOW },
      { iat: NOW + 1, exp: NOW },
    ];
    for (const overrides of refused) await expectUnauthorized(await ask(app, await sign(ownerCheckClaims(keyId, account, overrides))));
    for (const overrides of [{ iat: NOW + 5, exp: NOW + 65 }, { iat: NOW - 59, exp: NOW + 1 }, { iat: NOW, exp: NOW + 60 }]) {
      expect(await answer(await ask(app, await sign(ownerCheckClaims(keyId, account, overrides))))).toEqual({ owner: true });
    }
  });

  test('a missing claim, an extra claim and a wrong claim value are refused', async () => {
    const { keyId, account } = await seed();
    const app = router();
    const full = ownerCheckClaims(keyId, account);
    for (const name of Object.keys(full)) {
      const { [name]: _removed, ...rest } = full;
      await expectUnauthorized(await ask(app, await sign(rest)));
    }
    await expectUnauthorized(await ask(app, await sign({ ...full, orgId: `o${'a'.repeat(26)}` })));
    for (const overrides of [
      { iss: 'did:web:other.example' }, { aud: 'https://openkey.so' }, { purpose: 'org-registration/v1' },
      { account: account.toUpperCase().replace('0X', '0x') }, { account: getAddress(account) }, { account: account.slice(0, 40) },
      { keyId: 7 }, { keyId: '' }, { jti: 7 }, { iat: '1793100000' }, { exp: NOW + 60.5 }, { iat: null },
    ]) await expectUnauthorized(await ask(app, await sign({ ...full, ...overrides })));
  });

  test('a wrong header, a wrong signer and a malformed token are refused', async () => {
    const { keyId, account } = await seed();
    const app = router();
    const claims = ownerCheckClaims(keyId, account);
    const other = await generateKeyPair('EdDSA', { extractable: true });
    await expectUnauthorized(await ask(app, await sign(claims, {}, other.privateKey)));
    await expectUnauthorized(await ask(app, await sign(claims, { typ: undefined })));
    await expectUnauthorized(await ask(app, await sign(claims, { typ: 'JWT' })));
    await expectUnauthorized(await ask(app, await sign(claims, { cty: 'x' })));
    await expectUnauthorized(await ask(app, await sign(claims, { kid: 'did:web:other.example#controller' })));
    await expectUnauthorized(await ask(app, await sign(claims, { kid: issuer })));
    await expectUnauthorized(await ask(app, `${await sign(claims)}.extra`));
    const [header, payload, signature] = (await sign(claims)).split('.');
    await expectUnauthorized(await ask(app, `${header}.${payload}.${signature!.slice(0, -2)}AA`));
    await expectUnauthorized(await ask(app, `${header}.${payload}`));
    await expectUnauthorized(await ask(app, undefined));
    await expectUnauthorized(await ask(app, '', { headers: { authorization: '' } }));
    await expectUnauthorized(await ask(app, undefined, { headers: { authorization: `Basic ${await sign(claims)}` } }));
    await expectUnauthorized(await ask(app, undefined, { headers: { authorization: await sign(claims) } }));
    const hmac = await new CompactSign(new TextEncoder().encode(JSON.stringify(claims))).setProtectedHeader({ alg: 'HS256', kid, typ: 'org-owner-check+jwt' }).sign(randomBytes(32));
    await expectUnauthorized(await ask(app, hmac));
  });

  test('9. an unknown kid is refused with at most one forced DID refresh per 10 s', async () => {
    const { keyId, account } = await seed();
    const app = router();
    expect(await answer(await ask(app, await sign(ownerCheckClaims(keyId, account))))).toEqual({ owner: true });
    expect(didFetches).toBe(1);
    const unknown = await sign(ownerCheckClaims(keyId, account), { kid: `${issuer}#unknown` });
    for (let i = 0; i < 4; i += 1) await expectUnauthorized(await ask(app, unknown));
    expect(didFetches).toBe(2);
    setSystemTime(new Date((NOW + 9) * 1000));
    await expectUnauthorized(await ask(app, await sign(ownerCheckClaims(keyId, account, { iat: NOW + 9, exp: NOW + 69 }), { kid: `${issuer}#unknown` })));
    expect(didFetches).toBe(2);
    setSystemTime(new Date((NOW + 11) * 1000));
    await expectUnauthorized(await ask(app, await sign(ownerCheckClaims(keyId, account, { iat: NOW + 11, exp: NOW + 71 }), { kid: `${issuer}#unknown` })));
    expect(didFetches).toBe(3);
  });

  test('a key rotated into the DID is picked up by the forced refresh', async () => {
    const { keyId, account } = await seed();
    const app = router();
    expect(await answer(await ask(app, await sign(ownerCheckClaims(keyId, account))))).toEqual({ owner: true });
    const rotated = await generateKeyPair('EdDSA', { extractable: true });
    const rotatedKid = `${issuer}#rotated`;
    didDocument = { id: issuer, assertionMethod: [kid, rotatedKid], verificationMethod: [
      (didDocument.verificationMethod as unknown[])[0],
      { id: rotatedKid, controller: issuer, type: 'JsonWebKey2020', publicKeyJwk: await exportJWK(rotated.publicKey) },
    ] };
    expect(await answer(await ask(app, await sign(ownerCheckClaims(keyId, account), { kid: rotatedKid }, rotated.privateKey)))).toEqual({ owner: true });
  });

  test('a key present in verificationMethod but not asserted is refused', async () => {
    const { keyId, account } = await seed();
    didDocument = { ...didDocument, assertionMethod: [] };
    await expectUnauthorized(await ask(router(), await sign(ownerCheckClaims(keyId, account))));
  });

  test('an unavailable issuer DID answers 503, never an answer', async () => {
    const { keyId, account } = await seed();
    const token = await sign(ownerCheckClaims(keyId, account));
    for (const unavailable of [() => new Response('nope', { status: 500 }), () => new Response('not json', { status: 200 })]) {
      didResponse = unavailable;
      const response = await ask(router(), token);
      expect(response.status).toBe(503);
      expect(await response.json()).not.toHaveProperty('owner');
    }
  });
});

describe('the route', () => {
  test('the capability flag off answers 404 before anything else, with no DID fetch', async () => {
    const { keyId, account } = await seed();
    for (const value of ['false', undefined, 'TRUE', '1']) {
      if (value === undefined) delete process.env.ORG_KEY_CUSTODY_ENABLED;
      else process.env.ORG_KEY_CUSTODY_ENABLED = value;
      const response = await ask(router(), await sign(ownerCheckClaims(keyId, account)), { body: 'x' });
      expect(response.status).toBe(404);
    }
    expect(didFetches).toBe(0);
  });

  test('11. a non-empty body answers 400, before authentication', async () => {
    const { keyId, account } = await seed();
    const app = router();
    const token = await sign(ownerCheckClaims(keyId, account));
    for (const body of ['{}', 'x', '{"keyId":"a"}']) {
      expect((await ask(app, token, { body, headers: { 'content-type': 'application/json' } })).status).toBe(400);
      expect((await ask(app, undefined, { body })).status).toBe(400);
    }
    expect(didFetches).toBe(0);
    expect(await answer(await ask(app, token, { body: '' }))).toEqual({ owner: true });
  });

  test('only POST is served', async () => {
    const { keyId, account } = await seed();
    const app = router();
    const token = await sign(ownerCheckClaims(keyId, account));
    for (const method of ['GET', 'PUT', 'DELETE', 'PATCH']) {
      expect((await app.request('/', { method, headers: { authorization: `Bearer ${token}` } })).status).toBe(404);
    }
  });

  test('10. no Access-Control-* header is returned, for a browser Origin, on any outcome', async () => {
    const { keyId, account } = await seed();
    const app = router();
    const token = await sign(ownerCheckClaims(keyId, account));
    const responses = [
      await ask(app, token, { headers: { origin: 'https://credentials.org' } }),
      await ask(app, undefined, { headers: { origin: 'https://openkey.so' } }),
      await ask(app, token, { body: 'x', headers: { origin: 'http://localhost:5173' } }),
      await app.request('/', { method: 'OPTIONS', headers: { origin: 'https://openkey.so', 'access-control-request-method': 'POST', 'access-control-request-headers': 'authorization' } }),
    ];
    for (const response of responses) {
      for (const [name] of response.headers) expect(name.toLowerCase().startsWith('access-control-')).toBe(false);
    }
  });
});
