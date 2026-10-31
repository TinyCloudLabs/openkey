// TC-1518 K1 T1: an organization key must never surface through a personal-key
// route. The fake store applies every `where` field it is given, so a call site
// that drops `personalKeyWhere()` lets the ORG row through and fails these tests.

import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import type { keysRouter } from '../routes/keys';
import type { ownerRevocationRouter } from '../routes/owner-revocation-runtime';
import { MemoryPreparedHandoffStore, PreparedHandoffService } from '../services/prepared-handoff';
import { mockModules, replaceModules } from './mock-module';

type Row = Record<string, unknown>;

const user = { id: 'user_1', email: 'alice@example.test', emailVerified: true };
const createdAt = new Date('2026-01-01T00:00:00.000Z');
const ownerRevocationHandoffs = new PreparedHandoffService(new MemoryPreparedHandoffStore());

const personalKey: Row = {
  id: 'key_personal', userId: user.id, custody: 'PERSONAL', address: `0x${'1'.repeat(40)}`,
  publicKey: '0x', keyType: 'MANAGED', keyIndex: 0, label: null, isCanonicalTinyCloud: true,
  archivedAt: null, createdAt, sealedBlob: 'sealed',
};
// K1 T2: an ORG row has no userId and is EXTERNAL with no sealed blob. Access to
// it comes through an active OWNER grant, which these personal-key routes never read.
const orgKey: Row = {
  id: 'key_org', userId: null, custody: 'ORG', address: `0x${'2'.repeat(40)}`,
  publicKey: '0x', keyType: 'EXTERNAL', keyIndex: 0, label: 'org', isCanonicalTinyCloud: false,
  archivedAt: null, createdAt, sealedBlob: null,
};

let rows: Row[] = [];

function matches(where: Row | undefined, row: Row): boolean {
  if (!where) return true;
  return Object.entries(where).every(([field, cond]) => {
    const value = row[field];
    if (cond === null) return value === null;
    if (typeof cond === 'object') {
      const op = cond as Row;
      if ('not' in op) return op.not === null ? value !== null : value !== op.not;
      if ('equals' in op) return String(value).toLowerCase() === String(op.equals).toLowerCase();
      throw new Error(`unsupported where operator on ${field}`);
    }
    return value === cond;
  });
}

function project(row: Row, select?: Record<string, boolean>): Row {
  if (!select) return { ...row };
  return Object.fromEntries(Object.keys(select).filter((k) => select[k]).map((k) => [k, row[k]]));
}

const ethereumKey = {
  findMany: mock(async ({ where, select }: { where?: Row; select?: Record<string, boolean> }) =>
    rows.filter((row) => matches(where, row)).map((row) => project(row, select))),
  findFirst: mock(async ({ where, select }: { where?: Row; select?: Record<string, boolean> }) => {
    const row = rows.find((candidate) => matches(where, candidate));
    return row ? project(row, select) : null;
  }),
};

// auth.ts extends the client at load time, so the fake must tolerate $extends.
const fakeClient: Record<string, unknown> = { ethereumKey };
fakeClient.$extends = () => fakeClient;

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', user);
      c.set('session', { id: 'session_1', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
  '../routes/prepared-handoffs': () => ({
    preparedHandoffService: ownerRevocationHandoffs,
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => fakeClient }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({ deriveKey: mock(async () => new Uint8Array(32)), isInTee: () => false }),
    seal: mock(async () => 'sealed'),
    unseal: mock(async () => '0x'),
    generatePrivateKey: () => '0x',
    getAddressFromPrivateKey: () => '0x',
  }),
  '../services/tinycloud-bootstrap': () => ({
    ensureTinyCloudBootstrapForApprovedSign: mock(async () => ({ status: 'skipped' })),
  }),
});

let router: typeof keysRouter;
let revocationRouter: typeof ownerRevocationRouter;
let buildKeyClaims: typeof import('../auth').buildKeyClaims;

beforeAll(async () => {
  // auth.ts reads these at load time; the fake DB needs no real values.
  process.env.BETTER_AUTH_URL ??= 'https://api.test.example';
  process.env.BETTER_AUTH_SECRET ??= 'org-key-t1-test-secret-000000000000';
  ({ keysRouter: router } = await import('../routes/keys?org-key-t1-keys' as string));
  ({ buildKeyClaims } = (await import('../auth?org-key-t1-auth' as string)) as typeof import('../auth'));
  // Load the runtime after its scoped DB, session, and handoff fixtures are registered.
  ({ ownerRevocationRouter: revocationRouter } = await import('../routes/owner-revocation-runtime?org-key-t1-owner-revocation' as string));
});

// The OAuth keys claim reads only through the injected DB, so the fake store drives it.
function claimsFor() {
  return buildKeyClaims(
    user,
    ['keys'],
    { id: 'client_1' } as never,
    false,
    fakeClient as never,
  );
}

beforeEach(() => {
  ethereumKey.findMany.mockClear();
  ethereumKey.findFirst.mockClear();
});

describe('K1 T1: a user whose only key is an org key', () => {
  beforeEach(() => {
    rows = [{ ...orgKey }];
  });

  test('GET /api/keys lists no keys', async () => {
    const res = await router.request('/');
    expect(res.status).toBe(200);
    expect(((await res.json()) as { keys: unknown[] }).keys).toEqual([]);
  });

  test('GET /api/keys/:orgKeyId is not found', async () => {
    const res = await router.request('/key_org');
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: 'Key not found' });
  });

  test('POST /api/keys/:orgKeyId/sign is not found, never reaches signing', async () => {
    const res = await router.request('/key_org/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'hello' }),
    });
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: 'Key not found' });
  });

  test('POST /api/keys/:orgKeyId/sign-typed-data is not found', async () => {
    const res = await router.request('/key_org/sign-typed-data', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ domain: {}, types: {}, primaryType: 'Mail', message: {} }),
    });
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: 'Key not found' });
  });

  test('GET /api/keys/:orgKeyId/quote is not found', async () => {
    const res = await router.request('/key_org/quote');
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: 'Key not found' });
  });

  test('the OAuth keys claim is empty', async () => {
    expect(await claimsFor()).toEqual([]);
  });
});

describe('K1 T1: a user with one personal key and one org key', () => {
  beforeEach(() => {
    rows = [{ ...personalKey }, { ...orgKey }];
  });

  test('GET /api/keys returns only the personal key', async () => {
    const res = await router.request('/');
    const keys = ((await res.json()) as { keys: Array<{ id: string }> }).keys;
    expect(keys.map((key) => key.id)).toEqual(['key_personal']);
  });

  test('the org key id is not found while the personal key id resolves', async () => {
    expect((await router.request('/key_org')).status).toBe(404);
    expect((await router.request('/key_personal')).status).toBe(200);
  });

  test('the OAuth keys claim lists only the personal key', async () => {
    const claims = (await claimsFor()) as Array<{ keyId: string }>;
    expect(claims.map((claim) => claim.keyId)).toEqual(['key_personal']);
  });
});

test('owner revocation accepts a non-primary personal key and refuses other key bindings', async () => {
  const origin = 'https://openkey.test';
  const previousCorsOrigin = process.env.CORS_ORIGIN;
  const previousWebauthnOrigin = process.env.WEBAUTHN_ORIGIN;
  process.env.CORS_ORIGIN = origin;
  process.env.WEBAUTHN_ORIGIN = origin;
  const activePersonal = { ...personalKey, isCanonicalTinyCloud: false, sealingContext: 'A'.repeat(43) };
  const cases: Array<{ row: Row; status: number }> = [
    { row: activePersonal, status: 200 },
    // The stateful fixture can represent inconsistent rows, independently checking the custody predicate.
    { row: { ...activePersonal, custody: 'ORG' }, status: 403 },
    { row: { ...activePersonal, userId: 'another_user' }, status: 403 },
    { row: { ...activePersonal, archivedAt: createdAt }, status: 403 },
    { row: { ...activePersonal, id: 'another_key' }, status: 403 },
  ];
  try {
    for (const [index, { row, status }] of cases.entries()) {
      rows = [row];
      const ticket = Buffer.alloc(32, index + 10).toString('base64url');
      await ownerRevocationHandoffs.claim({
        transportVersion: 2,
        request: {
          kind: 'owner-revocation',
          ownerDid: `did:pkh:eip155:1:${String(personalKey.address)}`,
          cid: 'bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe',
          nonce: Buffer.alloc(16, index + 1).toString('hex'),
          expiresAt: new Date(Date.now() + 590_000).toISOString(),
        },
        delivery: {
          handoffId: ticket,
          state: Buffer.alloc(32, 30).toString('base64url'),
          cancelSecret: Buffer.alloc(32, 31).toString('base64url'),
        },
      }, user.id);
      const response = await revocationRouter.request('/prepare', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin },
        body: JSON.stringify({ keyId: personalKey.id, ticket }),
      });
      expect(response.status).toBe(status);
      if (status !== 200) {
        expect('authorizationContextToken' in await response.json()).toBe(false);
      }
    }
  } finally {
    if (previousCorsOrigin === undefined) delete process.env.CORS_ORIGIN;
    else process.env.CORS_ORIGIN = previousCorsOrigin;
    if (previousWebauthnOrigin === undefined) delete process.env.WEBAUTHN_ORIGIN;
    else process.env.WEBAUTHN_ORIGIN = previousWebauthnOrigin;
  }
});
