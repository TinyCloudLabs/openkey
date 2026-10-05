import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { Client } from 'pg';
import { privateKeyToAccount } from 'viem/accounts';
import { recoverMessageAddress, type Hex } from 'viem';
import { serializeSignedCookie } from 'better-call';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { z } from 'zod';
import { createLocalJWKSet, jwtVerify } from 'jose';
import type * as DatabaseModule from '@openkey/db';
import type * as PrimaryModule from '../apps/api/src/services/primary-key';
import type * as AuthModule from '../apps/api/src/auth';
import type * as KeysModule from '../apps/api/src/routes/keys';
import type * as DelegateModule from '../apps/api/src/routes/delegate';
import type * as TeeModule from '@openkey/tee';
import type * as SealingModule from '../apps/api/src/services/key-sealing';

// Run in a fresh process: other API tests replace @openkey/db, Better Auth and
// the TEE module globally. These regressions must exercise their real paths.
const backend = process.env.TC704_PRIMARY_TEST_CHILD;
const postgresUrl = process.env.OPENKEY_TEST_POSTGRES_URL;
const root = resolve(import.meta.dir, '..');

if (!backend) {
  for (const engine of ['pglite', 'postgres']) {
    test.skipIf(engine === 'postgres' && !postgresUrl)(
      `TC-704 primary-key integration (${engine}${engine === 'postgres' ? ', concurrent connections' : ''})`,
      async () => {
        const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
          cwd: root,
          env: {
            ...process.env,
            TC704_PRIMARY_TEST_CHILD: engine,
            NODE_ENV: 'test',
            TEE_MODE: 'development',
            BETTER_AUTH_URL: 'http://localhost:3000',
            BETTER_AUTH_SECRET: 'tc704-isolated-regression-secret-not-for-production',
            WEBAUTHN_RP_ID: 'localhost',
            WEBAUTHN_ORIGIN: 'http://localhost:5173',
            CORS_ORIGIN: 'http://localhost:5173',
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
      },
      120_000,
    );
  }
} else {
  // Use the tracked migration chain, not db push: the partial unique index
  // and other raw-SQL constraints are part of the behavior under test.
  const directory = await mkdtemp(join(tmpdir(), 'openkey-tc704-'));
  const databaseName = `tc704_${randomUUID().replaceAll('-', '')}`;
  let admin: Client | undefined;
  let migrationConnection: Client | undefined;
  let prisma: DatabaseModule.PrismaClient;
  let createPrismaClient: typeof DatabaseModule.createPrismaClient;
  let setPrimaryKey: typeof PrimaryModule.setPrimaryKey;
  let PrimaryKeyConflictError: typeof PrimaryModule.PrimaryKeyConflictError;
  let auth: typeof AuthModule.auth;
  let authPrisma: DatabaseModule.PrismaClient;
  let buildClaim: typeof AuthModule.buildCanonicalTinyCloudIdentityClaim;
  let keysRouter: typeof KeysModule.keysRouter;
  let delegateRouter: typeof DelegateModule.delegateRouter;
  let tee: TeeModule.TeeClient;
  let seal: typeof TeeModule.seal;
  let createSealingContext: typeof SealingModule.createSealingContext;
  let connectionString: string;
  let cookie: string;
  let sessionToken: string;
  const userId = 'tc704-user';
  const clientId = 'tc704-client';
  const rawBearer = 'tc704-oauth-token';
  const scopes = ['openid', 'keys', 'tinycloud:manage-key'];
  const origin = 'http://localhost:5173';
  const accounts = Object.fromEntries(
    ['old', 'next', 'third', 'external', 'archived', 'unavailable', 'foreign', 'unowned']
      .map((id, index) => [id, privateKeyToAccount(`0x${String(index + 1).repeat(64)}`)]),
  );
  const keyResponseSchema = z.object({
    id: z.string(), isPrimary: z.boolean(), sealedBlob: z.unknown().optional(),
  });
  const primaryResponseSchema = z.object({
    changed: z.boolean().optional(),
    key: keyResponseSchema.nullable().optional(),
    error: z.unknown().optional(),
  });
  const errorSchema = z.object({ code: z.string(), message: z.string() });
  const signingResponseSchema = z.object({
    approved: z.boolean(),
    code: z.string().optional(),
    signature: z.custom<Hex>((value) => typeof value === 'string' && /^0x[0-9a-f]+$/i.test(value)).optional(),
    canonicalIdentity: z.unknown().optional(),
  });

  beforeAll(async () => {
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    if (backend === 'postgres') {
      if (!postgresUrl) throw new Error('OPENKEY_TEST_POSTGRES_URL is required for concurrent PostgreSQL coverage');
      // Never migrate/reset the supplied database. It is only a maintenance
      // connection; all test data lives in a newly created disposable database.
      admin = new Client({ connectionString: postgresUrl });
      await admin.connect();
      await admin.query(`CREATE DATABASE "${databaseName}"`);
      const target = new URL(postgresUrl);
      target.pathname = `/${databaseName}`;
      connectionString = target.toString();
      migrationConnection = new Client({ connectionString });
      await migrationConnection.connect();
      for (const migration of migrations) {
        await migrationConnection.query(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
      }
    } else {
      const database = new PGlite(directory);
      try {
        for (const migration of migrations) {
          await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
        }
      } finally {
        await database.close();
      }
      connectionString = `pglite:${directory}`;
    }
    process.env.DATABASE_URL = connectionString;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    // Deliberate module-loading boundary: route singletons capture DATABASE_URL
    // on import, so they must load only after the disposable database exists.
    ({ createPrismaClient } = await import('@openkey/db'));
    prisma = createPrismaClient();
    ({ setPrimaryKey, PrimaryKeyConflictError } = await import('../apps/api/src/services/primary-key'));
    ({ auth, prisma: authPrisma, buildCanonicalTinyCloudIdentityClaim: buildClaim } = await import('../apps/api/src/auth'));
    ({ keysRouter } = await import('../apps/api/src/routes/keys'));
    ({ delegateRouter } = await import('../apps/api/src/routes/delegate'));
    const teeModule = await import('@openkey/tee');
    tee = teeModule.createTeeClient();
    seal = teeModule.seal;
    ({ createSealingContext } = await import('../apps/api/src/services/key-sealing'));
  }, 60_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    await authPrisma?.$disconnect();
    await migrationConnection?.end();
    if (admin) {
      // Routes own lazy Prisma pools; terminate only connections to this
      // uniquely named disposable database before removing it.
      await admin.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
      await admin.end();
    }
    await rm(directory, { recursive: true, force: true });
  });

  beforeEach(async () => {
    await prisma.$executeRawUnsafe('TRUNCATE TABLE "user", "oauth_client" CASCADE');
    await prisma.user.createMany({ data: [
      { id: userId, email: 'owner@example.test', name: 'Primary owner', emailVerified: true, tinyCloudManageKeyMode: 'USER_CONTROLLED_SHARED', tinyCloudManageKeyPolicyEpoch: 7n },
      { id: 'other-user', email: 'other@example.test', emailVerified: true },
    ] });
    for (const [index, id] of Object.keys(accounts).entries()) {
      const account = accounts[id]!;
      const sealingContext = createSealingContext();
      const sealedBlob = await seal(`0x${String(index + 1).repeat(64)}`, await tee.deriveKey(`openkey/key/${sealingContext}`));
      await prisma.ethereumKey.create({ data: {
        id,
        userId: id === 'foreign' ? 'other-user' : id === 'unowned' ? null : userId,
        address: account.address,
        publicKey: account.publicKey,
        sealedBlob: id === 'external' || id === 'unavailable' ? null : sealedBlob,
        sealingContext,
        keyType: id === 'external' ? 'EXTERNAL' : 'MANAGED',
        keyIndex: index,
        isCanonicalTinyCloud: id === 'old',
        archivedAt: id === 'archived' ? new Date() : null,
      } });
    }
    await prisma.oauthClient.create({ data: {
      id: clientId, clientId, name: 'Primary regression client', clientSecret: 'hashed-test-secret',
      redirectUris: ['https://app.example.test/callback'], scopes, contacts: [],
      type: 'web', public: false, tokenEndpointAuthMethod: 'client_secret_basic',
      grantTypes: ['authorization_code'], responseTypes: ['code'],
    } });
    await prisma.oauthConsent.create({ data: { id: 'consent', userId, clientId, scopes } });
    await prisma.tinyCloudManageKeyAppPreference.create({ data: {
      userId, clientId, enabled: true, status: 'ENABLED', clientNameSnapshot: 'Primary regression client',
    } });
    await prisma.oauthAccessToken.create({ data: {
      id: 'token', token: new Bun.CryptoHasher('sha256').update(rawBearer).digest('base64url'),
      clientId, userId, scopes, expiresAt: new Date(Date.now() + 300_000),
    } });
    sessionToken = randomUUID();
    await prisma.session.create({ data: {
      id: 'session', token: sessionToken, userId, expiresAt: new Date(Date.now() + 3_600_000),
    } });
    const context = await auth.$context;
    cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, sessionToken, context.secret)).split(';')[0]!;
  });

  async function primaries() {
    return prisma.ethereumKey.findMany({
      where: { userId, keyType: 'MANAGED', archivedAt: null, isCanonicalTinyCloud: true },
      select: { id: true }, orderBy: { id: 'asc' },
    });
  }

  async function events() {
    return prisma.tinyCloudManageKeyControlEvent.findMany({ where: { userId }, orderBy: { createdAt: 'asc' } });
  }

  async function policySnapshot() {
    return {
      user: await prisma.user.findUniqueOrThrow({ where: { id: userId } }),
      grants: await prisma.tinyCloudManageKeyAppPreference.findMany({ where: { userId } }),
      consents: await prisma.oauthConsent.findMany({ where: { userId } }),
      tokens: await prisma.oauthAccessToken.findMany({ where: { userId } }),
    };
  }

  async function postPrimary(keyId: string, headers: Record<string, string> = { cookie, origin }) {
    const response = await keysRouter.request(`/${keyId}/primary`, { method: 'POST', headers });
    return { status: response.status, body: primaryResponseSchema.parse(await response.json()) };
  }

  // SQL fault injection fails a real statement, rather than emulating a
  // transaction in a mock and accidentally asserting the mock's semantics.
  async function withFault(table: string, operation: string, body: string, run: () => Promise<void>) {
    await prisma.$executeRawUnsafe(`CREATE FUNCTION tc704_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN ${body} END $$`);
    try {
      await prisma.$executeRawUnsafe(`CREATE TRIGGER tc704_fault BEFORE ${operation} ON "${table}" FOR EACH ROW EXECUTE FUNCTION tc704_fault()`);
      await run();
    } finally {
      await prisma.$executeRawUnsafe(`DROP TRIGGER IF EXISTS tc704_fault ON "${table}"`);
      await prisma.$executeRawUnsafe('DROP FUNCTION tc704_fault()');
    }
  }

  describe(`primary key atomicity and eligibility (${backend})`, () => {
    test('clears before setting under the real partial unique index, preserves custody/policy, and is idempotent', async () => {
      await expect(Promise.resolve(prisma.ethereumKey.update({ where: { id: 'next' }, data: { isCanonicalTinyCloud: true } })))
        .rejects.toMatchObject({ code: 'P2002' });
      const policy = await policySnapshot();
      const keyMaterial = await prisma.ethereumKey.findMany({ select: { id: true, address: true, sealedBlob: true, sealingContext: true }, orderBy: { id: 'asc' } });
      expect(await setPrimaryKey(prisma, userId, 'next')).toMatchObject({ kind: 'changed', keyId: 'next', previousKeyId: 'old', key: { id: 'next', isPrimary: true } });
      expect(await primaries()).toEqual([{ id: 'next' }]);
      expect(await prisma.ethereumKey.findMany({ select: { id: true, address: true, sealedBlob: true, sealingContext: true }, orderBy: { id: 'asc' } })).toEqual(keyMaterial);
      expect(await policySnapshot()).toEqual(policy);
      expect(await events()).toMatchObject([{ action: 'PRIMARY_KEY_CHANGED', policyEpoch: 7n, mode: 'USER_CONTROLLED_SHARED' }]);
      expect(await setPrimaryKey(prisma, userId, 'next')).toMatchObject({ kind: 'unchanged', keyId: 'next', key: { id: 'next', isPrimary: true } });
      expect(await primaries()).toEqual([{ id: 'next' }]);
      expect(await events()).toHaveLength(1);
    });

    test.each([
      ['missing', 'not_found'], ['foreign', 'not_found'], ['unowned', 'not_found'],
      ['external', 'external_key'], ['archived', 'archived'], ['unavailable', 'unavailable'],
    ])('rejects %s without changing primary or recording a successful change', async (keyId, kind) => {
      expect(await setPrimaryKey(prisma, userId, keyId)).toEqual({ kind });
      expect(await primaries()).toEqual([{ id: 'old' }]);
      expect(await events()).toEqual([]);
    });

    test('rejects malformed non-null sealing context from a legacy database without moving primary', async () => {
      const target = await prisma.ethereumKey.findUniqueOrThrow({ where: { id: 'next' } });
      // Model legacy/db-push data independently of the newer SQL format guard.
      // This is only the disposable test database; restore its guard afterward.
      await prisma.$executeRawUnsafe('ALTER TABLE "ethereum_keys" DROP CONSTRAINT "ethereum_keys_sealing_context_format_check"');
      try {
        await prisma.ethereumKey.update({ where: { id: 'next' }, data: { sealingContext: 'malformed-context' } });
        const response = await postPrimary('next');
        expect(response.status).toBe(400);
        expect(errorSchema.parse(response.body.error).code).toBe('key_unavailable');
        expect(await primaries()).toEqual([{ id: 'old' }]);
        expect(await events()).toEqual([]);
      } finally {
        await prisma.ethereumKey.update({ where: { id: 'next' }, data: { sealingContext: target.sealingContext } });
        await prisma.$executeRawUnsafe(`ALTER TABLE "ethereum_keys" ADD CONSTRAINT "ethereum_keys_sealing_context_format_check"
          CHECK ("sealingContext" IS NULL OR "sealingContext" ~ '^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$')`);
      }
    });

    test.each([
      ['corrupt ciphertext', { sealedBlob: 'not-a-sealed-key' }],
      ['invalid address', { address: 'not-an-address' }],
      ['different signing address', { address: '0x9999999999999999999999999999999999999999' }],
    ])('rejects %s without changing the primary', async (_name, data) => {
      await prisma.ethereumKey.update({ where: { id: 'next' }, data });
      expect(await setPrimaryKey(prisma, userId, 'next')).toEqual({ kind: 'unavailable' });
      expect(await primaries()).toEqual([{ id: 'old' }]);
      expect(await events()).toEqual([]);
    });

    test('retains the null-context legacy signing path when its material matches the address', async () => {
      const sealedBlob = await seal(`0x${'2'.repeat(64)}`, await tee.deriveKey(`openkey/user/${userId}/keys`));
      await prisma.ethereumKey.update({ where: { id: 'next' }, data: { sealingContext: null, sealedBlob } });
      expect((await postPrimary('next')).status).toBe(200);
      expect(await primaries()).toEqual([{ id: 'next' }]);
    });

    test('replaces an archived primary and allows restoring it without a second primary', async () => {
      const archived = await keysRouter.request('/old/archive', { method: 'POST', headers: { cookie, origin } });
      expect(archived.status).toBe(200);
      expect(await primaries()).toEqual([]);
      expect(await setPrimaryKey(prisma, userId, 'next')).toMatchObject({ kind: 'changed', keyId: 'next', previousKeyId: null });
      const restored = await keysRouter.request('/old/unarchive', { method: 'POST', headers: { cookie, origin } });
      expect(restored.status).toBe(200);
      expect(await primaries()).toEqual([{ id: 'next' }]);
      expect((await prisma.ethereumKey.findUniqueOrThrow({ where: { id: 'old' } })).isCanonicalTinyCloud).toBe(false);
    });

    test('rolls back the old flag when the target update fails', async () => {
      await withFault('ethereum_keys', 'UPDATE', `
        IF NEW."id" = 'next' AND NEW."isCanonicalTinyCloud" THEN
          RAISE EXCEPTION 'tc704 forced promotion failure';
        END IF;
        RETURN NEW;
      `, async () => {
        await expect(setPrimaryKey(prisma, userId, 'next')).rejects.toThrow('tc704 forced promotion failure');
        expect(await primaries()).toEqual([{ id: 'old' }]);
        expect(await events()).toEqual([]);
      });
    });

    test('rolls back both flags when the transactional audit cannot be written', async () => {
      await withFault('tinycloud_manage_key_control_event', 'INSERT', "RAISE EXCEPTION 'tc704 forced audit failure';", async () => {
        await expect(setPrimaryKey(prisma, userId, 'next')).rejects.toThrow('tc704 forced audit failure');
        expect(await primaries()).toEqual([{ id: 'old' }]);
        expect(await events()).toEqual([]);
      });
    });

    test('a lost target update is a conflict and does not leave the user without a primary', async () => {
      await withFault('ethereum_keys', 'UPDATE', `
        IF NEW."id" = 'next' AND NEW."isCanonicalTinyCloud" THEN RETURN NULL; END IF;
        RETURN NEW;
      `, async () => {
        await expect(setPrimaryKey(prisma, userId, 'next')).rejects.toBeInstanceOf(PrimaryKeyConflictError);
        const response = await postPrimary('next');
        expect(response.status).toBe(409);
        expect(errorSchema.parse(response.body.error).code).toBe('primary_key_conflict');
        expect(await primaries()).toEqual([{ id: 'old' }]);
        expect(await events()).toEqual([]);
      });
    });
  });

  describe('primary route browser authorization', () => {
    test('requires an authenticated cookie and an allowed browser Origin; bearer cannot switch custody', async () => {
      const signedSessionBearer = cookie.slice(cookie.indexOf('=') + 1);
      const denials: Array<[string, Record<string, string>, number]> = [
        ['missing session', { origin }, 401],
        ['missing Origin', { cookie }, 403],
        ['cross-origin', { cookie, origin: 'https://attacker.example' }, 403],
        ['opaque Origin', { cookie, origin: 'null' }, 403],
        ['session bearer', { origin, authorization: `Bearer ${signedSessionBearer}` }, 403],
        ['cookie plus session bearer', { cookie, origin, authorization: `Bearer ${signedSessionBearer}` }, 403],
        // Better Auth interprets the bearer as a session credential before
        // the route guard: an OAuth token cannot authenticate that session.
        ['cookie plus OAuth bearer', { cookie, origin, authorization: `Bearer ${rawBearer}` }, 401],
      ];
      for (const [category, headers, status] of denials) {
        const response = await postPrimary('next', headers);
        expect(response.status, category).toBe(status);
        expect(await primaries()).toEqual([{ id: 'old' }]);
        expect(await events()).toEqual([]);
      }
      const response = await postPrimary('next');
      expect(response.status).toBe(200);
      expect(response.body.changed).toBe(true);
      expect(response.body.key).toMatchObject({ id: 'next', isPrimary: true });
      expect(response.body.key).not.toHaveProperty('sealedBlob');
      expect(await primaries()).toEqual([{ id: 'next' }]);
      const repeat = await postPrimary('next');
      expect(repeat.status).toBe(200);
      expect(repeat.body.changed).toBe(false);
      const detail = await keysRouter.request('/next', { headers: { cookie, origin } });
      expect(detail.status).toBe(200);
      expect(await detail.json()).toMatchObject({ key: { id: 'next', isPrimary: true } });
    });

    test.each([
      ['foreign', 404, 'key_not_found'], ['unowned', 404, 'key_not_found'],
      ['external', 400, 'external_key_not_eligible'], ['archived', 400, 'key_archived'],
      ['unavailable', 400, 'key_unavailable'],
    ])('returns a structured eligibility error for %s', async (keyId, status, code) => {
      const response = await postPrimary(keyId);
      expect(response.status).toBe(status);
      expect(errorSchema.parse(response.body.error)).toMatchObject({ code });
      expect(await primaries()).toEqual([{ id: 'old' }]);
    });
  });

  test('canonical identity and real delegate/sign follow the change; old-owner SIWE is rejected', async () => {
    function requestBody(owner: string) {
      const address = accounts[owner]!.address;
      const now = new Date();
      return {
        // Both selectors are deliberately stale. Only the authenticated
        // account's primary key and the SIWE/ReCap owner may select custody.
        keyId: 'old', address: accounts.old!.address, chainId: 1, type: 'siwe',
        message: prepareSession({
          address, chainId: 1, domain: 'app.example.test', issuedAt: now.toISOString(),
          expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
          spaceId: `tinycloud:pkh:eip155:1:${address}:applications`,
          jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
          abilities: { kv: { '': ['tinycloud.kv/get', 'tinycloud.kv/put'] } },
        }).siwe,
      };
    }
    async function sign(body: unknown) {
      const response = await delegateRouter.request('/sign', {
        method: 'POST', headers: { authorization: `Bearer ${rawBearer}`, 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
      return { status: response.status, body: signingResponseSchema.parse(await response.json()) };
    }
    async function assertUserInfoClaim(identity: unknown) {
      const response = await auth.handler(new Request('http://localhost:3000/api/auth/oauth2/userinfo', {
        headers: { authorization: `Bearer ${rawBearer}` },
      }));
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        sub: userId,
        'https://tinycloud.xyz/canonical_identity': identity,
      });
    }
    const policy = await policySnapshot();
    const before = await buildClaim({ id: userId }, scopes, { id: clientId }, prisma);
    expect(before).toMatchObject({ keyId: 'old', address: accounts.old!.address });
    await assertUserInfoClaim(before);
    const oldRequest = requestBody('old');
    const oldSignature = await sign(oldRequest);
    expect(oldSignature.status).toBe(200);
    expect(await recoverMessageAddress({ message: oldRequest.message, signature: oldSignature.body.signature! })).toBe(accounts.old!.address);
    expect((await postPrimary('next')).status).toBe(200);
    const after = await buildClaim({ id: userId }, scopes, { id: clientId }, prisma);
    expect(after).toEqual({
      version: 'v1', keyId: 'next', address: accounts.next!.address, chainId: 1,
      did: `did:pkh:eip155:1:${accounts.next!.address}`,
      spaceId: `tinycloud:pkh:eip155:1:${accounts.next!.address}:applications`,
    });
    await assertUserInfoClaim(after);
    const rejected = await sign(oldRequest);
    expect(rejected.status).toBe(400);
    expect(rejected.body).toMatchObject({ approved: false, code: 'message_rejected' });
    expect(rejected.body.signature).toBeUndefined();
    const newRequest = requestBody('next');
    const signed = await sign(newRequest);
    expect(signed.status).toBe(200);
    expect(signed.body).toMatchObject({ approved: true, canonicalIdentity: after });
    expect(await recoverMessageAddress({ message: newRequest.message, signature: signed.body.signature! })).toBe(accounts.next!.address);
    expect(await policySnapshot()).toEqual(policy);
  });

  test.each(['body', 'basic'] as const)('a real %s-authenticated refresh ID token follows the newly selected primary', async (method) => {
    const clientSecret = 'tc704-confidential-client-secret';
    const refreshScopes = [...scopes, 'offline_access'];
    await prisma.oauthClient.update({ where: { clientId }, data: {
      clientSecret: new Bun.CryptoHasher('sha256').update(clientSecret).digest('base64url'),
      scopes: refreshScopes, grantTypes: ['authorization_code', 'refresh_token'],
      tokenEndpointAuthMethod: method === 'basic' ? 'client_secret_basic' : 'client_secret_post',
    } });
    await prisma.oauthConsent.update({ where: { id: 'consent' }, data: { scopes: refreshScopes } });
    const verifier = randomUUID() + randomUUID();
    const query = new URLSearchParams({
      client_id: clientId, response_type: 'code', redirect_uri: 'https://app.example.test/callback',
      scope: refreshScopes.join(' '), state: randomUUID(),
      code_challenge: new Bun.CryptoHasher('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 'S256',
    });
    const authorize = await auth.handler(new Request(`http://localhost:3000/api/auth/oauth2/authorize?${query}`, { headers: { cookie } }));
    const location = authorize.headers.get('location');
    expect(location, await authorize.text()).toStartWith('https://app.example.test/callback');
    const code = new URL(location!).searchParams.get('code');
    expect(code).toBeTruthy();
    async function exchange(fields: Record<string, string>) {
      const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' };
      const body = new URLSearchParams(fields);
      if (method === 'basic') {
        headers.authorization = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;
        // The provider authenticates the header, not this conflicting body ID.
        body.set('client_id', 'not-the-authenticated-client');
      } else {
        body.set('client_id', clientId);
        body.set('client_secret', clientSecret);
      }
      const response = await auth.handler(new Request('http://localhost:3000/api/auth/oauth2/token', { method: 'POST', headers, body }));
      const payload = await response.json();
      expect(response.status, JSON.stringify(payload)).toBe(200);
      return z.object({ id_token: z.string(), refresh_token: z.string() }).parse(payload);
    }
    const initial = await exchange({ grant_type: 'authorization_code', code: code!, code_verifier: verifier, redirect_uri: 'https://app.example.test/callback' });
    const jwksResponse = await auth.handler(new Request('http://localhost:3000/api/auth/jwks'));
    const jwks = createLocalJWKSet(await jwksResponse.json() as Parameters<typeof createLocalJWKSet>[0]);
    async function identity(idToken: string) {
      const { payload } = await jwtVerify(idToken, jwks, { audience: clientId, issuer: (await auth.$context).baseURL });
      return payload['https://tinycloud.xyz/canonical_identity'];
    }
    expect(await identity(initial.id_token)).toMatchObject({ keyId: 'old', address: accounts.old!.address });
    expect((await postPrimary('next')).status).toBe(200);
    const refreshed = await exchange({ grant_type: 'refresh_token', refresh_token: initial.refresh_token });
    expect(await identity(refreshed.id_token)).toEqual({
      version: 'v1', keyId: 'next', address: accounts.next!.address, chainId: 1,
      did: `did:pkh:eip155:1:${accounts.next!.address}`,
      spaceId: `tinycloud:pkh:eip155:1:${accounts.next!.address}:applications`,
    });
  });

  test.skipIf(backend !== 'postgres')('competing switches wait for the user lock and commit exactly one primary', async () => {
    const blocker = new Client({ connectionString });
    const inspector = new Client({ connectionString });
    const secondPrisma = createPrismaClient({ connectionString });
    await blocker.connect();
    await inspector.connect();
    let switches: Array<Promise<PrimaryModule.SetPrimaryKeyResult>> = [];
    try {
      await blocker.query('BEGIN');
      await blocker.query('SELECT "id" FROM "user" WHERE "id" = $1 FOR UPDATE', [userId]);
      switches = [setPrimaryKey(prisma, userId, 'next'), setPrimaryKey(secondPrisma, userId, 'third')];
      // Observe actual database lock waits; each query yields to the real
      // connections, without assuming a fixed sleep makes them overlap.
      const deadline = Date.now() + 3_000;
      let waiting = 0;
      while (Date.now() < deadline) {
        const result = await inspector.query(`
          SELECT count(*)::int AS count FROM pg_stat_activity
          WHERE datname = current_database() AND wait_event_type = 'Lock'
            AND query LIKE '%FOR UPDATE%'
        `);
        waiting = result.rows[0].count;
        if (waiting === 2) break;
      }
      expect(waiting).toBe(2);
      expect(await primaries()).toEqual([{ id: 'old' }]);
      await blocker.query('COMMIT');
      const results = await Promise.all(switches);
      const changes = results.filter((result) => result.kind === 'changed');
      expect(changes).toHaveLength(2);
      const first = changes.find((result) => result.previousKeyId === 'old');
      expect(first).toBeDefined();
      const second = changes.find((result) => result !== first)!;
      expect(second.previousKeyId).toBe(first!.keyId);
      expect(await primaries()).toEqual([{ id: second.keyId }]);
      expect(await events()).toHaveLength(2);
    } finally {
      await blocker.query('ROLLBACK');
      await Promise.allSettled(switches);
      await secondPrisma.$disconnect();
      await blocker.end();
      await inspector.end();
    }
  }, 15_000);
}
