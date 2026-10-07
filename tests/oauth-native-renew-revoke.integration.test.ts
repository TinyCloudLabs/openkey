import { afterAll, beforeAll, beforeEach, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomUUID, sign, type KeyObject } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { Client } from 'pg';
import { serializeSignedCookie } from 'better-call';
import { getAddress, recoverMessageAddress } from 'viem';
import { SiweMessage } from 'siwe';
import type * as DatabaseModule from '@openkey/db';

const backend = process.env.TC773_O5_TEST_CHILD;
const postgresUrl = process.env.OPENKEY_TEST_POSTGRES_URL;
const root = resolve(import.meta.dir, '..');

if (!backend) {
  for (const engine of ['pglite', 'postgres']) {
    test.skipIf(engine === 'postgres' && !postgresUrl)(`TC-773 native renew and revoke (${engine})`, async () => {
      const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
        cwd: root, env: { ...process.env, TC773_O5_TEST_CHILD: engine, NODE_ENV: 'test', TEE_MODE: 'development',
          BETTER_AUTH_URL: 'https://api.openkey.test', BETTER_AUTH_SECRET: 'tc773-o5-isolated-test-secret-for-development-only',
          WEBAUTHN_RP_ID: 'openkey.test', WEBAUTHN_ORIGIN: 'https://openkey.test', CORS_ORIGIN: 'https://openkey.test',
          ADMIN_API_KEY: 'tc773-admin-key', RESEND_API_KEY: '', GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '' },
        stdout: 'pipe', stderr: 'pipe',
      });
      const [stdout, stderr, exitCode] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
      expect(exitCode, stdout + stderr).toBe(0);
    }, 300_000);
  }
} else {
  const directory = await mkdtemp(join(tmpdir(), 'openkey-tc773-o5-'));
  const databaseName = `tc773_o5_${randomUUID().replaceAll('-', '')}`;
  let admin: Client | undefined;
  let prisma: DatabaseModule.PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let clientId: string;
  let address: string;
  let cookie: string;
  const API = 'https://api.openkey.test';
  const ISSUER = `${API}/api/auth`;
  const RENEW = '/api/auth/oauth2/tinycloud/renew';
  const REVOKE = '/api/auth/oauth2/tinycloud/revoke';
  const DELEGATION = 'tinycloud:delegation';
  const HOST = 'https://tee.node.tinycloud.xyz';
  const USER = 'o5-user';
  const permissions = [
    { service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] },
    { service: 'tinycloud.kv', space: 'applications', path: 'xyz.tinycloud.tinychat/threads/', actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] },
  ];
  const ceiling = { version: 1, appId: 'xyz.tinycloud.tinychat', tinycloudHost: HOST,
    kv: { paths: ['xyz.tinycloud.tinychat/threads/'], actions: ['get', 'put', 'list'] }, sql: null,
    maxDelegationTtlSeconds: 3600, grantLifetimeSeconds: 30 * 86400 };
  const hash = (value: string) => createHash('sha256').update(value).digest('base64url');
  const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  type SessionKey = { privateKey: KeyObject; publicJwk: { kty: 'OKP'; crv: 'Ed25519'; x: string }; jkt: string };

  function sessionKey(): SessionKey {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const { x } = publicKey.export({ format: 'jwk' }) as { x: string };
    return { privateKey, publicJwk: { kty: 'OKP', crv: 'Ed25519', x }, jkt: hash(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x })) };
  }

  function didKey(x: string) {
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let value = BigInt(`0x${Buffer.from([0xed, 0x01, ...Buffer.from(x, 'base64url')]).toString('hex')}`);
    let encoded = '';
    while (value > 0n) { encoded = alphabet[Number(value % 58n)] + encoded; value /= 58n; }
    return `did:key:z${encoded}`;
  }

  function proof(key: SessionKey, token: string, path: string, overrides: { signer?: KeyObject; kid?: string; credHash?: string } = {}) {
    const header = b64({ typ: 'openkey-session-proof+jwt', alg: 'EdDSA', kid: overrides.kid ?? key.jkt });
    const payload = b64({ jti: randomUUID().replaceAll('-', ''), iat: Math.floor(Date.now() / 1000), htm: 'POST',
      htu: `${ISSUER}${path.slice('/api/auth'.length)}`, client_id: clientId, cred_hash: overrides.credHash ?? hash(token) });
    return `${header}.${payload}.${sign(null, Buffer.from(`${header}.${payload}`), overrides.signer ?? key.privateKey).toString('base64url')}`;
  }

  function form(path: string, fields: URLSearchParams, sessionProof?: string, extraHeaders: Record<string, string> = {}) {
    return app.fetch(new Request(`${API}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded',
      Origin: 'capacitor://localhost', ...(sessionProof ? { 'OpenKey-Session-Proof': sessionProof } : {}), ...extraHeaders }, body: fields.toString() }));
  }
  function renew(key: SessionKey, token: string, extra: Record<string, string> = {}, proofOverride?: string) {
    return form(RENEW, new URLSearchParams({ client_id: clientId, refresh_token: token, ...extra }), proofOverride ?? proof(key, token, RENEW));
  }
  function revoke(key: SessionKey, token: string, proofOverride?: string) {
    return form(REVOKE, new URLSearchParams({ client_id: clientId, refresh_token: token }), proofOverride ?? proof(key, token, REVOKE));
  }
  async function error(response: Response) { return (await response.json() as { error: string }).error; }

  async function seedDevice(id: string, key: SessionKey, token: string, options: { ttl?: number; expiresAt?: Date; tokenExpiresAt?: Date; revoked?: boolean; lastRenewedAt?: Date } = {}) {
    const did = didKey(key.publicJwk.x);
    await prisma.oauthRefreshToken.create({ data: { id: `${id}-refresh`, token: hash(token), clientId, userId: USER,
      scopes: ['openid', 'offline_access', DELEGATION], revoked: options.revoked ? new Date() : null,
      expiresAt: options.tokenExpiresAt ?? new Date(Date.now() + 7 * 86400_000) } });
    await prisma.tinyCloudNativeGrant.create({ data: { id, userId: USER, clientId, consentId: 'o5-consent', consentGeneration: 0n,
      keyId: 'o5-key', address, sessionDid: `${did}#${did.slice('did:key:'.length)}`, sessionJwk: key.publicJwk,
      sessionJkt: key.jkt, spaceId: `tinycloud:pkh:eip155:1:${address}:applications`, approvedPermissions: permissions,
      ttlSeconds: options.ttl ?? 3600, tinycloudHost: HOST, refreshTokenHash: hash(token),
      absoluteExpiresAt: options.expiresAt ?? new Date(Date.now() + 30 * 86400_000), lastRenewedAt: options.lastRenewedAt ?? null } });
  }

  beforeAll(async () => {
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    let connectionString: string;
    if (backend === 'postgres') {
      if (!postgresUrl) throw new Error('OPENKEY_TEST_POSTGRES_URL required');
      admin = new Client({ connectionString: postgresUrl }); await admin.connect();
      await admin.query(`CREATE DATABASE "${databaseName}"`);
      const target = new URL(postgresUrl); target.pathname = `/${databaseName}`; connectionString = target.toString();
      const connection = new Client({ connectionString }); await connection.connect();
      try { for (const migration of migrations) await connection.query(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8')); }
      finally { await connection.end(); }
    } else {
      const database = new PGlite(directory);
      try { for (const migration of migrations) await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8')); }
      finally { await database.close(); }
      connectionString = `pglite:${directory}`;
    }
    process.env.DATABASE_URL = connectionString;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    const { createPrismaClient } = await import('@openkey/db');
    prisma = createPrismaClient();
    const { auth } = await import('../apps/api/src/auth');
    app = (await import('../apps/api/src/index')).default;
    await prisma.user.create({ data: { id: USER, email: 'o5@example.test', name: 'O5', emailVerified: true } });
    const sessionToken = randomUUID();
    await prisma.session.create({ data: { id: 'o5-session', token: sessionToken, userId: USER, expiresAt: new Date(Date.now() + 3_600_000) } });
    const context = await auth.$context;
    cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, sessionToken, context.secret)).split(';')[0]!;
    const { createTeeClient, generatePrivateKey, getAddressFromPrivateKey, seal } = await import('@openkey/tee');
    const privateKey = generatePrivateKey(); address = getAddress(getAddressFromPrivateKey(privateKey));
    const sealingContext = randomUUID().replaceAll('-', '').padEnd(43, 'A').slice(0, 43);
    const sealingKey = await createTeeClient().deriveKey(`openkey/key/${sealingContext}`);
    await prisma.ethereumKey.create({ data: { id: 'o5-key', userId: USER, address, publicKey: '0x1',
      sealedBlob: await seal(privateKey, sealingKey), sealingContext, keyType: 'MANAGED', isCanonicalTinyCloud: true } });
    const response = await app.fetch(new Request(`${API}/api/admin/oauth/clients`, { method: 'POST',
      headers: { Authorization: 'Bearer tc773-admin-key', 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'O5 native', type: 'native', redirectUris: ['xyz.tinycloud.exo://openkey/callback'], tinycloudNativeDelegation: ceiling }) }));
    expect(response.status, await response.clone().text()).toBe(201);
    clientId = (await response.json() as { client: { clientId: string } }).client.clientId;
  }, 120_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    if (admin) { await admin.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`); await admin.end(); }
    await rm(directory, { recursive: true, force: true });
  });

  beforeEach(async () => {
    await prisma.$executeRawUnsafe(`TRUNCATE TABLE "oauth_refresh_token", "oauth_access_token", "oauth_consent",
      "tinycloud_native_grant", "tinycloud_native_request", "tinycloud_native_consent_generation",
      "tinycloud_manage_key_app_preference", "tinycloud_manage_key_signing_decision" CASCADE`);
    await prisma.user.update({ where: { id: USER }, data: { tinyCloudManageKeyMode: 'APP_MANAGED' } });
    await prisma.oauthClient.update({ where: { clientId }, data: { disabled: false, scopes: ['openid', 'offline_access', DELEGATION], tinycloudNativeDelegation: ceiling } });
    await prisma.oauthConsent.create({ data: { id: 'o5-consent', userId: USER, clientId, scopes: ['openid', 'offline_access', DELEGATION] } });
    await prisma.tinyCloudNativeConsentGeneration.create({ data: { userId: USER, clientId, generation: 0n } });
  });

  test(`renew rotates over HTTP with the same DID, approved permissions, TTL and copied scopes (${backend})`, async () => {
    const key = sessionKey(); await seedDevice('device-a', key, 'token-a', { ttl: 300 });
    const response = await renew(key, 'token-a', { siwe_nonce: 'abcdefgh' });
    expect(response.status, await response.clone().text()).toBe(200);
    expect(response.headers.get('access-control-allow-origin')).toBe('*');
    const body = await response.json() as { refresh_token: string; expires_in: number; tinycloud_delegation: {
      grantId: string; verificationMethod: string; siwe: string; signature: `0x${string}`; issuedAt: string; expiresAt: string;
      permissions: typeof permissions; renewableUntil: string; hosting: string;
    } };
    expect(body.expires_in).toBe(604800);
    expect(body.refresh_token).not.toBe('token-a');
    expect(body.tinycloud_delegation.grantId).toBe('device-a');
    expect(body.tinycloud_delegation.verificationMethod).toBe((await prisma.tinyCloudNativeGrant.findUniqueOrThrow({ where: { id: 'device-a' } })).sessionDid);
    expect(body.tinycloud_delegation.permissions).toEqual(permissions);
    expect(Date.parse(body.tinycloud_delegation.expiresAt) - Date.parse(body.tinycloud_delegation.issuedAt)).toBe(300_000);
    expect(new SiweMessage(body.tinycloud_delegation.siwe).nonce).toBe('abcdefgh');
    expect(await recoverMessageAddress({ message: body.tinycloud_delegation.siwe, signature: body.tinycloud_delegation.signature })).toBe(address);
    const old = await prisma.oauthRefreshToken.findUniqueOrThrow({ where: { token: hash('token-a') } });
    expect(old.revoked).not.toBeNull();
    const current = await prisma.oauthRefreshToken.findUniqueOrThrow({ where: { token: hash(body.refresh_token) } });
    expect(current.scopes).toEqual(old.scopes);
    expect((await prisma.tinyCloudManageKeySigningDecision.findFirstOrThrow({ where: { userId: USER }, orderBy: { createdAt: 'desc' } })).reason).toBe('native_renew');
  });

  test(`subset succeeds; superset and detail nonce/TTL are refused (${backend})`, async () => {
    const key = sessionKey(); await seedDevice('device-a', key, 'token-a');
    const detail = (subset: typeof permissions, extra = {}) => JSON.stringify([{ type: 'tinycloud_delegation', session_key: key.publicJwk, permissions: subset, ...extra }]);
    const subset = [{ ...permissions[0]! }, { ...permissions[1]!, actions: ['tinycloud.kv/get'] }];
    const first = await renew(key, 'token-a', { authorization_details: detail(subset) });
    expect(first.status, await first.clone().text()).toBe(200);
    expect((await first.json() as { tinycloud_delegation: { permissions: unknown } }).tinycloud_delegation.permissions).toEqual(subset);
    const rotated = (await prisma.tinyCloudNativeGrant.findUniqueOrThrow({ where: { id: 'device-a' } })).refreshTokenHash!;
    const row = await prisma.oauthRefreshToken.findUniqueOrThrow({ where: { token: rotated } });
    expect(row.scopes).toContain(DELEGATION);
    const tooWide = [{ ...permissions[0]! }, { ...permissions[1]!, actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] }];
    const superset = await renew(key, 'token-a', { authorization_details: detail(tooWide) });
    // Previous-token conflict has precedence, so use a second live device.
    expect(superset.status).toBe(409);
    const other = sessionKey(); await seedDevice('device-b', other, 'token-b');
    const refused = await renew(other, 'token-b', { authorization_details: JSON.stringify([{ type: 'tinycloud_delegation', session_key: other.publicJwk, permissions: tooWide }]) });
    expect(refused.status).toBe(400);
    expect(await error(refused)).toBe('invalid_authorization_details');
    for (const field of [{ ttl_seconds: 3600 }, { siwe_nonce: 'abcdefgh' }]) {
      const bad = await renew(other, 'token-b', { authorization_details: JSON.stringify([{ type: 'tinycloud_delegation', session_key: other.publicJwk, permissions, ...field }]) });
      expect(bad.status).toBe(400);
      expect(await error(bad)).toBe('invalid_authorization_details');
    }
  });

  test(`unknown and wrong proofs are indistinguishable; dead tokens fail (${backend})`, async () => {
    const key = sessionKey(); await seedDevice('device-a', key, 'token-a');
    const wrong = sessionKey();
    for (const response of [await renew(key, 'unknown'), await renew(key, 'token-a', {}, proof(wrong, 'token-a', RENEW)),
      await renew(key, 'token-a', {}, proof(key, 'token-a', RENEW, { kid: wrong.jkt })),
      await renew(key, 'token-a', {}, proof(key, 'token-a', RENEW, { credHash: hash('wrong') }))]) {
      expect(response.status).toBe(401); expect(await error(response)).toBe('invalid_session_proof');
    }
    await prisma.oauthRefreshToken.update({ where: { token: hash('token-a') }, data: { expiresAt: new Date(Date.now() - 1000) } });
    const expired = await renew(key, 'token-a'); expect(expired.status).toBe(400); expect(await error(expired)).toBe('invalid_grant');
    await prisma.oauthRefreshToken.update({ where: { token: hash('token-a') }, data: { expiresAt: new Date(Date.now() + 7 * 86400_000), revoked: new Date() } });
    const used = await renew(key, 'token-a'); expect(used.status).toBe(400); expect(await error(used)).toBe('invalid_grant');
    await prisma.oauthRefreshToken.delete({ where: { token: hash('token-a') } });
    const missing = await renew(key, 'token-a'); expect(missing.status).toBe(400); expect(await error(missing)).toBe('invalid_grant');
  });

  test(`withdrawal, block, exclusive mode and fixed short TTL (${backend})`, async () => {
    const key = sessionKey(); await seedDevice('device-a', key, 'token-a', { ttl: 300 });
    await prisma.tinyCloudManageKeyAppPreference.create({ data: { userId: USER, clientId, enabled: false, status: 'DISABLED' } });
    const blocked = await renew(key, 'token-a'); expect(blocked.status).toBe(400); expect(await error(blocked)).toBe('access_denied');
    await prisma.tinyCloudManageKeyAppPreference.delete({ where: { userId_clientId: { userId: USER, clientId } } });
    await prisma.user.update({ where: { id: USER }, data: { tinyCloudManageKeyMode: 'USER_CONTROLLED_EXCLUSIVE' } });
    const exclusive = await renew(key, 'token-a'); expect(exclusive.status).toBe(400); expect(await error(exclusive)).toBe('access_denied');
    await prisma.user.update({ where: { id: USER }, data: { tinyCloudManageKeyMode: 'APP_MANAGED' } });
    await prisma.oauthClient.update({ where: { clientId }, data: { tinycloudNativeDelegation: { ...ceiling, maxDelegationTtlSeconds: 7200 } } });
    const renewed = await renew(key, 'token-a'); expect(renewed.status).toBe(200);
    const body = await renewed.json() as { refresh_token: string; tinycloud_delegation: { issuedAt: string; expiresAt: string } };
    expect(Date.parse(body.tinycloud_delegation.expiresAt) - Date.parse(body.tinycloud_delegation.issuedAt)).toBe(300_000);
    await prisma.oauthConsent.delete({ where: { id: 'o5-consent' } });
    await prisma.oauthConsent.create({ data: { id: 'o5-consent-new', userId: USER, clientId, scopes: ['openid', 'offline_access', DELEGATION] } });
    const withdrawn = await renew(key, body.refresh_token);
    expect(withdrawn.status).toBe(400); expect(await error(withdrawn)).toBe('invalid_grant');
  });

  test(`current ceiling and absolute grant end cap the renewed TTL (${backend})`, async () => {
    const keyA = sessionKey();
    await seedDevice('device-a', keyA, 'token-a', { ttl: 3600, expiresAt: new Date(Date.now() + 3500_000) });
    const capped = await renew(keyA, 'token-a'); expect(capped.status).toBe(200);
    const first = await capped.json() as { tinycloud_delegation: { issuedAt: string; expiresAt: string } };
    expect(Date.parse(first.tinycloud_delegation.expiresAt) - Date.parse(first.tinycloud_delegation.issuedAt)).toBeLessThanOrEqual(3500_000);
    const keyB = sessionKey(); await seedDevice('device-b', keyB, 'token-b');
    await prisma.oauthClient.update({ where: { clientId }, data: { tinycloudNativeDelegation: { ...ceiling, maxDelegationTtlSeconds: 300 } } });
    const lowered = await renew(keyB, 'token-b'); expect(lowered.status).toBe(200);
    const second = await lowered.json() as { tinycloud_delegation: { issuedAt: string; expiresAt: string } };
    expect(Date.parse(second.tinycloud_delegation.expiresAt) - Date.parse(second.tinycloud_delegation.issuedAt)).toBe(300_000);
  });

  test(`disabled client, reduced permission ceiling and changed canonical key require consent (${backend})`, async () => {
    const key = sessionKey(); await seedDevice('device-a', key, 'token-a');
    await prisma.oauthClient.update({ where: { clientId }, data: { disabled: true } });
    const disabled = await renew(key, 'token-a'); expect(disabled.status).toBe(400); expect(await error(disabled)).toBe('consent_required');
    await prisma.oauthClient.update({ where: { clientId }, data: { disabled: false,
      tinycloudNativeDelegation: { ...ceiling, kv: { ...ceiling.kv, actions: ['get'] } } } });
    const reduced = await renew(key, 'token-a'); expect(reduced.status).toBe(400); expect(await error(reduced)).toBe('consent_required');
    await prisma.oauthClient.update({ where: { clientId }, data: { tinycloudNativeDelegation: ceiling } });
    await prisma.ethereumKey.update({ where: { id: 'o5-key' }, data: { isCanonicalTinyCloud: false } });
    try {
      const changed = await renew(key, 'token-a'); expect(changed.status).toBe(400); expect(await error(changed)).toBe('consent_required');
    } finally {
      await prisma.ethereumKey.update({ where: { id: 'o5-key' }, data: { isCanonicalTinyCloud: true } });
    }
  });

  test(`429 has CORS-visible Retry-After; previous-token reuse is one-device only (${backend})`, async () => {
    const keyA = sessionKey(), keyB = sessionKey();
    await seedDevice('device-a', keyA, 'token-a'); await seedDevice('device-b', keyB, 'token-b');
    const first = await renew(keyA, 'token-a'); expect(first.status).toBe(200);
    const rotated = (await first.json() as { refresh_token: string }).refresh_token;
    const conflict = await renew(keyA, 'token-a'); expect(conflict.status).toBe(409); expect(await error(conflict)).toBe('renewal_conflict');
    const soon = await renew(keyA, rotated); expect(soon.status).toBe(429); expect(await error(soon)).toBe('renewal_too_soon');
    expect(Number(soon.headers.get('retry-after'))).toBeGreaterThan(0);
    expect(soon.headers.get('access-control-expose-headers')?.toLowerCase()).toContain('retry-after');
    await prisma.tinyCloudNativeGrant.update({ where: { id: 'device-a' }, data: { rotatedAt: new Date(Date.now() - 31_000) } });
    const reused = await renew(keyA, 'token-a'); expect(reused.status).toBe(400); expect(await error(reused)).toBe('invalid_grant');
    expect((await prisma.tinyCloudNativeGrant.findUniqueOrThrow({ where: { id: 'device-a' } })).revokedReason).toBe('refresh_reuse');
    expect(await prisma.oauthRefreshToken.findUnique({ where: { token: hash(rotated) } })).toBeNull();
    const other = await renew(keyB, 'token-b'); expect(other.status).toBe(200);
  });

  test(`native revoke is idempotent and leaves the other device intact; provider revoke refuses rotated tokens (${backend})`, async () => {
    const keyA = sessionKey(), keyB = sessionKey();
    await seedDevice('device-a', keyA, 'token-a'); await seedDevice('device-b', keyB, 'token-b');
    for (const id of ['device-a', 'device-b']) await prisma.oauthAccessToken.create({ data: {
      id: `${id}-access`, token: hash(`${id}-access`), clientId, userId: USER, refreshId: `${id}-refresh`,
      scopes: ['openid', DELEGATION], expiresAt: new Date(Date.now() + 300_000),
    } });
    const first = await renew(keyA, 'token-a'); expect(first.status).toBe(200);
    const rotated = (await first.json() as { refresh_token: string }).refresh_token;
    const provider = await form('/api/auth/oauth2/revoke', new URLSearchParams({ client_id: clientId, token: 'token-a' }));
    expect(provider.status).toBe(400); expect(await error(provider)).toBe('unsupported_token_type');
    const providerCurrent = await form('/api/auth/oauth2/revoke', new URLSearchParams({ client_id: clientId, token: rotated }));
    expect(providerCurrent.status).toBe(400); expect(await error(providerCurrent)).toBe('unsupported_token_type');
    const removed = await revoke(keyA, rotated); expect(removed.status).toBe(200); expect(await removed.json()).toEqual({});
    expect(await prisma.oauthAccessToken.findUnique({ where: { id: 'device-a-access' } })).toBeNull();
    expect(await prisma.oauthAccessToken.findUnique({ where: { id: 'device-b-access' } })).not.toBeNull();
    const again = await revoke(keyA, 'token-a'); expect(again.status).toBe(200); expect(await again.json()).toEqual({});
    const unknown = await revoke(keyA, 'unknown'); expect(unknown.status).toBe(401); expect(await error(unknown)).toBe('invalid_session_proof');
    const other = await renew(keyB, 'token-b'); expect(other.status).toBe(200);
  });

  test(`account list includes native grants; block and Disconnect control renewal (${backend})`, async () => {
    const key = sessionKey(); await seedDevice('device-a', key, 'token-a');
    const account = (method: string, body?: unknown) => app.fetch(new Request(`${API}/api/account/tinycloud-apps${method === 'GET' ? '' : `/${clientId}`}`, {
      method, headers: { cookie, Origin: 'https://openkey.test', ...(body ? { 'Content-Type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    }));
    const listed = await account('GET'); expect(listed.status).toBe(200);
    const data = await listed.json() as { apps: { clientId: string; nativeDelegation: boolean; activeNativeGrants: number; enabled: boolean }[]; policyEpoch: number };
    expect(data.apps).toContainEqual(expect.objectContaining({ clientId, nativeDelegation: true, activeNativeGrants: 1, enabled: true }));
    const blocked = await account('PATCH', { enabled: false, expectedEpoch: data.policyEpoch, confirmation: 'TAKE CONTROL' });
    expect(blocked.status, await blocked.clone().text()).toBe(200);
    const refused = await renew(key, 'token-a'); expect(refused.status).toBe(400); expect(await error(refused)).toBe('access_denied');
    const disconnected = await account('DELETE', { confirmation: 'DISCONNECT' });
    expect(disconnected.status, await disconnected.clone().text()).toBe(200);
    expect((await prisma.tinyCloudNativeGrant.findUniqueOrThrow({ where: { id: 'device-a' } })).status).toBe('REVOKED');
    expect(await prisma.oauthRefreshToken.findUnique({ where: { token: hash('token-a') } })).toBeNull();
  });

  if (backend === 'postgres') {
    test('a consent lock timeout rolls back renew and revoke and exposes Retry-After', async () => {
      const key = sessionKey(); await seedDevice('device-a', key, 'token-a');
      const blocker = new Client({ connectionString: process.env.DATABASE_URL }); await blocker.connect();
      try {
        await blocker.query('BEGIN');
        await blocker.query('SELECT id FROM oauth_consent WHERE id = $1 FOR UPDATE', ['o5-consent']);
        for (const response of [await renew(key, 'token-a'), await revoke(key, 'token-a')]) {
          expect(response.status, await response.clone().text()).toBe(503);
          expect(await error(response)).toBe('temporarily_unavailable');
          expect(response.headers.get('retry-after')).toBe('2');
          expect(response.headers.get('access-control-expose-headers')?.toLowerCase()).toContain('retry-after');
        }
        expect((await prisma.tinyCloudNativeGrant.findUniqueOrThrow({ where: { id: 'device-a' } })).status).toBe('ACTIVE');
      } finally { await blocker.query('ROLLBACK').catch(() => {}); await blocker.end(); }
    }, 20_000);

    test('consent deletion commits first; renewal observes withdrawal without a deadlock', async () => {
      const key = sessionKey(); await seedDevice('device-a', key, 'token-a');
      const connection = new Client({ connectionString: process.env.DATABASE_URL }); await connection.connect();
      try {
        await connection.query('BEGIN');
        await connection.query('DELETE FROM oauth_consent WHERE id = $1', ['o5-consent']);
        const pending = renew(key, 'token-a');
        await Bun.sleep(150);
        await connection.query('COMMIT');
        const response = await pending;
        expect(response.status).toBe(400);
        expect(['invalid_grant', 'consent_required']).toContain(await error(response));
        expect(await prisma.oauthRefreshToken.findUnique({ where: { token: hash('token-a') } })).toBeNull();
      } finally { await connection.query('ROLLBACK').catch(() => {}); await connection.end(); }
    });

    test('renewal commits first; waiting consent deletion deletes its new token', async () => {
      const key = sessionKey(); await seedDevice('device-a', key, 'token-a');
      const blocker = new Client({ connectionString: process.env.DATABASE_URL });
      const deleter = new Client({ connectionString: process.env.DATABASE_URL });
      await blocker.connect(); await deleter.connect();
      try {
        await blocker.query('BEGIN');
        await blocker.query('SELECT id FROM oauth_refresh_token WHERE token = $1 FOR UPDATE', [hash('token-a')]);
        const renewal = renew(key, 'token-a');
        await Bun.sleep(250);
        const deletion = deleter.query('DELETE FROM oauth_consent WHERE id = $1', ['o5-consent']);
        await Bun.sleep(150);
        await blocker.query('COMMIT');
        const response = await renewal;
        expect(response.status, await response.clone().text()).toBe(200);
        const token = (await response.json() as { refresh_token: string }).refresh_token;
        await deletion;
        expect(await prisma.oauthRefreshToken.findUnique({ where: { token: hash(token) } })).toBeNull();
        expect((await prisma.tinyCloudNativeGrant.findUniqueOrThrow({ where: { id: 'device-a' } })).status).toBe('REVOKED');
      } finally {
        await blocker.query('ROLLBACK').catch(() => {});
        await Promise.all([blocker.end(), deleter.end()]);
      }
    });
  }
}
