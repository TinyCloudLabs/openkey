import './tc1777-test-env';
import { afterAll, beforeAll, beforeEach, expect, spyOn, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomUUID, sign, type KeyObject } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { getAddress, recoverMessageAddress } from 'viem';
import { SiweMessage } from 'siwe';
import { serializeSignedCookie } from 'better-call';
import type * as DatabaseModule from '@openkey/db';
import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/server';
import { createSoftPasskey } from './soft-passkey';

// TC-3569 PR 2a: the step-up request endpoint over HTTP on the tracked
// migration chain. It records a STEPUP request and signs nothing; the sign-in
// consent and exchange paths refuse such a request. Runs in a child process:
// other API tests replace @openkey/db and Better Auth globally.
const root = resolve(import.meta.dir, '../../../..');
const child = process.env.TC3569_STEPUP_TEST_CHILD === '1';

if (!child) {
  test('step-up request endpoint (HTTP, real migration chain)', async () => {
    const run = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env, TC3569_STEPUP_TEST_CHILD: '1', NODE_ENV: 'test', TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test', BETTER_AUTH_SECRET: 'tc3569-stepup-isolated-test-secret-0123456789',
        WEBAUTHN_RP_ID: 'openkey.test', WEBAUTHN_ORIGIN: 'https://openkey.test', CORS_ORIGIN: 'https://openkey.test',
        ADMIN_API_KEY: 'tc3569-admin-key', RESEND_API_KEY: '', GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '',
      },
      stdout: 'pipe', stderr: 'pipe',
    });
    const [stdout, stderr, status] = await Promise.all([new Response(run.stdout).text(), new Response(run.stderr).text(), run.exited]);
    expect(status, stdout + stderr).toBe(0);
  }, 300_000);
} else {
  const directory = await mkdtemp(join(tmpdir(), 'openkey-tc3569-'));
  let prisma: DatabaseModule.PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let clientId: string;
  let cookie: string;
  let cookieB: string;
  let address: `0x${string}`;
  const API = 'https://api.openkey.test';
  const ISSUER = `${API}/api/auth`;
  const STEPUP = '/api/auth/oauth2/tinycloud/stepup';
  const RENEW = '/api/auth/oauth2/tinycloud/renew';
  const DELEGATION = 'tinycloud:delegation';
  const HOST = 'https://tee.node.tinycloud.xyz';
  const HOME_REDIRECT = 'xyz.tinycloud.exo://openkey/callback';
  const STEPUP_REDIRECT = 'xyz.tinycloud.exo://openkey/stepup';
  const USER = 'su-user';
  const EXPLORER = 'xyz.tinycloud.explorer';
  const homePermissions = [
    { service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] },
    { service: 'tinycloud.kv', space: 'applications', path: 'xyz.tinycloud.home/', actions: ['tinycloud.kv/get'] },
  ];
  const explorerEntries = [
    { service: 'tinycloud.kv', space: 'public', path: '', actions: ['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/metadata'] },
    { service: 'tinycloud.sql', space: 'applications', path: 'default', actions: ['tinycloud.sql/read', 'tinycloud.sql/schema'] },
  ];
  const ceiling = {
    version: 1, appId: 'xyz.tinycloud.home', tinycloudHost: HOST,
    kv: { paths: ['xyz.tinycloud.home/'], actions: ['get', 'list'] }, sql: null,
    maxDelegationTtlSeconds: 3600, grantLifetimeSeconds: 30 * 86400,
    stepUps: {
      [EXPLORER]: {
        public: { kv: { paths: [''], actions: ['get', 'list', 'metadata'] } },
        applications: { sql: { databases: ['default'], actions: ['read', 'schema'] } },
      },
      'xyz.tinycloud.account': { account: { kv: { paths: ['applications/', 'spaces/'], actions: ['get', 'list'] } } },
    },
  };
  const hash = (value: string) => createHash('sha256').update(value).digest('base64url');
  const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const VERIFIER = 'tc3569-stepup-verifier-0123456789-0123456789-0123456789';
  const challenge = hash(VERIFIER);
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

  function proof(key: SessionKey, token: string, path: string, overrides: { signer?: KeyObject; jti?: string } = {}) {
    const header = b64({ typ: 'openkey-session-proof+jwt', alg: 'EdDSA', kid: key.jkt });
    const payload = b64({ jti: overrides.jti ?? randomUUID().replaceAll('-', ''), iat: Math.floor(Date.now() / 1000), htm: 'POST',
      htu: `${ISSUER}${path.slice('/api/auth'.length)}`, client_id: clientId, cred_hash: hash(token) });
    return `${header}.${payload}.${sign(null, Buffer.from(`${header}.${payload}`), overrides.signer ?? key.privateKey).toString('base64url')}`;
  }

  function post(path: string, fields: URLSearchParams, sessionProof?: string) {
    return app.fetch(new Request(`${API}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded',
      Origin: 'capacitor://localhost', ...(sessionProof ? { 'OpenKey-Session-Proof': sessionProof } : {}) }, body: fields.toString() }));
  }

  function stepUp(key: SessionKey, token: string, overrides: Record<string, string> = {}, proofOverride?: string) {
    return post(STEPUP, new URLSearchParams({
      client_id: clientId, refresh_token: token, app_id: EXPLORER, permissions: JSON.stringify(explorerEntries),
      redirect_uri: STEPUP_REDIRECT, state: 'a'.repeat(32), code_challenge: challenge, code_challenge_method: 'S256',
      ...overrides,
    }), proofOverride ?? proof(key, token, STEPUP));
  }

  async function body(response: Response) { return await response.json() as Record<string, string>; }

  async function seedDevice(id: string, key: SessionKey, token: string, options: { expiresAt?: Date; tokenExpiresAt?: Date; tokenRevoked?: boolean } = {}) {
    const did = didKey(key.publicJwk.x);
    await prisma.oauthRefreshToken.create({ data: { id: `${id}-refresh`, token: hash(token), clientId, userId: USER,
      scopes: ['openid', 'offline_access', DELEGATION], revoked: options.tokenRevoked ? new Date() : null,
      expiresAt: options.tokenExpiresAt ?? new Date(Date.now() + 7 * 86400_000) } });
    await prisma.tinyCloudNativeGrant.create({ data: { id, userId: USER, clientId, consentId: 'su-consent', consentGeneration: 0n,
      keyId: 'su-key', address, sessionDid: `${did}#${did.slice('did:key:'.length)}`,
      sessionJwk: key.publicJwk, sessionJkt: key.jkt, spaceId: `tinycloud:pkh:eip155:1:${address}:applications`,
      approvedPermissions: homePermissions, ttlSeconds: 3600, tinycloudHost: HOST, refreshTokenHash: hash(token),
      absoluteExpiresAt: options.expiresAt ?? new Date(Date.now() + 30 * 86400_000) } });
  }

  const requests = () => prisma.tinyCloudNativeRequest.count();

  beforeAll(async () => {
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    const database = new PGlite(directory);
    try { for (const migration of migrations) await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8')); }
    finally { await database.close(); }
    process.env.DATABASE_URL = `pglite:${directory}`;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    // The per-user consent budget (30 approves a minute) is not what these flows test; the endpoint's own caps are.
    const { mock } = await import('bun:test');
    const userRateLimit = await import('../services/native-delegation/user-rate-limit');
    mock.module('../services/native-delegation/user-rate-limit', () => ({ ...userRateLimit, nativeUserRetryAfter: () => 0 }));
    const { createPrismaClient } = await import('@openkey/db');
    prisma = createPrismaClient();
    const { auth } = await import('../auth');
    app = (await import('../index')).default;
    await prisma.user.create({ data: { id: USER, email: 'su@example.test', name: 'SU', emailVerified: true } });
    const sessionToken = randomUUID();
    await prisma.session.create({ data: { id: 'su-session', token: sessionToken, userId: USER, expiresAt: new Date(Date.now() + 3_600_000) } });
    const context = await auth.$context;
    cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, sessionToken, context.secret)).split(';')[0]!;
    await prisma.user.create({ data: { id: 'su-user-b', email: 'sub@example.test', name: 'SUB', emailVerified: true } });
    const tokenB = randomUUID();
    await prisma.session.create({ data: { id: 'su-session-b', token: tokenB, userId: 'su-user-b', expiresAt: new Date(Date.now() + 3_600_000) } });
    cookieB = (await serializeSignedCookie(context.authCookies.sessionToken.name, tokenB, context.secret)).split(';')[0]!;
    const { createTeeClient, generatePrivateKey, getAddressFromPrivateKey, seal } = await import('@openkey/tee');
    const privateKey = generatePrivateKey(); address = getAddress(getAddressFromPrivateKey(privateKey));
    const sealingContext = randomUUID().replaceAll('-', '').padEnd(43, 'A').slice(0, 43);
    const sealingKey = await createTeeClient().deriveKey(`openkey/key/${sealingContext}`);
    await prisma.ethereumKey.create({ data: { id: 'su-key', userId: USER, address, publicKey: '0x1',
      sealedBlob: await seal(privateKey, sealingKey), sealingContext, keyType: 'MANAGED', isCanonicalTinyCloud: true } });
    const response = await app.fetch(new Request(`${API}/api/admin/oauth/clients`, { method: 'POST',
      headers: { Authorization: 'Bearer tc3569-admin-key', 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Step-up Home', type: 'native', redirectUris: [HOME_REDIRECT, STEPUP_REDIRECT], tinycloudNativeDelegation: ceiling }) }));
    expect(response.status, await response.clone().text()).toBe(201);
    clientId = (await response.json() as { client: { clientId: string } }).client.clientId;
  }, 120_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    await rm(directory, { recursive: true, force: true });
    delete process.env.OPENKEY_NATIVE_STEPUP_ENABLED;
  });

  beforeEach(async () => {
    process.env.OPENKEY_NATIVE_STEPUP_ENABLED = '1';
    await prisma.$executeRawUnsafe(`TRUNCATE TABLE "oauth_refresh_token", "oauth_access_token", "native_session_proof_jti", "oauth_consent", "tinycloud_manage_key_app_preference",
      "tinycloud_native_grant", "tinycloud_native_request", "tinycloud_native_consent_generation" CASCADE`);
    await prisma.user.update({ where: { id: USER }, data: { lockedAt: null, reviewerHoldAt: null, tinyCloudManageKeyMode: 'APP_MANAGED' } });
    await prisma.ethereumKey.update({ where: { id: 'su-key' }, data: { isCanonicalTinyCloud: true } });
    await prisma.$executeRawUnsafe('TRUNCATE TABLE "tinycloud_bootstrap_state"');
    await prisma.tinyCloudBootstrapState.create({ data: { userId: USER, keyId: 'su-key', address, chainId: 1, tinycloudHost: HOST,
      bootstrapVersion: 'test', status: 'complete', checkedAt: new Date(), completedAt: new Date() } });
    await prisma.oauthClient.update({ where: { clientId }, data: { disabled: false, scopes: ['openid', 'offline_access', DELEGATION], tinycloudNativeDelegation: ceiling } });
    await prisma.oauthConsent.create({ data: { id: 'su-consent', userId: USER, clientId, scopes: ['openid', 'offline_access', DELEGATION] } });
    await prisma.tinyCloudNativeConsentGeneration.create({ data: { userId: USER, clientId, generation: 0n } });
  });

  test('records a STEPUP request bound to the grant and changes nothing else', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const grantBefore = await prisma.tinyCloudNativeGrant.findUniqueOrThrow({ where: { id: 'g1' } });
    const consentBefore = await prisma.oauthConsent.findUniqueOrThrow({ where: { id: 'su-consent' } });
    const response = await stepUp(key, 'token-1');
    expect(response.status, await response.clone().text()).toBe(201);
    expect(response.headers.get('cache-control')).toBe('no-store');
    const created = await response.json() as { request_uri: string; expires_in: number };
    expect(created.expires_in).toBe(90);
    const id = created.request_uri.slice('urn:ietf:params:oauth:request_uri:'.length);
    const row = await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } });
    expect(row).toMatchObject({
      kind: 'STEPUP', grantId: 'g1', appId: EXPLORER, clientId, userId: USER, status: 'PENDING', redirectUri: STEPUP_REDIRECT,
      scopes: [DELEGATION], sessionDid: grantBefore.sessionDid, sessionJkt: grantBefore.sessionJkt, ttlSeconds: 3600, consentGeneration: 0n,
    });
    expect(row.sessionJwk).toEqual(grantBefore.sessionJwk as object);
    expect(row.requestedPermissions).toEqual(explorerEntries);
    // No rotation, no new grant, no step-up, consent untouched.
    expect(await prisma.tinyCloudNativeGrant.findUniqueOrThrow({ where: { id: 'g1' } })).toMatchObject({
      refreshTokenHash: grantBefore.refreshTokenHash, previousRefreshTokenHash: null, renewCount: 0, status: 'ACTIVE',
    });
    expect((await prisma.oauthRefreshToken.findUniqueOrThrow({ where: { token: hash('token-1') } })).revoked).toBeNull();
    expect(await prisma.oauthRefreshToken.count()).toBe(1);
    expect(await prisma.tinyCloudNativeGrant.count()).toBe(1);
    expect(await prisma.tinyCloudNativeStepUp.count()).toBe(0);
    expect(await prisma.oauthConsent.findUniqueOrThrow({ where: { id: 'su-consent' } })).toEqual(consentBefore);
    expect(await prisma.nativeSessionProofJti.count()).toBe(1);
  });

  test('is off unless the operator enables it', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    for (const value of [undefined, '', '0', 'false']) {
      if (value === undefined) delete process.env.OPENKEY_NATIVE_STEPUP_ENABLED; else process.env.OPENKEY_NATIVE_STEPUP_ENABLED = value;
      const response = await stepUp(key, 'token-1');
      expect(response.status).toBe(404);
      expect((await body(response)).error).toBe('not_found');
    }
    expect(await requests()).toBe(0);
    expect(await prisma.nativeSessionProofJti.count()).toBe(0);
  });

  test('the delegate key can only come from the grant', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const other = sessionKey();
    for (const extra of [{ session_key: JSON.stringify(other.publicJwk) }, { session_did: 'did:key:z6Mk' }, { authorization_details: '[]' }] as Array<Record<string, string>>) {
      const response = await stepUp(key, 'token-1', extra);
      expect(response.status).toBe(400);
      expect((await body(response)).error).toBe('invalid_request');
    }
    expect(await requests()).toBe(0);
  });

  test('credentials: unknown token, foreign key, wrong endpoint proof, replay and a rotated-out token are 401', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const foreign = sessionKey();
    const first = proof(key, 'token-1', STEPUP);
    for (const response of [
      await stepUp(key, 'unknown'),
      await stepUp(key, 'token-1', {}, proof(foreign, 'token-1', STEPUP)),
      await stepUp(key, 'token-1', {}, proof(key, 'token-1', RENEW)),
      await stepUp(key, 'token-1', {}, proof(key, 'other-token', STEPUP)),
      await stepUp(key, 'token-1', {}, 'not-a-proof'),
    ]) {
      expect(response.status).toBe(401);
      expect((await body(response)).error).toBe('invalid_session_proof');
    }
    expect((await stepUp(key, 'token-1', {}, first)).status).toBe(201);
    const replay = await stepUp(key, 'token-1', {}, first);
    expect(replay.status).toBe(401);
    expect(await requests()).toBe(1);
    // A token that is only the previous hash is not accepted.
    await prisma.tinyCloudNativeGrant.update({ where: { id: 'g1' }, data: { refreshTokenHash: hash('token-2'), previousRefreshTokenHash: hash('token-1') } });
    expect((await stepUp(key, 'token-1')).status).toBe(401);
  });

  test('a grant that is revoked, expired, withdrawn, locked or without a live token gets no request', async () => {
    const key = sessionKey();
    const cases: Array<[string, () => Promise<void>, number, string]> = [
      ['revoked grant', async () => { await prisma.tinyCloudNativeGrant.update({ where: { id: 'g1' }, data: { status: 'REVOKED', revokedAt: new Date() } }); }, 400, 'invalid_grant'],
      ['expired grant', async () => { await prisma.tinyCloudNativeGrant.update({ where: { id: 'g1' }, data: { absoluteExpiresAt: new Date(Date.now() + 200_000) } }); }, 400, 'consent_required'],
      ['past absolute expiry', async () => { await prisma.tinyCloudNativeGrant.update({ where: { id: 'g1' }, data: { absoluteExpiresAt: new Date(Date.now() - 1000) } }); }, 400, 'consent_required'],
      // Deleting the consent revokes the grant (the withdrawal trigger), so the grant is gone before any ceiling check.
      ['withdrawn consent', async () => {
        await prisma.oauthConsent.delete({ where: { id: 'su-consent' } });
        await prisma.oauthConsent.create({ data: { id: 'su-consent-new', userId: USER, clientId, scopes: ['openid', 'offline_access', DELEGATION] } });
      }, 400, 'invalid_grant'],
      ['locked account', async () => { await prisma.user.update({ where: { id: USER }, data: { lockedAt: new Date() } }); }, 400, 'access_denied'],
      ['expired token', async () => { await prisma.oauthRefreshToken.update({ where: { token: hash('token-1') }, data: { expiresAt: new Date(Date.now() - 1000) } }); }, 400, 'invalid_grant'],
      ['revoked token', async () => { await prisma.oauthRefreshToken.update({ where: { token: hash('token-1') }, data: { revoked: new Date() } }); }, 400, 'invalid_grant'],
      ['disabled client', async () => { await prisma.oauthClient.update({ where: { clientId }, data: { disabled: true } }); }, 400, 'consent_required'],
      ['key control exclusive to the user', async () => { await prisma.user.update({ where: { id: USER }, data: { tinyCloudManageKeyMode: 'USER_CONTROLLED_EXCLUSIVE' } }); }, 400, 'access_denied'],
      ['app switched off', async () => { await prisma.tinyCloudManageKeyAppPreference.create({ data: { userId: USER, clientId, enabled: false, status: 'DISABLED' } }); }, 400, 'access_denied'],
      ['canonical key changed', async () => { await prisma.ethereumKey.update({ where: { id: 'su-key' }, data: { isCanonicalTinyCloud: false } }); }, 400, 'consent_required'],
    ];
    for (const [label, arrange, status, code] of cases) {
      await beforeEachReset();
      await seedDevice('g1', key, 'token-1');
      await arrange();
      const response = await stepUp(key, 'token-1');
      expect([label, response.status, (await body(response)).error]).toEqual([label, status, code]);
      expect([label, await requests()]).toEqual([label, 0]);
    }
  });

  async function beforeEachReset() {
    await prisma.$executeRawUnsafe(`TRUNCATE TABLE "oauth_refresh_token", "native_session_proof_jti", "oauth_consent", "tinycloud_native_grant",
      "tinycloud_native_request", "tinycloud_native_consent_generation", "tinycloud_manage_key_app_preference" CASCADE`);
    await prisma.user.update({ where: { id: USER }, data: { lockedAt: null, reviewerHoldAt: null, tinyCloudManageKeyMode: 'APP_MANAGED' } });
    await prisma.ethereumKey.update({ where: { id: 'su-key' }, data: { isCanonicalTinyCloud: true } });
    await prisma.oauthClient.update({ where: { clientId }, data: { disabled: false } });
    await prisma.oauthConsent.create({ data: { id: 'su-consent', userId: USER, clientId, scopes: ['openid', 'offline_access', DELEGATION] } });
    await prisma.tinyCloudNativeConsentGeneration.create({ data: { userId: USER, clientId, generation: 0n } });
  }

  test('entries beyond the step-up ceiling, other apps and other spellings of an app id are refused', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const entry = (over: Record<string, unknown>) => ({ ...explorerEntries[0]!, ...over });
    const refused: Array<[string, Record<string, string>]> = [
      ['unknown app', { app_id: 'xyz.tinycloud.unknown' }],
      ['app id case', { app_id: 'xyz.tinycloud.Explorer' }],
      ['app id prefix', { app_id: 'xyz.tinycloud.explore' }],
      ['wider kv path', { permissions: JSON.stringify([entry({ path: 'x/' })]) }],
      ['space not in ceiling', { permissions: JSON.stringify([entry({ space: 'agents' })]) }],
      ['other app\'s entries', { permissions: JSON.stringify([{ service: 'tinycloud.kv', space: 'account', path: 'spaces/', actions: ['tinycloud.kv/get'] }]) }],
      ['sql database not named', { permissions: JSON.stringify([{ ...explorerEntries[1]!, path: 'other' }]) }],
      ['action not in this app\'s ceiling', { app_id: 'xyz.tinycloud.account', permissions: JSON.stringify([{ service: 'tinycloud.kv', space: 'account', path: 'spaces/', actions: ['tinycloud.kv/metadata'] }]) }],
    ];
    for (const [label, over] of refused) {
      const response = await stepUp(key, 'token-1', over);
      expect([label, response.status, (await body(response)).error]).toEqual([label, 400, 'access_denied']);
    }
    const malformed: Array<[string, Record<string, string>]> = [
      ['empty list', { permissions: '[]' }],
      ['not json', { permissions: 'x' }],
      ['dot segment', { permissions: JSON.stringify([entry({ path: '../x' })]) }],
      ['unknown space', { permissions: JSON.stringify([entry({ space: 'secrets' })]) }],
      ['unknown service', { permissions: JSON.stringify([entry({ service: 'tinycloud.hooks' })]) }],
      ['extra member', { permissions: JSON.stringify([entry({ extra: 1 })]) }],
      ['duplicate entries', { permissions: JSON.stringify([entry({}), entry({})]) }],
      ['kv write action', { permissions: JSON.stringify([entry({ actions: ['tinycloud.kv/put'] })]) }],
      ['kv delete action', { permissions: JSON.stringify([entry({ actions: ['tinycloud.kv/del'] })]) }],
      ['sql write action', { permissions: JSON.stringify([{ ...explorerEntries[1]!, actions: ['tinycloud.sql/write'] }]) }],
    ];
    for (const [label, over] of malformed) {
      const response = await stepUp(key, 'token-1', over);
      expect([label, response.status, (await body(response)).error]).toEqual([label, 400, 'invalid_authorization_details']);
    }
    expect(await requests()).toBe(0);
  });

  test('a ceiling without stepUps, or removed since sign-in, refuses', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const { stepUps: _removed, ...withoutStepUps } = ceiling;
    await prisma.oauthClient.update({ where: { clientId }, data: { tinycloudNativeDelegation: withoutStepUps } });
    const response = await stepUp(key, 'token-1');
    expect([response.status, (await body(response)).error]).toEqual([400, 'access_denied']);
    expect(await requests()).toBe(0);
  });

  test('redirect URI must be registered; the PKCE fields are validated; open requests are capped', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    for (const over of [
      { redirect_uri: 'xyz.tinycloud.exo://openkey/other' }, { code_challenge_method: 'plain' }, { code_challenge: 'short' }, { state: 'short' },
    ] as Array<Record<string, string>>) {
      const response = await stepUp(key, 'token-1', over);
      expect([JSON.stringify(over), response.status, (await body(response)).error]).toEqual([JSON.stringify(over), 400, 'invalid_request']);
    }
    for (let index = 0; index < 8; index++) expect((await stepUp(key, 'token-1')).status).toBe(201);
    const capped = await stepUp(key, 'token-1');
    expect(capped.status).toBe(429);
    expect(capped.headers.get('retry-after')).toBe('10');
    expect(await requests()).toBe(8);
  });

  test('only live requests count toward the cap, and parallel requests cannot pass it', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    for (let index = 0; index < 8; index++) expect((await stepUp(key, 'token-1')).status).toBe(201);
    expect((await stepUp(key, 'token-1')).status).toBe(429);
    // Request URIs that were never opened expire; their slots are free again.
    await prisma.tinyCloudNativeRequest.updateMany({ where: { grantId: 'g1' }, data: { requestUriExpiresAt: new Date(Date.now() - 1000) } });
    expect((await stepUp(key, 'token-1')).status).toBe(201);
    // An opened (RESOLVED) request counts until it expires, then it does not.
    await prisma.tinyCloudNativeRequest.updateMany({ where: { grantId: 'g1', status: 'PENDING' }, data: { status: 'RESOLVED', expiresAt: new Date(Date.now() - 1000) } });
    for (let index = 0; index < 8; index++) expect((await stepUp(key, 'token-1')).status).toBe(201);
    expect((await stepUp(key, 'token-1')).status).toBe(429);
    await prisma.tinyCloudNativeRequest.deleteMany({});
    const statuses = (await Promise.all(Array.from({ length: 12 }, () => stepUp(key, 'token-1')))).map((response) => response.status);
    expect(statuses.filter((status) => status === 201).length).toBeLessThanOrEqual(8);
    expect(statuses.every((status) => status === 201 || status === 429)).toBe(true);
    expect(await prisma.tinyCloudNativeRequest.count({ where: { status: 'PENDING' } })).toBeLessThanOrEqual(8);
  });

  test('a request never outlives the moment its grant can no longer be used', async () => {
    const key = sessionKey();
    const expiresAt = new Date(Date.now() + 400_000);
    await seedDevice('g1', key, 'token-1', { expiresAt });
    const created = await (await stepUp(key, 'token-1')).json() as { request_uri: string };
    const row = await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id: created.request_uri.slice('urn:ietf:params:oauth:request_uri:'.length) } });
    expect(row.expiresAt.getTime()).toBeLessThanOrEqual(expiresAt.getTime() - 300_000);
    expect(row.requestUriExpiresAt.getTime()).toBeLessThanOrEqual(row.expiresAt.getTime());
  });

  // ---- PR 2b: consent prepare / approve for a STEPUP request ----
  const CONSENT = `${API}/api/oauth/tinycloud/requests`;
  const spaceId = (name: string) => `tinycloud:pkh:eip155:1:${address}:${name}`;
  interface Preview { requestId: string; revision: number; digest: string; sessionSiwe: string; kind: string; reactivation: boolean;
    spaces: Array<{ space: string; spaceId: string }>; stepUp: { grantId: string; appId: string }; error?: string; error_description?: string }
  interface Approval { status: string; hosting: string; spaces: string[]; error?: string; error_description?: string }

  async function consent(id: string, action: 'prepare' | 'approve', payload: Record<string, unknown> = {}, as = cookie) {
    return app.fetch(new Request(`${CONSENT}/${id}/${action}`, { method: 'POST',
      headers: { cookie: as, origin: 'https://openkey.test', 'content-type': 'application/json' }, body: JSON.stringify(payload) }));
  }
  // The request the way the app sees it after /authorize: RESOLVED, waiting for the user.
  async function newRequest(key: SessionKey) {
    const created = await (await stepUp(key, 'token-1')).json() as { request_uri: string };
    // The provider's /authorize resolves the request URI with this function; the request becomes RESOLVED.
    const { resolveRequestUri, REQUEST_URI_PREFIX } = await import('../services/native-delegation/par');
    const query = await resolveRequestUri(prisma, created.request_uri, clientId);
    const id = created.request_uri.slice(REQUEST_URI_PREFIX.length);
    expect(query).toMatchObject({ client_id: clientId, redirect_uri: STEPUP_REDIRECT, tinycloud_request: id });
    return id;
  }
  async function prepared(id: string) {
    const response = await consent(id, 'prepare');
    return { response, preview: await response.json() as Preview };
  }
  const approval = (preview: Preview) => ({ revision: preview.revision, digest: preview.digest, sessionSiwe: preview.sessionSiwe });
  const allHosted = () => new Response(JSON.stringify({ activated: [spaceId('public'), spaceId('applications')], skipped: [] }), { status: 200 });

  // The node: /delegate answers `delegate`, /revoke is counted, anything else is a test failure.
  async function withNode<T>(delegate: () => Response, run: () => Promise<T>, revokeStatus = 200) {
    const original = globalThis.fetch;
    const calls = { delegate: 0, revoke: 0 };
    globalThis.fetch = (async (input: Request | URL | string) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      if (url === `${HOST}/delegate`) { calls.delegate++; return delegate(); }
      if (url === `${HOST}/revoke`) { calls.revoke++; return new Response('{}', { status: revokeStatus }); }
      throw new Error(`unexpected fetch ${url}`);
    }) as typeof fetch;
    try { return { value: await run(), calls }; } finally { globalThis.fetch = original; }
  }
  async function snapshot() {
    return JSON.stringify([
      await prisma.tinyCloudNativeGrant.findMany({ orderBy: { id: 'asc' } }), await prisma.oauthRefreshToken.findMany({ orderBy: { id: 'asc' } }),
      await prisma.oauthAccessToken.count(), await prisma.oauthConsent.findMany({ orderBy: { id: 'asc' } }),
      await prisma.tinyCloudNativeConsentGeneration.findMany(), await prisma.tinyCloudNativeStepUp.findMany(),
    ], (_key, value) => typeof value === 'bigint' ? value.toString() : value);
  }

  test('prepare builds one multi-space SIWE to the grant\'s own session key and signs nothing', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const id = await newRequest(key);
    const { response, preview } = await prepared(id);
    expect(response.status).toBe(200);
    expect(preview).toMatchObject({ kind: 'STEPUP', reactivation: false, stepUp: { grantId: 'g1', appId: EXPLORER } });
    expect(preview.spaces).toEqual([{ space: 'public', spaceId: spaceId('public') }, { space: 'applications', spaceId: spaceId('applications') }]);
    const grant = await prisma.tinyCloudNativeGrant.findUniqueOrThrow({ where: { id: 'g1' } });
    const siwe = new SiweMessage(preview.sessionSiwe);
    expect(siwe.address).toBe(address);
    expect(preview.sessionSiwe).toContain(grant.sessionDid.split('#')[0]!);
    const row = await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } });
    expect(row).toMatchObject({ status: 'RESOLVED', signature: null, delegation: null, approvedRevision: null });
    expect(await prisma.tinyCloudNativePreparation.count()).toBe(1);
  });

  test('approve signs for the grant\'s key and creates no grant, token, step-up or consent change', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const id = await newRequest(key);
    const { preview } = await prepared(id);
    const before = await snapshot();
    const { value, calls } = await withNode(allHosted, async () => {
      const first = await consent(id, 'approve', approval(preview));
      const replay = await consent(id, 'approve', approval(preview));
      return { first, firstBody: await first.json() as Approval, replay, replayBody: await replay.json() as Approval };
    });
    expect(value.first.status).toBe(200);
    expect(value.firstBody).toMatchObject({ status: 'APPROVED', hosting: 'existing', spaces: ['public', 'applications'] });
    expect(value.replay.status).toBe(200);
    expect(value.replayBody).toMatchObject({ status: 'APPROVED', hosting: 'existing' });
    expect(calls).toEqual({ delegate: 1, revoke: 0 });
    const row = await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } });
    expect(row.status).toBe('APPROVED');
    // The signed text is the one rebuilt at approve (same content as the preview, its own issued-at).
    const signed = (row.delegation as { siwe: string }).siwe;
    expect(await recoverMessageAddress({ message: signed, signature: row.signature as `0x${string}` })).toBe(address);
    expect(row.delegation).toMatchObject({ grantId: 'g1', appId: EXPLORER, sessionDid: row.sessionDid });
    expect(await snapshot()).toBe(before);
  });

  // TC-3596: a passkey sign-in made for the step-up request covers its Approve; no other session and no other request.
  test('a passkey sign-in made for a step-up request covers its Approve and records the method; another session is still asked', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    await prisma.user.update({ where: { id: USER }, data: { passkeyApprovalMode: 'ALWAYS' } });
    const passkey = await createSoftPasskey(prisma, USER, true, 'https://openkey.test');
    try {
      const created = await (await stepUp(key, 'token-1')).json() as { request_uri: string };
      const { resolveRequestUri, REQUEST_URI_PREFIX } = await import('../services/native-delegation/par');
      const id = created.request_uri.slice(REQUEST_URI_PREFIX.length);
      // The passkey sign-in the login page makes while the request is still pending.
      const asked = await app.fetch(new Request(`${API}/api/auth/passkey/generate-authenticate-options`, { headers: { origin: 'https://openkey.test' } }));
      const cookies = (response: Response) => response.headers.getSetCookie().map((value) => value.split(';')[0]).join('; ');
      const verified = await app.fetch(new Request(`${API}/api/auth/passkey/verify-authentication`, { method: 'POST',
        headers: { origin: 'https://openkey.test', 'content-type': 'application/json', cookie: cookies(asked), 'x-openkey-passkey-flow': id },
        body: JSON.stringify({ response: passkey.assert(await asked.json() as PublicKeyCredentialRequestOptionsJSON) }) }));
      expect(verified.status, await verified.clone().text()).toBe(200);
      const signedIn = cookies(verified);
      await resolveRequestUri(prisma, created.request_uri, clientId);

      // Another session of the same account is asked, for this very request.
      const other = await (await consent(id, 'prepare', {}, cookie)).json() as Preview & { passkey: { required: boolean } };
      expect(other.passkey.required).toBe(true);
      const refused = await consent(id, 'approve', approval(other), cookie);
      expect(refused.status).toBe(403);
      expect(await refused.json()).toMatchObject({ code: 'passkey_approval_required' });

      // The session that signed in for it is not, on prepare or on a re-prepare, and Approve needs no assertion.
      const first = await consent(id, 'prepare', {}, signedIn);
      expect((await first.json() as { passkey: unknown }).passkey).toEqual({ required: false });
      const preview = await (await consent(id, 'prepare', {}, signedIn)).json() as Preview & { passkey: unknown };
      expect(preview.passkey).toEqual({ required: false });
      const { value, calls } = await withNode(allHosted, async () => {
        const approved = await consent(id, 'approve', approval(preview), signedIn);
        return { approved, body: await approved.json() as Approval };
      });
      expect(value.approved.status, JSON.stringify(value.body)).toBe(200);
      expect(value.body).toMatchObject({ status: 'APPROVED', spaces: ['public', 'applications'] });
      expect(calls).toEqual({ delegate: 1, revoke: 0 });
      expect((await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } })).approvalPasskeyMethod).toBe('FLOW_PASSKEY');
      expect(await prisma.verification.count({ where: { identifier: { startsWith: 'openkey-flow-passkey:' } } })).toBe(0);
    } finally {
      await prisma.user.update({ where: { id: USER }, data: { passkeyApprovalMode: 'SENSITIVE' } });
      await prisma.passkey.deleteMany({ where: { userId: USER } });
    }
  });

  test('the delegation never outlives a nearly-ended grant', async () => {
    const key = sessionKey();
    const expiresAt = new Date(Date.now() + 400_000);
    await seedDevice('g1', key, 'token-1', { expiresAt });
    const id = await newRequest(key);
    const { preview } = await prepared(id);
    expect(Date.parse(/Expiration Time: ([^\n]+)/.exec(preview.sessionSiwe)![1]!)).toBeLessThanOrEqual(expiresAt.getTime());
    const { value } = await withNode(allHosted, () => consent(id, 'approve', approval(preview)));
    expect(value.status).toBe(200);
    const row = await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } });
    expect(Date.parse((row.delegation as { expiresAt: string }).expiresAt)).toBeLessThanOrEqual(expiresAt.getTime());
  });

  test('a space the node did not activate refuses the whole step-up, withdraws the approval and revokes the delegation', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const id = await newRequest(key);
    const { preview } = await prepared(id);
    const { value, calls } = await withNode(
      () => new Response(JSON.stringify({ activated: [spaceId('applications')], skipped: [spaceId('public')] }), { status: 200 }),
      async () => { const response = await consent(id, 'approve', approval(preview)); return { response, text: await response.text() }; });
    const payload = JSON.parse(value.text) as Approval;
    expect(value.response.status).toBe(409);
    expect(payload.error).toBe('space_not_hosted');
    expect(payload.error_description).toBe('Spaces not hosted on this node: public');
    // No signature, delegation, CID or header reaches the client.
    expect(Object.keys(payload).sort()).toEqual(['error', 'error_description']);
    expect(calls).toEqual({ delegate: 1, revoke: 1 });
    expect(await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } })).toMatchObject({ status: 'DENIED', signature: null, delegation: null });
  });

  test('when the node also fails to revoke, nothing reaches the client and the request keeps only the CID for a retry', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const id = await newRequest(key);
    const { preview } = await prepared(id);
    const { value, calls } = await withNode(
      () => new Response(JSON.stringify({ activated: [spaceId('applications')], skipped: [spaceId('public')] }), { status: 200 }),
      async () => { const response = await consent(id, 'approve', approval(preview)); return { response, text: await response.text() }; }, 500);
    expect(value.response.status).toBe(409);
    expect(Object.keys(JSON.parse(value.text) as object).sort()).toEqual(['error', 'error_description']);
    expect(calls.revoke).toBe(1);
    const row = await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } });
    expect(row).toMatchObject({ status: 'DENIED', signature: null });
    expect(row.delegation).toEqual({ revokePending: true, delegationCid: expect.any(String), tinycloudHost: HOST, address, grantId: 'g1', appId: EXPLORER, expiresAt: expect.any(String), siweDomain: 'openkey.so' });
  });

  test('another account can neither prepare nor approve this account\'s request', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const id = await newRequest(key);
    const { preview } = await prepared(id);
    const prepare = await consent(id, 'prepare', {}, cookieB);
    expect(prepare.status).toBeGreaterThanOrEqual(400);
    const { value, calls } = await withNode(allHosted, () => consent(id, 'approve', approval(preview), cookieB));
    expect(value.status).toBeGreaterThanOrEqual(400);
    expect(calls.delegate).toBe(0);
    expect(await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } })).toMatchObject({ status: 'RESOLVED', signature: null, delegation: null, userId: USER });
    expect(await prisma.tinyCloudNativePreparation.count()).toBe(1);
  });

  test('a node failure at activation is a 503, withdraws the approval and revokes the delegation', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const id = await newRequest(key);
    const { preview } = await prepared(id);
    const { value, calls } = await withNode(() => new Response('{}', { status: 500 }), async () => {
      const response = await consent(id, 'approve', approval(preview)); return { response, payload: await response.json() as Approval }; });
    expect([value.response.status, value.payload.error]).toEqual([503, 'temporarily_unavailable']);
    expect(calls.revoke).toBe(1);
    expect(await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } })).toMatchObject({ status: 'DENIED', signature: null, delegation: null });
  });

  test('without a completed bootstrap the spaces are not hosted: prepare refuses and stores nothing', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const id = await newRequest(key);
    await prisma.$executeRawUnsafe('TRUNCATE TABLE "tinycloud_bootstrap_state"');
    const { response, preview } = await prepared(id);
    expect([response.status, preview.error, preview.error_description]).toEqual([409, 'space_not_hosted', 'Spaces not hosted on this node: public, applications']);
    expect(await prisma.tinyCloudNativePreparation.count()).toBe(0);
  });

  test('every gate is re-checked at approve: nothing is signed, the node is not called, the request stays pending', async () => {
    const cases: Array<[string, () => Promise<unknown>, number, string]> = [
      ['grant revoked', () => prisma.tinyCloudNativeGrant.update({ where: { id: 'g1' }, data: { status: 'REVOKED', revokedAt: new Date(), revokedReason: 'test' } }), 409, 'preparation_superseded'],
      ['grant near its end', () => prisma.tinyCloudNativeGrant.update({ where: { id: 'g1' }, data: { absoluteExpiresAt: new Date(Date.now() + 100_000) } }), 409, 'preparation_superseded'],
      ['refresh token revoked', () => prisma.oauthRefreshToken.update({ where: { token: hash('token-1') }, data: { revoked: new Date() } }), 409, 'preparation_superseded'],
      ['stepUps removed from the ceiling', () => prisma.oauthClient.update({ where: { clientId }, data: { tinycloudNativeDelegation: { ...ceiling, stepUps: undefined } } }), 409, 'preparation_superseded'],
      ['ceiling narrowed', () => prisma.oauthClient.update({ where: { clientId }, data: { tinycloudNativeDelegation: { ...ceiling, stepUps: { [EXPLORER]: { public: ceiling.stepUps[EXPLORER].public } } } } }), 409, 'preparation_superseded'],
      ['client disabled', () => prisma.oauthClient.update({ where: { clientId }, data: { disabled: true } }), 409, 'preparation_superseded'],
      ['canonical key changed', () => prisma.ethereumKey.update({ where: { id: 'su-key' }, data: { isCanonicalTinyCloud: false } }), 409, 'preparation_mismatch'],
      ['account locked', () => prisma.user.update({ where: { id: USER }, data: { lockedAt: new Date() } }), 401, 'unauthorized'],
      ['reviewer hold', () => prisma.user.update({ where: { id: USER }, data: { reviewerHoldAt: new Date() } }), 401, 'unauthorized'],
      ['key control exclusive to the user', () => prisma.user.update({ where: { id: USER }, data: { tinyCloudManageKeyMode: 'USER_CONTROLLED_EXCLUSIVE' } }), 403, 'access_denied'],
      ['app switched off', () => prisma.tinyCloudManageKeyAppPreference.create({ data: { userId: USER, clientId, enabled: false, status: 'DISABLED' } }), 403, 'access_denied'],
      ['consent generation moved', () => prisma.tinyCloudNativeConsentGeneration.update({ where: { userId_clientId: { userId: USER, clientId } }, data: { generation: 1n } }), 409, 'preparation_superseded'],
      ['bootstrap gone', () => prisma.$executeRawUnsafe('TRUNCATE TABLE "tinycloud_bootstrap_state"'), 409, 'space_not_hosted'],
    ];
    for (const [label, arrange, status, code] of cases) {
      await beforeEachReset();
      await prisma.$executeRawUnsafe('TRUNCATE TABLE "tinycloud_bootstrap_state"');
      await prisma.tinyCloudBootstrapState.create({ data: { userId: USER, keyId: 'su-key', address, chainId: 1, tinycloudHost: HOST,
        bootstrapVersion: 'test', status: 'complete', checkedAt: new Date(), completedAt: new Date() } });
      await prisma.oauthClient.update({ where: { clientId }, data: { tinycloudNativeDelegation: ceiling } });
      const key = sessionKey(); await seedDevice('g1', key, 'token-1');
      const id = await newRequest(key);
      const { preview } = await prepared(id);
      await arrange();
      const { value, calls } = await withNode(allHosted, async () => {
        const response = await consent(id, 'approve', approval(preview)); return { response, payload: await response.json() as Approval }; });
      expect([label, value.response.status, value.payload.error]).toEqual([label, status, code]);
      expect([label, calls]).toEqual([label, { delegate: 0, revoke: 0 }]);
      expect([label, await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } })]).toEqual([label, expect.objectContaining({ status: 'RESOLVED', signature: null, delegation: null })]);
      expect(await prisma.tinyCloudNativeStepUp.count()).toBe(0);
    }
  });

  test('a stale, tampered or foreign preview is not signed', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const id = await newRequest(key);
    const first = (await prepared(id)).preview;
    const second = (await prepared(id)).preview;
    expect(second.revision).toBe(first.revision + 1);
    for (const [label, payload] of [
      ['old revision', approval(first)],
      ['wrong digest', { ...approval(second), digest: 'x'.repeat(second.digest.length) }],
      ['edited SIWE', { ...approval(second), sessionSiwe: second.sessionSiwe.replace('public', 'account') }],
      ['no body', {}],
    ] as const) {
      const { value, calls } = await withNode(allHosted, async () => (await consent(id, 'approve', payload)).status);
      expect([label, value >= 400 && value < 500, calls.delegate]).toEqual([label, true, 0]);
    }
    expect(await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } })).toMatchObject({ status: 'RESOLVED', signature: null, delegation: null });
  });

  test('a step-up revoked by the app is shown as a re-activation and consent leaves the row alone', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const revokedAt = new Date(Date.now() - 60_000);
    await prisma.tinyCloudNativeStepUp.create({ data: { id: 'su-1', grantId: 'g1', appId: EXPLORER, approvedPermissions: explorerEntries,
      status: 'REVOKED', revokedAt, revokedReason: 'app_revoked' } });
    const id = await newRequest(key);
    const { preview } = await prepared(id);
    expect(preview.reactivation).toBe(true);
    const { value } = await withNode(allHosted, () => consent(id, 'approve', approval(preview)));
    expect(value.status).toBe(200);
    expect(await prisma.tinyCloudNativeStepUp.findUniqueOrThrow({ where: { id: 'su-1' } })).toMatchObject({ status: 'REVOKED', revokedReason: 'app_revoked', revokedAt, grantId: 'g1' });
  });

  // ---- PR 2c: the code exchange of an approved STEPUP request ----
  async function approvedCode(key: SessionKey, token = 'token-1') {
    const created = await (await stepUp(key, token)).json() as { request_uri: string };
    const authorize = await app.fetch(new Request(`${API}/api/auth/oauth2/authorize?${new URLSearchParams({ client_id: clientId, request_uri: created.request_uri })}`, { headers: { cookie } }));
    expect(authorize.status, await authorize.clone().text()).toBe(302);
    const consentUrl = new URL(authorize.headers.get('location')!);
    expect(consentUrl.pathname).toBe('/oauth/consent');
    const id = created.request_uri.slice('urn:ietf:params:oauth:request_uri:'.length);
    const { preview } = await prepared(id);
    const { value: approved } = await withNode(allHosted, () => consent(id, 'approve', approval(preview)));
    expect(approved.status, await approved.clone().text()).toBe(200);
    const accepted = await app.fetch(new Request(`${API}/api/auth/oauth2/consent`, { method: 'POST',
      headers: { cookie, origin: 'https://openkey.test', 'content-type': 'application/json' }, body: JSON.stringify({ accept: true, oauth_query: consentUrl.searchParams.toString() }) }));
    expect(accepted.status, await accepted.clone().text()).toBe(200);
    const code = new URL((await accepted.json() as { url: string }).url).searchParams.get('code')!;
    expect(code).toBeTruthy();
    return { id, code, preview };
  }
  function redeem(key: SessionKey, code: string, overrides: Record<string, string> = {}, sessionProof?: string) {
    return post('/api/auth/oauth2/token', new URLSearchParams({
      grant_type: 'authorization_code', code, client_id: clientId, redirect_uri: STEPUP_REDIRECT, code_verifier: VERIFIER, ...overrides,
    }), sessionProof ?? proof(key, code, '/api/auth/oauth2/token'));
  }

  // What the Home sign-in owns. A step-up exchange must leave all of it exactly as it was.
  async function homeState() {
    return JSON.stringify([
      await prisma.tinyCloudNativeGrant.findMany({ orderBy: { id: 'asc' } }), await prisma.oauthRefreshToken.findMany({ orderBy: { id: 'asc' } }),
      await prisma.oauthConsent.findMany({ orderBy: { id: 'asc' } }), await prisma.tinyCloudNativeConsentGeneration.findMany(),
    ], (_key, value) => typeof value === 'bigint' ? value.toString() : value);
  }
  async function fresh() {
    await beforeEachReset();
    await prisma.$executeRawUnsafe('TRUNCATE TABLE "oauth_access_token", "verification", "tinycloud_bootstrap_state"');
    await prisma.tinyCloudBootstrapState.create({ data: { userId: USER, keyId: 'su-key', address, chainId: 1, tinycloudHost: HOST,
      bootstrapVersion: 'test', status: 'complete', checkedAt: new Date(), completedAt: new Date() } });
    await prisma.oauthClient.update({ where: { clientId }, data: { disabled: false, tinycloudNativeDelegation: ceiling } });
  }

  test('the exchange returns the signed step-up; it adds no grant, refresh token or consent change', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const home = await homeState();
    const flow = await approvedCode(key);
    const response = await redeem(key, flow.code);
    const payload = await response.json() as { access_token: string; expires_in: number; scope: string; refresh_token?: string; id_token?: string; tinycloud_delegation?: unknown;
      tinycloud_stepup: { grantId: string; appId: string; siwe: string; signature: string; spaces: Array<{ space: string }>; expiresAt: string; renewableUntil: string; hosting: string; permissions: unknown } };
    expect(response.status, JSON.stringify(payload)).toBe(200);
    expect(payload).toMatchObject({ scope: DELEGATION, expires_in: 300, tinycloud_stepup: { grantId: 'g1', appId: EXPLORER, hosting: 'existing', permissions: explorerEntries } });
    expect(payload.tinycloud_stepup.spaces.map((space) => space.space)).toEqual(['public', 'applications']);
    expect([payload.refresh_token, payload.id_token, payload.tinycloud_delegation]).toEqual([undefined, undefined, undefined]);
    expect(await recoverMessageAddress({ message: payload.tinycloud_stepup.siwe, signature: payload.tinycloud_stepup.signature as `0x${string}` })).toBe(address);
    const grant = await prisma.tinyCloudNativeGrant.findUniqueOrThrow({ where: { id: 'g1' } });
    expect(Date.parse(payload.tinycloud_stepup.expiresAt)).toBeLessThanOrEqual(grant.absoluteExpiresAt.getTime());
    expect(Date.parse(payload.tinycloud_stepup.renewableUntil)).toBe(grant.absoluteExpiresAt.getTime() - 300_000);
    // Home is exactly as before: same grant, same single refresh token, same consent (scopes included), same generation.
    expect(await homeState()).toBe(home);
    expect(await prisma.tinyCloudNativeStepUp.findMany()).toEqual([expect.objectContaining({ grantId: 'g1', appId: EXPLORER, status: 'ACTIVE', approvedPermissions: explorerEntries, revokedAt: null })]);
    expect((await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id: flow.id } })).status).toBe('REDEEMED');
    // The one access token holds only the delegation scope, lives 300 s and hangs off no refresh token.
    const tokens = await prisma.oauthAccessToken.findMany();
    expect(tokens).toHaveLength(1);
    expect(tokens[0]).toMatchObject({ scopes: [DELEGATION], refreshId: null, clientId, userId: USER });
    expect(tokens[0]!.expiresAt.getTime() - tokens[0]!.createdAt.getTime()).toBeLessThanOrEqual(300_000);
  });

  test('the step-up access token opens nothing: not the signer, not userinfo, not the step-up, renew or revoke endpoints', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const flow = await approvedCode(key);
    const payload = await (await redeem(key, flow.code)).json() as { access_token: string };
    const home = await homeState();
    const bearer = { Authorization: `Bearer ${payload.access_token}`, 'content-type': 'application/json', origin: 'https://openkey.test' };
    const outcomes: Array<[string, number]> = [];
    for (const [path, method] of [['/api/delegate/sign', 'POST'], ['/api/auth/oauth2/userinfo', 'GET'], ['/api/auth/oauth2/tinycloud/stepup', 'POST'],
      ['/api/auth/oauth2/tinycloud/renew', 'POST'], ['/api/auth/oauth2/tinycloud/revoke', 'POST'], ['/api/account/connected-apps', 'GET']] as const) {
      const response = await app.fetch(new Request(`${API}${path}`, { method, headers: bearer, body: method === 'POST' ? '{}' : undefined }));
      outcomes.push([path, response.status >= 400 && response.status < 500 ? 4 : response.status]);
    }
    expect(outcomes).toEqual([['/api/delegate/sign', 4], ['/api/auth/oauth2/userinfo', 4], ['/api/auth/oauth2/tinycloud/stepup', 4],
      ['/api/auth/oauth2/tinycloud/renew', 4], ['/api/auth/oauth2/tinycloud/revoke', 4], ['/api/account/connected-apps', 4]]);
    expect(await homeState()).toBe(home);
  });

  test('a code redeems once; a wrong proof spends the code and nothing else', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const stranger = sessionKey();
    for (const [label, bad] of [
      ['proof from another key', (code: string) => proof(stranger, code, '/api/auth/oauth2/token', { signer: stranger.privateKey })],
      ['proof for another credential', (code: string) => proof(key, 'other-code', '/api/auth/oauth2/token')],
      ['proof for another client', (code: string) => proof(key, code, '/api/auth/oauth2/token').replace(/^[^.]+\.[^.]+/, () => `${b64({ typ: 'openkey-session-proof+jwt', alg: 'EdDSA', kid: stranger.jkt })}.${b64({ jti: 'x' })}`)],
    ] as const) {
      const flow = await approvedCode(key);
      const response = await redeem(key, flow.code, {}, bad(flow.code));
      expect([label, response.status, (await body(response)).error]).toEqual([label, 401, 'invalid_session_proof']);
      // The provider spent the code before the proof was checked: the right proof no longer redeems it.
      expect([label, (await redeem(key, flow.code)).status >= 400]).toEqual([label, true]);
      expect([label, await prisma.tinyCloudNativeStepUp.count(), await prisma.oauthAccessToken.count()]).toEqual([label, 0, 0]);
      await prisma.tinyCloudNativeRequest.deleteMany({});
    }
    const flow = await approvedCode(key);
    expect((await redeem(key, flow.code)).status).toBe(200);
    expect((await redeem(key, flow.code)).status).toBeGreaterThanOrEqual(400);
    expect(await prisma.tinyCloudNativeStepUp.count()).toBe(1);
    expect(await prisma.oauthAccessToken.count()).toBe(1);
  });

  test('every gate is re-checked at exchange: the code is spent, no step-up row, no token', async () => {
    const cases: Array<[string, (requestId: string) => Promise<unknown>]> = [
      ['grant revoked', () => prisma.tinyCloudNativeGrant.update({ where: { id: 'g1' }, data: { status: 'REVOKED', revokedAt: new Date(), revokedReason: 'test' } })],
      ['grant near its end', () => prisma.tinyCloudNativeGrant.update({ where: { id: 'g1' }, data: { absoluteExpiresAt: new Date(Date.now() + 100_000) } })],
      ['refresh token revoked', () => prisma.oauthRefreshToken.update({ where: { token: hash('token-1') }, data: { revoked: new Date() } })],
      ['stepUps removed from the ceiling', () => prisma.oauthClient.update({ where: { clientId }, data: { tinycloudNativeDelegation: { ...ceiling, stepUps: undefined } } })],
      ['ceiling narrowed', () => prisma.oauthClient.update({ where: { clientId }, data: { tinycloudNativeDelegation: { ...ceiling, stepUps: { [EXPLORER]: { public: ceiling.stepUps[EXPLORER].public } } } } })],
      ['canonical key changed', () => prisma.ethereumKey.update({ where: { id: 'su-key' }, data: { isCanonicalTinyCloud: false } })],
      ['key control exclusive to the user', () => prisma.user.update({ where: { id: USER }, data: { tinyCloudManageKeyMode: 'USER_CONTROLLED_EXCLUSIVE' } })],
      ['app switched off', () => prisma.tinyCloudManageKeyAppPreference.create({ data: { userId: USER, clientId, enabled: false, status: 'DISABLED' } })],
      ['consent withdrawn', () => prisma.oauthConsent.deleteMany({ where: { userId: USER, clientId } })],
      ['hosting did not finish', (requestId) => prisma.tinyCloudNativeRequest.update({ where: { id: requestId }, data: { hosting: 'failed' } })],
      ['client disabled', () => prisma.oauthClient.update({ where: { clientId }, data: { disabled: true } })],
      ['delegation is a revoke record, not an approval', (requestId) => prisma.tinyCloudNativeRequest.update({ where: { id: requestId },
        data: { delegation: { revokePending: true, delegationCid: 'bafy-test', grantId: 'g1', appId: EXPLORER } } })],
      ['approved delegation would outlive the grant', async (requestId) => {
        const row = await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id: requestId } });
        await prisma.tinyCloudNativeRequest.update({ where: { id: requestId }, data: { delegation: { ...(row.delegation as object), expiresAt: new Date(Date.now() + 90 * 86400_000).toISOString() } } });
      }],
    ];
    for (const [label, arrange] of cases) {
      await fresh();
      const key = sessionKey(); await seedDevice('g1', key, 'token-1');
      const flow = await approvedCode(key);
      await arrange(flow.id);
      const response = await redeem(key, flow.code);
      expect([label, response.status >= 400 && response.status < 600]).toEqual([label, true]);
      expect([label, await prisma.tinyCloudNativeStepUp.count(), await prisma.oauthAccessToken.count()]).toEqual([label, 0, 0]);
      // Withdrawing the consent also withdraws every request (the consent trigger); the others stay approved and unredeemed.
      const expected = label === 'consent withdrawn' ? 'WITHDRAWN' : 'APPROVED';
      expect([label, (await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id: flow.id } })).status]).toEqual([label, expected]);
    }
  });

  test('a code for a STEPUP request can never mint a grant or a sign-in: a forged sign-in scope is refused', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const flow = await approvedCode(key);
    const home = await homeState();
    const row = await prisma.verification.findFirstOrThrow({ where: { identifier: hash(flow.code) } });
    const value = JSON.parse(row.value) as { query: Record<string, unknown> };
    value.query.scope = `openid offline_access ${DELEGATION}`;
    await prisma.verification.update({ where: { id: row.id }, data: { value: JSON.stringify(value) } });
    const response = await redeem(key, flow.code);
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(await homeState()).toBe(home);
    expect(await prisma.oauthRefreshToken.count()).toBe(1);
    expect(await prisma.tinyCloudNativeStepUp.count()).toBe(0);
  });

  test('an app-revoked step-up comes back through this full consent; a row a grant revoke took down never does', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    await prisma.tinyCloudNativeStepUp.create({ data: { id: 'su-1', grantId: 'g1', appId: EXPLORER, approvedPermissions: explorerEntries.slice(0, 1),
      status: 'REVOKED', revokedAt: new Date(Date.now() - 60_000), revokedReason: 'app_revoked' } });
    const flow = await approvedCode(key);
    expect((await redeem(key, flow.code)).status).toBe(200);
    expect(await prisma.tinyCloudNativeStepUp.findMany()).toEqual([expect.objectContaining({ id: 'su-1', grantId: 'g1', status: 'ACTIVE', revokedAt: null, revokedReason: null, approvedPermissions: explorerEntries })]);

    await fresh();
    const second = sessionKey(); await seedDevice('g1', second, 'token-1');
    await prisma.tinyCloudNativeStepUp.create({ data: { id: 'su-2', grantId: 'g1', appId: EXPLORER, approvedPermissions: explorerEntries,
      status: 'REVOKED', revokedAt: new Date(Date.now() - 60_000), revokedReason: 'grant_revoked' } });
    const stale = await approvedCode(second);
    expect((await redeem(second, stale.code)).status).toBeGreaterThanOrEqual(400);
    expect(await prisma.tinyCloudNativeStepUp.findUniqueOrThrow({ where: { id: 'su-2' } })).toMatchObject({ status: 'REVOKED', revokedReason: 'grant_revoked' });
  });

  test('an active step-up is replaced by the newly approved set, never duplicated', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    await prisma.tinyCloudNativeStepUp.create({ data: { id: 'su-1', grantId: 'g1', appId: EXPLORER, approvedPermissions: explorerEntries.slice(0, 1) } });
    const flow = await approvedCode(key);
    expect((await redeem(key, flow.code)).status).toBe(200);
    expect(await prisma.tinyCloudNativeStepUp.findMany()).toEqual([expect.objectContaining({ id: 'su-1', status: 'ACTIVE', approvedPermissions: explorerEntries })]);
  });

  test('Home renews and signs in with consent narrowed to the delegation scope: renewal never needs openid or offline_access', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    // What a crash between the provider's consent write and the restore would leave behind.
    await prisma.oauthConsent.updateMany({ where: { userId: USER, clientId }, data: { scopes: [DELEGATION] } });
    const generation = JSON.stringify(await prisma.tinyCloudNativeConsentGeneration.findMany(), (_k, v) => typeof v === 'bigint' ? v.toString() : v);
    const response = await post(RENEW, new URLSearchParams({ client_id: clientId, refresh_token: 'token-1' }), proof(key, 'token-1', RENEW));
    const payload = await response.json() as { refresh_token?: string; tinycloud_delegation?: { grantId: string } };
    expect(response.status, JSON.stringify(payload)).toBe(200);
    expect(payload.tinycloud_delegation?.grantId).toBe('g1');
    // The renewed token is the new credential and keeps working for the next renewal.
    const next = await post(RENEW, new URLSearchParams({ client_id: clientId, refresh_token: payload.refresh_token! }), proof(key, payload.refresh_token!, RENEW));
    expect([next.status, (await next.json() as { error?: string }).error]).not.toEqual([400, 'consent_required']);
    expect(JSON.stringify(await prisma.tinyCloudNativeConsentGeneration.findMany(), (_k, v) => typeof v === 'bigint' ? v.toString() : v)).toBe(generation);
    expect((await prisma.tinyCloudNativeGrant.findUniqueOrThrow({ where: { id: 'g1' } })).status).toBe('ACTIVE');
  });

  test('the consent restore applies only to the provider write: an update-consent or a withdrawal after it is never undone', async () => {
    const { restoreStepUpConsent } = await import('../services/native-delegation/interceptors');
    const full = ['openid', 'offline_access', DELEGATION];
    const before = await prisma.oauthConsent.findFirstOrThrow({ where: { userId: USER, clientId } });
    expect(before.scopes).toEqual(full);
    const generation = async () => (await prisma.tinyCloudNativeConsentGeneration.findFirst({ where: { userId: USER, clientId } }))?.generation ?? 0n;
    const snapshot = async () => ({ id: before.id, userId: USER, clientId, scopes: before.scopes, updatedAt: before.updatedAt, generation: await generation() });
    const scopesNow = async () => (await prisma.oauthConsent.findMany({ where: { userId: USER, clientId } })).map((row) => row.scopes);

    // The provider's write is undone, updatedAt included.
    const taken = await snapshot();
    await prisma.oauthConsent.update({ where: { id: before.id }, data: { scopes: [DELEGATION], updatedAt: new Date() } });
    await restoreStepUpConsent(prisma, taken);
    expect(await prisma.oauthConsent.findUniqueOrThrow({ where: { id: before.id } })).toMatchObject({ scopes: full, updatedAt: before.updatedAt });

    // Nothing to undo: untouched.
    await restoreStepUpConsent(prisma, taken);
    expect(await scopesNow()).toEqual([full]);

    // The provider writes, then the user's update-consent withdraws the delegation scope (generation moves): the
    // restore must not bring the old scopes back.
    await prisma.oauthConsent.update({ where: { id: before.id }, data: { scopes: [DELEGATION] } });
    await prisma.oauthConsent.update({ where: { id: before.id }, data: { scopes: ['openid'] } });
    expect(await generation()).toBeGreaterThan(taken.generation);
    await restoreStepUpConsent(prisma, taken);
    expect(await scopesNow()).toEqual([['openid']]);

    // The consent was withdrawn outright: nothing is recreated.
    await prisma.oauthConsent.delete({ where: { id: before.id } });
    await restoreStepUpConsent(prisma, taken);
    expect(await scopesNow()).toEqual([]);

    // A snapshot that never held the delegation scope is never restored.
    await prisma.oauthConsent.create({ data: { id: before.id, userId: USER, clientId, scopes: [DELEGATION] } });
    await restoreStepUpConsent(prisma, { ...await snapshot(), scopes: ['openid'] });
    expect(await scopesNow()).toEqual([[DELEGATION]]);
  });

  test('withdrawing consent deletes the 300 s access token a step-up exchange mints, not only the grant\'s own tokens', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const token = (id: string, refreshId: string | null, scopes: string[]) => ({ id, token: hash(id), clientId, userId: USER, refreshId, scopes, expiresAt: new Date(Date.now() + 300_000) });
    await prisma.oauthAccessToken.createMany({ data: [token('stepup-token', null, [DELEGATION]), token('other-client-less', null, ['openid'])] });
    await prisma.oauthConsent.deleteMany({ where: { userId: USER, clientId } });
    expect((await prisma.oauthAccessToken.findMany({ where: { userId: USER } })).map((row) => row.id)).toEqual(['other-client-less']);
  });

  // ---- PR 3: renewal re-signs the grant's active step-ups ----
  async function renewHome(key: SessionKey, token = 'token-1') {
    const response = await post(RENEW, new URLSearchParams({ client_id: clientId, refresh_token: token }), proof(key, token, RENEW));
    return { response, payload: await response.json() as { refresh_token: string; tinycloud_delegation?: { permissions: unknown; expiresAt: string }; tinycloud_stepups?: Array<Record<string, any>>; tinycloud_stepups_dropped?: string[]; tinycloud_stepups_failed?: string[]; tinycloud_stepups_removed?: string[]; error?: string } };
  }

  test('renewal re-signs an active step-up for the grant key, inside the grant, and leaves Home\'s own delegation as it was', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    await prisma.tinyCloudNativeStepUp.create({ data: { id: 'su-1', grantId: 'g1', appId: EXPLORER, approvedPermissions: explorerEntries } });
    const { response, payload } = await renewHome(key);
    expect(response.status, JSON.stringify(payload)).toBe(200);
    expect(payload.tinycloud_stepups).toHaveLength(1);
    const [stepUp] = payload.tinycloud_stepups!;
    expect(stepUp).toMatchObject({ version: 1, appId: EXPLORER, grantId: 'g1', hosting: 'existing', permissions: explorerEntries, address, tinycloudHost: HOST });
    expect(stepUp!.spaces.map((space: { space: string }) => space.space)).toEqual(['public', 'applications']);
    expect(await recoverMessageAddress({ message: stepUp!.siwe, signature: stepUp!.signature })).toBe(address);
    const grant = await prisma.tinyCloudNativeGrant.findUniqueOrThrow({ where: { id: 'g1' } });
    expect(Date.parse(stepUp!.expiresAt)).toBeLessThanOrEqual(grant.absoluteExpiresAt.getTime());
    expect(stepUp!.renewableUntil).toBe(new Date(grant.absoluteExpiresAt.getTime() - 300_000).toISOString());
    // Home's delegation does not carry the step-up's entries: the step-up is its own delegation.
    expect(payload.tinycloud_delegation!.permissions).toEqual(homePermissions);
    expect(payload.tinycloud_stepups_dropped).toBeUndefined();
    expect(await prisma.tinyCloudNativeStepUp.findUniqueOrThrow({ where: { id: 'su-1' } })).toMatchObject({ status: 'ACTIVE', approvedPermissions: explorerEntries, grantId: 'g1' });
    expect((await prisma.tinyCloudNativeStepUp.findUniqueOrThrow({ where: { id: 'su-1' } })).lastRenewedAt).not.toBeNull();
  });

  test('renewal never re-signs a step-up the ceiling no longer covers, a revoked one, or any when the switch is off', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    await prisma.tinyCloudNativeStepUp.create({ data: { id: 'su-1', grantId: 'g1', appId: EXPLORER, approvedPermissions: explorerEntries } });
    await prisma.tinyCloudNativeStepUp.create({ data: { id: 'su-2', grantId: 'g1', appId: 'xyz.tinycloud.account', approvedPermissions: [{ service: 'tinycloud.kv', space: 'account', path: 'applications/', actions: ['tinycloud.kv/get'] }],
      status: 'REVOKED', revokedAt: new Date(), revokedReason: 'app_revoked' } });
    // The ceiling no longer covers Explorer's SQL: it is reported and not renewed, and its row is left as approved.
    await prisma.oauthClient.update({ where: { clientId }, data: { tinycloudNativeDelegation: { ...ceiling, stepUps: { [EXPLORER]: { public: ceiling.stepUps[EXPLORER].public } } } } });
    const narrowed = await renewHome(key);
    expect(narrowed.response.status, JSON.stringify(narrowed.payload)).toBe(200);
    expect(narrowed.payload.tinycloud_stepups).toEqual([]);
    expect(narrowed.payload.tinycloud_stepups_dropped).toEqual([EXPLORER]);
    expect(await prisma.tinyCloudNativeStepUp.findUniqueOrThrow({ where: { id: 'su-1' } })).toMatchObject({ status: 'ACTIVE', approvedPermissions: explorerEntries, lastRenewedAt: null });
    expect(await prisma.tinyCloudNativeStepUp.findUniqueOrThrow({ where: { id: 'su-2' } })).toMatchObject({ status: 'REVOKED', lastRenewedAt: null });
  });

  test('a grant with no active step-up renews with exactly the sign-in response; with the switch off a step-up is not renewed', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const plain = await renewHome(key);
    expect(plain.response.status).toBe(200);
    expect(Object.keys(plain.payload).sort()).toEqual(['expires_in', 'refresh_token', 'tinycloud_delegation']);
    // The inner delegation is the sign-in renewal's too: no step-up key leaks into it.
    const innerKeys = ['address', 'chainId', 'delegationCid', 'delegationHeader', 'expiresAt', 'grantId', 'hosting', 'issuedAt', 'ownerDid', 'permissions', 'renewableUntil', 'signature', 'siwe', 'spaceId', 'tinycloudHost', 'verificationMethod', 'version'];
    expect(Object.keys(plain.payload.tinycloud_delegation!).sort()).toEqual(innerKeys);

    await prisma.tinyCloudNativeStepUp.create({ data: { id: 'su-1', grantId: 'g1', appId: EXPLORER, approvedPermissions: explorerEntries } });
    await prisma.tinyCloudNativeGrant.update({ where: { id: 'g1' }, data: { lastRenewedAt: null } });
    const previous = process.env.OPENKEY_NATIVE_STEPUP_ENABLED;
    delete process.env.OPENKEY_NATIVE_STEPUP_ENABLED;
    try {
      const off = await renewHome(key, plain.payload.refresh_token);
      expect(off.response.status, JSON.stringify(off.payload)).toBe(200);
      expect(Object.keys(off.payload).sort()).toEqual(['expires_in', 'refresh_token', 'tinycloud_delegation']);
      expect(Object.keys(off.payload.tinycloud_delegation!).sort()).toEqual(innerKeys);
      expect((await prisma.tinyCloudNativeStepUp.findUniqueOrThrow({ where: { id: 'su-1' } })).lastRenewedAt).toBeNull();
    } finally { if (previous === undefined) delete process.env.OPENKEY_NATIVE_STEPUP_ENABLED; else process.env.OPENKEY_NATIVE_STEPUP_ENABLED = previous; }
  });

  test('a step-up that cannot be signed is reported and skipped; Home\'s own renewal and the other step-ups still succeed', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const account = [{ service: 'tinycloud.kv', space: 'account', path: 'applications/', actions: ['tinycloud.kv/get'] }];
    await prisma.tinyCloudNativeStepUp.create({ data: { id: 'su-account', grantId: 'g1', appId: 'xyz.tinycloud.account', approvedPermissions: account } });
    await prisma.tinyCloudNativeStepUp.create({ data: { id: 'su-explorer', grantId: 'g1', appId: EXPLORER, approvedPermissions: explorerEntries } });
    const delegateSession = await import('../routes/delegate-session');
    const original = delegateSession.prepareDelegationSession;
    // Calls, in order: Home's delegation, then the step-ups by app id (account first).
    let calls = 0;
    const spy = spyOn(delegateSession, 'prepareDelegationSession').mockImplementation((input) => {
      calls += 1;
      if (calls === 2) throw new Error('prepare failed: SIWE-SENTINEL');
      return original(input);
    });
    try {
      const { response, payload } = await renewHome(key);
      expect(response.status, JSON.stringify(payload)).toBe(200);
      expect(payload.tinycloud_delegation).toBeDefined();
      expect(payload.tinycloud_stepups!.map((stepUp) => stepUp.appId)).toEqual([EXPLORER]);
      expect(payload.tinycloud_stepups_failed).toEqual(['xyz.tinycloud.account']);
      expect(JSON.stringify(payload)).not.toContain('SENTINEL');
      expect((await prisma.tinyCloudNativeStepUp.findUniqueOrThrow({ where: { id: 'su-account' } })).lastRenewedAt).toBeNull();
      expect((await prisma.tinyCloudNativeStepUp.findUniqueOrThrow({ where: { id: 'su-explorer' } })).lastRenewedAt).not.toBeNull();
    } finally { spy.mockRestore(); }
  });

  // ---- PR 3b: app revoke, ceiling removal, the revoke sweep ----
  const REVOKE = '/api/auth/oauth2/tinycloud/revoke';
  function revokeApp(key: SessionKey, token: string, fields: Record<string, string> = {}) {
    return post(REVOKE, new URLSearchParams({ client_id: clientId, refresh_token: token, ...fields }), proof(key, token, REVOKE));
  }
  const account = [{ service: 'tinycloud.kv', space: 'account', path: 'applications/', actions: ['tinycloud.kv/get'] }];

  test('revoking one app ends only its step-up: the grant, its token and the other step-ups stay', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    await prisma.tinyCloudNativeStepUp.create({ data: { id: 'su-explorer', grantId: 'g1', appId: EXPLORER, approvedPermissions: explorerEntries } });
    await prisma.tinyCloudNativeStepUp.create({ data: { id: 'su-account', grantId: 'g1', appId: 'xyz.tinycloud.account', approvedPermissions: account } });
    const home = await homeState();
    const response = await revokeApp(key, 'token-1', { app_id: EXPLORER });
    expect(response.status, await response.clone().text()).toBe(200);
    expect(await homeState()).toBe(home);
    expect(await prisma.tinyCloudNativeStepUp.findUniqueOrThrow({ where: { id: 'su-explorer' } })).toMatchObject({ status: 'REVOKED', revokedReason: 'app_revoked', grantId: 'g1' });
    expect(await prisma.tinyCloudNativeStepUp.findUniqueOrThrow({ where: { id: 'su-account' } })).toMatchObject({ status: 'ACTIVE', revokedReason: null });
    // The token still renews Home, and the revoked app's step-up is no longer signed.
    const renewed = await renewHome(key);
    expect(renewed.response.status, JSON.stringify(renewed.payload)).toBe(200);
    expect(renewed.payload.tinycloud_stepups!.map((stepUp) => stepUp.appId)).toEqual(['xyz.tinycloud.account']);
    // Revoking an app with no step-up is the same answer, and changes nothing.
    const again = await revokeApp(key, renewed.payload.refresh_token, { app_id: EXPLORER });
    expect(again.status).toBe(200);
  });

  test('app_id is refused on renew, malformed, or with the step-up switch off; a plain revoke still ends the grant and its step-ups', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    await prisma.tinyCloudNativeStepUp.create({ data: { id: 'su-explorer', grantId: 'g1', appId: EXPLORER, approvedPermissions: explorerEntries } });
    const renew = await post(RENEW, new URLSearchParams({ client_id: clientId, refresh_token: 'token-1', app_id: EXPLORER }), proof(key, 'token-1', RENEW));
    expect(renew.status).toBe(400);
    expect((await revokeApp(key, 'token-1', { app_id: 'not an app id' })).status).toBe(400);
    expect((await revokeApp(key, 'token-1', { app_id: '' })).status).toBe(400);
    const previous = process.env.OPENKEY_NATIVE_STEPUP_ENABLED;
    delete process.env.OPENKEY_NATIVE_STEPUP_ENABLED;
    try { expect((await revokeApp(key, 'token-1', { app_id: EXPLORER })).status).toBe(400); }
    finally { if (previous === undefined) delete process.env.OPENKEY_NATIVE_STEPUP_ENABLED; else process.env.OPENKEY_NATIVE_STEPUP_ENABLED = previous; }
    expect((await prisma.tinyCloudNativeStepUp.findUniqueOrThrow({ where: { id: 'su-explorer' } })).status).toBe('ACTIVE');

    expect((await revokeApp(key, 'token-1')).status).toBe(200);
    expect(await prisma.tinyCloudNativeGrant.findUniqueOrThrow({ where: { id: 'g1' } })).toMatchObject({ status: 'REVOKED' });
    expect(await prisma.tinyCloudNativeStepUp.findUniqueOrThrow({ where: { id: 'su-explorer' } })).toMatchObject({ status: 'REVOKED', revokedReason: 'grant_revoked' });
  });

  test('revoking an app closes its approved-but-unredeemed request and queues the delegation already on the node for the sweep', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const flow = await approvedCode(key);
    expect((await revokeApp(key, 'token-1', { app_id: EXPLORER })).status).toBe(200);
    const request = await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id: flow.id } });
    expect(request).toMatchObject({ status: 'DENIED', signature: null, hosting: 'failed' });
    // An identifier and where to send the revocation: no signature, no delegation header.
    expect(Object.keys(request.delegation as object).sort()).toEqual(['address', 'appId', 'delegationCid', 'expiresAt', 'grantId', 'revokePending', 'siweDomain', 'tinycloudHost']);
    expect((await redeem(key, flow.code)).status).toBeGreaterThanOrEqual(400);
    expect(await prisma.tinyCloudNativeStepUp.count()).toBe(0);

    const calls: Array<{ host: string; headers: Record<string, string> }> = [];
    const { sweepRevokePendingOnce } = await import('../services/native-delegation/revoke-pending');
    const { signManagedKey } = await import('../services/managed-key-signing');
    const deps = (ok: boolean) => ({ signManaged: signManagedKey, now: () => new Date(), host: { revokeDelegation: async (host: string, headers: Record<string, string>) => { calls.push({ host, headers }); return { ok, status: ok ? 200 : 503 }; } } });
    // The node refuses: the record stays, nothing is lost.
    expect(await sweepRevokePendingOnce(prisma, deps(false))).toEqual({ pending: 1, revoked: 0, expired: 0 });
    expect((await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id: flow.id } })).delegation).not.toBeNull();
    // The node confirms: the record is cleared, and a second pass has nothing to do.
    expect(await sweepRevokePendingOnce(prisma, deps(true))).toEqual({ pending: 0, revoked: 1, expired: 0 });
    expect((await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id: flow.id } })).delegation).toBeNull();
    expect(await sweepRevokePendingOnce(prisma, deps(true))).toEqual({ pending: 0, revoked: 0, expired: 0 });
    expect(calls.map((call) => call.host)).toEqual([HOST, HOST]);
  });

  test('the sweep retries a record whatever its status, drops an expired one without a node call, and skips one whose key is not the account\'s', async () => {
    const { sweepRevokePendingOnce, revokePendingRecord } = await import('../services/native-delegation/revoke-pending');
    const { signManagedKey } = await import('../services/managed-key-signing');
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const calls: string[] = [];
    const deps = { signManaged: signManagedKey, now: () => new Date(), host: { revokeDelegation: async (host: string) => { calls.push(host); return { ok: true, status: 200 }; } } };
    const artifact = (cid: string, expiresAt: Date, owner = address) => revokePendingRecord(
      { delegationCid: cid, tinycloudHost: HOST, address: owner, grantId: 'g1', appId: EXPLORER, expiresAt: expiresAt.toISOString() }, 'openkey.so');
    const base = { clientId, redirectUri: STEPUP_REDIRECT, state: 'a'.repeat(32), codeChallenge: challenge, scopes: [DELEGATION], sessionDid: 'did:key:z', sessionJwk: key.publicJwk,
      sessionJkt: key.jkt, requestedPermissions: [], ttlSeconds: 300, requestUriExpiresAt: new Date(Date.now() + 60_000), expiresAt: new Date(Date.now() + 600_000),
      kind: 'STEPUP', grantId: 'g1', appId: EXPLORER, userId: USER };
    const soon = new Date(Date.now() + 600_000);
    await prisma.tinyCloudNativeRequest.create({ data: { ...base, id: 'r-denied', status: 'DENIED', delegation: artifact('cid-1', soon) } });
    await prisma.tinyCloudNativeRequest.create({ data: { ...base, id: 'r-withdrawn', status: 'WITHDRAWN', delegation: artifact('cid-2', soon) } });
    await prisma.tinyCloudNativeRequest.create({ data: { ...base, id: 'r-expired', status: 'DENIED', delegation: artifact('cid-3', new Date(Date.now() - 1_000)) } });
    await prisma.tinyCloudNativeRequest.create({ data: { ...base, id: 'r-foreign', status: 'DENIED', delegation: artifact('cid-4', soon, getAddress('0x' + '22'.repeat(20))) } });
    expect(await sweepRevokePendingOnce(prisma, deps)).toEqual({ pending: 1, revoked: 2, expired: 1 });
    expect(calls).toEqual([HOST, HOST]);
    const left = (await prisma.tinyCloudNativeRequest.findMany({ select: { id: true, delegation: true } })).filter((row) => row.delegation !== null);
    expect(left.map((row) => row.id)).toEqual(['r-foreign']);
  });

  test('an app that leaves the ceiling entirely loses its step-up at renewal; getting it back takes a full consent', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    await prisma.tinyCloudNativeStepUp.create({ data: { id: 'su-explorer', grantId: 'g1', appId: EXPLORER, approvedPermissions: explorerEntries } });
    await prisma.tinyCloudNativeStepUp.create({ data: { id: 'su-account', grantId: 'g1', appId: 'xyz.tinycloud.account', approvedPermissions: account } });
    const { stepUps: _all, ...withoutStepUps } = ceiling;
    // Explorer is gone from the ceiling; Account stays.
    await prisma.oauthClient.update({ where: { clientId }, data: { tinycloudNativeDelegation: { ...withoutStepUps, stepUps: { 'xyz.tinycloud.account': ceiling.stepUps['xyz.tinycloud.account'] } } } });
    const renewed = await renewHome(key);
    expect(renewed.response.status, JSON.stringify(renewed.payload)).toBe(200);
    expect(renewed.payload.tinycloud_stepups_removed).toEqual([EXPLORER]);
    expect(renewed.payload.tinycloud_stepups!.map((stepUp) => stepUp.appId)).toEqual(['xyz.tinycloud.account']);
    expect(await prisma.tinyCloudNativeStepUp.findUniqueOrThrow({ where: { id: 'su-explorer' } })).toMatchObject({ status: 'REVOKED', revokedReason: 'ceiling_removed', grantId: 'g1' });
    expect(await prisma.tinyCloudNativeStepUp.findUniqueOrThrow({ where: { id: 'su-account' } })).toMatchObject({ status: 'ACTIVE' });

    // The admin reuses the app id: nothing is inherited. Renewal does not bring the row back...
    await prisma.oauthClient.update({ where: { clientId }, data: { tinycloudNativeDelegation: ceiling } });
    await prisma.tinyCloudNativeGrant.update({ where: { id: 'g1' }, data: { lastRenewedAt: null } });
    const again = await renewHome(key, renewed.payload.refresh_token);
    expect(again.payload.tinycloud_stepups!.map((stepUp) => stepUp.appId)).toEqual(['xyz.tinycloud.account']);
    expect((await prisma.tinyCloudNativeStepUp.findUniqueOrThrow({ where: { id: 'su-explorer' } })).status).toBe('REVOKED');
    // ...only a fully consented, redeemed request does.
    const flow = await approvedCode(key, again.payload.refresh_token);
    expect((await redeem(key, flow.code)).status).toBe(200);
    expect(await prisma.tinyCloudNativeStepUp.findUniqueOrThrow({ where: { id: 'su-explorer' } })).toMatchObject({ status: 'ACTIVE', revokedReason: null, grantId: 'g1' });
  });

  async function sweepDeps(ok: boolean, calls: string[]) {
    const { signManagedKey } = await import('../services/managed-key-signing');
    return { signManaged: signManagedKey, now: () => new Date(), host: { revokeDelegation: async (host: string) => { calls.push(host); return { ok, status: ok ? 200 : 503 }; } } };
  }

  test('every delegation a step-up signs is remembered; revoking the app marks them and the sweep revokes each one on the node', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const flow = await approvedCode(key);
    const exchanged = await redeem(key, flow.code);
    expect(exchanged.status, await exchanged.clone().text()).toBe(200);
    const first = (await exchanged.json() as { tinycloud_stepup: { delegationCid: string } }).tinycloud_stepup.delegationCid;
    const renewed = await renewHome(key);
    expect(renewed.response.status, JSON.stringify(renewed.payload)).toBe(200);
    const second = renewed.payload.tinycloud_stepups![0]!.delegationCid as string;
    expect(second).not.toBe(first);
    const rows = await prisma.tinyCloudNativeStepUpDelegation.findMany();
    expect(rows.map((row) => row.delegationCid).sort()).toEqual([first, second].sort());
    expect(rows.every((row) => row.grantId === 'g1' && row.appId === EXPLORER && row.tinycloudHost === HOST && row.address === address && row.revokeRequestedAt === null)).toBe(true);

    expect((await revokeApp(key, renewed.payload.refresh_token, { app_id: EXPLORER })).status).toBe(200);
    expect((await prisma.tinyCloudNativeStepUpDelegation.findMany()).every((row) => row.revokeRequestedAt !== null)).toBe(true);
    const { sweepRevokePendingOnce } = await import('../services/native-delegation/revoke-pending');
    const calls: string[] = [];
    expect(await sweepRevokePendingOnce(prisma, await sweepDeps(true, calls))).toEqual({ pending: 0, revoked: 2, expired: 0 });
    expect(calls).toEqual([HOST, HOST]);
    expect(await prisma.tinyCloudNativeStepUpDelegation.count()).toBe(0);
    expect(await prisma.tinyCloudNativeStepUp.findUniqueOrThrow({ where: { grantId_appId: { grantId: 'g1', appId: EXPLORER } } })).toMatchObject({ status: 'REVOKED', revokedReason: 'app_revoked' });
  });

  test('revoking the grant marks its step-up delegations too; expired ones are forgotten, and a node that refuses keeps the rest', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    await prisma.tinyCloudNativeStepUp.create({ data: { id: 'su-1', grantId: 'g1', appId: EXPLORER, approvedPermissions: explorerEntries } });
    const row = (id: string, expiresAt: Date) => ({ id, grantId: 'g1', appId: EXPLORER, delegationCid: `cid-${id}`, tinycloudHost: HOST, address, siweDomain: 'openkey.so', expiresAt });
    await prisma.tinyCloudNativeStepUpDelegation.create({ data: row('live', new Date(Date.now() + 600_000)) });
    await prisma.tinyCloudNativeStepUpDelegation.create({ data: row('old', new Date(Date.now() - 60_000)) });
    expect((await revokeApp(key, 'token-1')).status).toBe(200);
    expect((await prisma.tinyCloudNativeStepUpDelegation.findUniqueOrThrow({ where: { id: 'live' } })).revokeRequestedAt).not.toBeNull();
    expect((await prisma.tinyCloudNativeStepUpDelegation.findUniqueOrThrow({ where: { id: 'old' } })).revokeRequestedAt).toBeNull();

    const { sweepRevokePendingOnce } = await import('../services/native-delegation/revoke-pending');
    const calls: string[] = [];
    expect(await sweepRevokePendingOnce(prisma, await sweepDeps(false, calls))).toEqual({ pending: 1, revoked: 0, expired: 0 });
    expect((await prisma.tinyCloudNativeStepUpDelegation.findMany()).map((entry) => entry.id)).toEqual(['live']);
    expect(await sweepRevokePendingOnce(prisma, await sweepDeps(true, calls))).toEqual({ pending: 0, revoked: 1, expired: 0 });
    expect(await prisma.tinyCloudNativeStepUpDelegation.count()).toBe(0);
    expect(calls).toEqual([HOST, HOST]);
  });

  test('the sweep never signs for a node OpenKey does not talk to, nor for an account that took its key back', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    await prisma.tinyCloudNativeStepUp.create({ data: { id: 'su-1', grantId: 'g1', appId: EXPLORER, approvedPermissions: explorerEntries, status: 'REVOKED', revokedReason: 'app_revoked' } });
    const marked = (id: string, tinycloudHost: string) => ({ id, grantId: 'g1', appId: EXPLORER, delegationCid: `cid-${id}`, tinycloudHost, address, siweDomain: 'openkey.so',
      expiresAt: new Date(Date.now() + 600_000), revokeRequestedAt: new Date() });
    await prisma.tinyCloudNativeStepUpDelegation.create({ data: marked('good', HOST) });
    await prisma.tinyCloudNativeStepUpDelegation.create({ data: marked('evil', 'https://evil.example') });
    const { sweepRevokePendingOnce } = await import('../services/native-delegation/revoke-pending');
    const calls: string[] = [];
    await prisma.user.update({ where: { id: USER }, data: { tinyCloudManageKeyMode: 'USER_CONTROLLED_EXCLUSIVE' } });
    expect(await sweepRevokePendingOnce(prisma, await sweepDeps(true, calls))).toEqual({ pending: 2, revoked: 0, expired: 0 });
    expect(calls).toEqual([]);
    await prisma.user.update({ where: { id: USER }, data: { tinyCloudManageKeyMode: 'APP_MANAGED' } });
    expect(await sweepRevokePendingOnce(prisma, await sweepDeps(true, calls))).toEqual({ pending: 1, revoked: 1, expired: 0 });
    expect(calls).toEqual([HOST]);
    expect((await prisma.tinyCloudNativeStepUpDelegation.findMany()).map((row) => row.id)).toEqual(['evil']);
  });

  test('a request that was redeemed before the sweep is not touched by it', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const flow = await approvedCode(key);
    expect((await redeem(key, flow.code)).status).toBe(200);
    const { sweepRevokePendingOnce } = await import('../services/native-delegation/revoke-pending');
    const calls: string[] = [];
    expect(await sweepRevokePendingOnce(prisma, await sweepDeps(true, calls))).toEqual({ pending: 0, revoked: 0, expired: 0 });
    expect(calls).toEqual([]);
    expect((await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id: flow.id } })).status).toBe('REDEEMED');
  });

  // An approved step-up has its delegation live on the node before the exchange. Whatever ends it without a redeem
  // (sign-out, Apple revoke, consent withdrawal) must leave the sweep a record to revoke, and no signed artifact behind.
  const endings: Array<[string, (key: SessionKey) => Promise<void>, string]> = [
    ['sign-out', async (key) => { expect((await revokeApp(key, 'token-1')).status).toBe(200); }, 'DENIED'],
    ['consent withdrawal', async () => { await prisma.oauthConsent.deleteMany({ where: { userId: USER, clientId } }); }, 'WITHDRAWN'],
    // Last: it deletes the user's sessions, which the cookie of the tests after it would need.
    ['an Apple revoke', async () => {
      const { revokeUserAccess } = await import('../services/apple-notifications');
      await prisma.$transaction((tx) => revokeUserAccess(tx, USER, 'apple_consent_revoked'));
    }, 'DENIED'],
  ];
  for (const [label, end, status] of endings) {
    test(`an approved, unredeemed step-up ended by ${label} is revoked on the node by the sweep, and its signature is dropped`, async () => {
      const key = sessionKey(); await seedDevice('g1', key, 'token-1');
      const flow = await approvedCode(key);
      expect((await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id: flow.id } })).signature).not.toBeNull();
      await end(key);
      const { sweepRevokePendingOnce } = await import('../services/native-delegation/revoke-pending');
      const calls: string[] = [];
      // The node refuses first: the record, not the signature, is what is left.
      expect(await sweepRevokePendingOnce(prisma, await sweepDeps(false, calls))).toEqual({ pending: 1, revoked: 0, expired: 0 });
      const row = await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id: flow.id } });
      expect(row).toMatchObject({ status, signature: null, hosting: 'failed' });
      expect(Object.keys(row.delegation as object).sort()).toEqual(['address', 'appId', 'delegationCid', 'expiresAt', 'grantId', 'revokePending', 'siweDomain', 'tinycloudHost']);
      expect(await sweepRevokePendingOnce(prisma, await sweepDeps(true, calls))).toEqual({ pending: 0, revoked: 1, expired: 0 });
      expect((await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id: flow.id } })).delegation).toBeNull();
      expect(calls).toEqual([HOST, HOST]);
    });
  }

  test('entries that can never be revoked are dropped, and ones that stay move to the back of the queue', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    await prisma.tinyCloudNativeStepUp.create({ data: { id: 'su-1', grantId: 'g1', appId: EXPLORER, approvedPermissions: explorerEntries, status: 'REVOKED', revokedReason: 'app_revoked' } });
    const { sweepRevokePendingOnce, revokePendingRecord } = await import('../services/native-delegation/revoke-pending');
    const base = { clientId, redirectUri: STEPUP_REDIRECT, state: 'a'.repeat(32), codeChallenge: challenge, scopes: [DELEGATION], sessionDid: 'did:key:z', sessionJwk: key.publicJwk,
      sessionJkt: key.jkt, requestedPermissions: [], ttlSeconds: 300, requestUriExpiresAt: new Date(Date.now() + 60_000), expiresAt: new Date(Date.now() + 600_000),
      kind: 'STEPUP', grantId: 'g1', appId: EXPLORER };
    const record = revokePendingRecord({ delegationCid: 'cid-x', tinycloudHost: 'https://evil.example', address, grantId: 'g1', appId: EXPLORER, expiresAt: new Date(Date.now() + 600_000).toISOString() }, 'openkey.so');
    await prisma.tinyCloudNativeRequest.create({ data: { ...base, id: 'r-ownerless', status: 'DENIED', userId: null, delegation: { ...record, tinycloudHost: HOST } } });
    await prisma.tinyCloudNativeRequest.create({ data: { ...base, id: 'r-garbage', status: 'DENIED', userId: USER, delegation: { revokePending: true } } });
    await prisma.tinyCloudNativeRequest.create({ data: { ...base, id: 'r-gated', status: 'DENIED', userId: USER, delegation: record } });
    await prisma.tinyCloudNativeStepUpDelegation.create({ data: { id: 'd-gated', grantId: 'g1', appId: EXPLORER, delegationCid: 'cid-d', tinycloudHost: 'https://evil.example', address,
      siweDomain: 'openkey.so', expiresAt: new Date(Date.now() + 600_000), revokeRequestedAt: new Date() } });
    const calls: string[] = [];
    const before = await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id: 'r-gated' } });
    expect(await sweepRevokePendingOnce(prisma, await sweepDeps(true, calls))).toEqual({ pending: 2, revoked: 0, expired: 2 });
    expect(calls).toEqual([]);
    const left = (await prisma.tinyCloudNativeRequest.findMany({ select: { id: true, delegation: true, updatedAt: true } })).filter((row) => row.delegation !== null);
    expect(left.map((row) => row.id)).toEqual(['r-gated']);
    expect(left[0]!.updatedAt.getTime()).toBeGreaterThan(before.updatedAt.getTime());
    expect((await prisma.tinyCloudNativeStepUpDelegation.findUniqueOrThrow({ where: { id: 'd-gated' } })).lastAttemptAt).not.toBeNull();
  });
}
