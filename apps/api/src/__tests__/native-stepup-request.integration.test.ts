import './tc1777-test-env';
import { afterAll, beforeAll, beforeEach, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomUUID, sign, type KeyObject } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { getAddress } from 'viem';
import { serializeSignedCookie } from 'better-call';
import type * as DatabaseModule from '@openkey/db';

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
  let address: string;
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
  const challenge = hash('tc3569-verifier');
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
    const { createPrismaClient } = await import('@openkey/db');
    prisma = createPrismaClient();
    const { auth } = await import('../auth');
    app = (await import('../index')).default;
    await prisma.user.create({ data: { id: USER, email: 'su@example.test', name: 'SU', emailVerified: true } });
    const sessionToken = randomUUID();
    await prisma.session.create({ data: { id: 'su-session', token: sessionToken, userId: USER, expiresAt: new Date(Date.now() + 3_600_000) } });
    const context = await auth.$context;
    cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, sessionToken, context.secret)).split(';')[0]!;
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
    await prisma.user.update({ where: { id: USER }, data: { lockedAt: null, tinyCloudManageKeyMode: 'APP_MANAGED' } });
    await prisma.ethereumKey.update({ where: { id: 'su-key' }, data: { isCanonicalTinyCloud: true } });
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
    for (const extra of [{ session_key: JSON.stringify(other.publicJwk) }, { session_did: 'did:key:z6Mk' }, { authorization_details: '[]' }]) {
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
    await prisma.user.update({ where: { id: USER }, data: { lockedAt: null, tinyCloudManageKeyMode: 'APP_MANAGED' } });
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
    ]) {
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

  test('the sign-in consent path never acts on a STEPUP request', async () => {
    const key = sessionKey(); await seedDevice('g1', key, 'token-1');
    const created = await (await stepUp(key, 'token-1')).json() as { request_uri: string };
    const id = created.request_uri.slice('urn:ietf:params:oauth:request_uri:'.length);
    await prisma.tinyCloudNativeRequest.update({ where: { id }, data: { status: 'RESOLVED' } });
    for (const action of ['prepare', 'approve']) {
      const response = await app.fetch(new Request(`${API}/api/oauth/tinycloud/requests/${id}/${action}`, { method: 'POST',
        headers: { cookie, origin: 'https://openkey.test', 'content-type': 'application/json' }, body: '{}' }));
      expect([action, response.status, (await body(response)).error]).toEqual([action, 409, 'unsupported_request_kind']);
    }
    expect(await prisma.tinyCloudNativePreparation.count()).toBe(0);
    expect((await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } })).status).toBe('RESOLVED');
    expect(await prisma.tinyCloudNativeStepUp.count()).toBe(0);
    expect(await prisma.tinyCloudNativeGrant.count()).toBe(1);
  });
}
