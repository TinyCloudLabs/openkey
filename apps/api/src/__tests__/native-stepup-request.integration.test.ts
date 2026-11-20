import './tc1777-test-env';
import { afterAll, beforeAll, beforeEach, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomUUID, sign, type KeyObject } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { getAddress, recoverMessageAddress } from 'viem';
import { SiweMessage } from 'siwe';
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
    expect(row.delegation).toEqual({ revokePending: true, delegationCid: expect.any(String), tinycloudHost: HOST, address, grantId: 'g1', appId: EXPLORER, expiresAt: expect.any(String) });
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
}
