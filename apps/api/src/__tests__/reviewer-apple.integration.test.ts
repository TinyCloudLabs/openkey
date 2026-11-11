import './tc1777-test-env';
import { afterAll, beforeAll, expect, test, setSystemTime } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { generateCodeChallenge } from 'better-auth/oauth2';
import { verifyMessage } from 'viem';
import type { Prisma, PrismaClient } from '@openkey/db';

const root = resolve(import.meta.dir, '../../../..');
if (!process.env.OPENKEY_APPLE_REVIEW_TEST_CHILD) {
  test('Apple reviewer lifecycle through the real provider and disposable node transport', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], { cwd: root, env: {
      ...process.env, OPENKEY_APPLE_REVIEW_TEST_CHILD: '1', APPLE_REVIEW_ENABLED: 'true', NODE_ENV: 'test', TEE_MODE: 'development',
      BETTER_AUTH_URL: 'https://api.openkey.test', BETTER_AUTH_SECRET: 'apple-review-test-secret-01234567890123456789',
      WEBAUTHN_RP_ID: 'openkey.test', WEBAUTHN_ORIGIN: 'https://openkey.test', CORS_ORIGIN: 'https://openkey.test',
      ADMIN_API_KEY: 'isolated-apple-review-test-admin', RESEND_API_KEY: '', GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '',
    }, stdout: 'pipe', stderr: 'pipe' });
    const [stdout, stderr, status] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
    expect(status, stdout + stderr).toBe(0);
  }, 240_000);
} else {
  const clientId = 'ok_e1d13d0b220379f37a553aa0391d28a4';
  const host = 'https://tee.node.tinycloud.xyz';
  const redirect = 'xyz.tinycloud.exo://openkey/callback';
  const api = 'https://api.openkey.test';
  const email = 'appreview@tinycloud.xyz';
  const code = randomBytes(32).toString('base64url');
  const appId = 'xyz.tinycloud.tinychat';
  const ceiling = { version: 1, appId, tinycloudHost: host,
    kv: { paths: [`${appId}/threads/`, `${appId}/connectors/`, `${appId}/exo/v1/requests/`, `${appId}/exo/v1/jobs/`], actions: ['get', 'put', 'list', 'del', 'metadata'], root: true },
    sql: { databases: ['threads', 'canvas', 'connectors', 'home_feed', 'details', 'summaries', 'transcripts'].map(x => `${appId}/${x}`), actions: ['read', 'write', 'schema'], prefixes: [`${appId}/feed/`], foreignDatabases: ['xyz.tinycloud.sample.healthlog/healthlog', 'xyz.tinycloud.sample.recipes/recipes'] },
    hooks: { paths: [`sql/${appId}/feed/`, `sql/${appId}/home_feed`, `sql/${appId}/threads`], actions: ['subscribe'] },
    maxDelegationTtlSeconds: 3600, grantLifetimeSeconds: 30 * 86400, siweDomain: 'openkey.so' };
  let directory: string;
  let database: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let accounts: typeof import('../services/reviewer-accounts');
  let policy: typeof import('../services/reviewer-apple-policy');
  let seed: typeof import('../services/reviewer-apple-seed');
  let cleanup: typeof import('../services/reviewer-cleanup');
  let key: any;
  let spaceId: string;
  let cookie: string;
  let sourceCreatedAt: number;
  const originalFetch = globalThis.fetch;
  const originalWrite = process.stdout.write;
  let capturedOutput = '';
  const pair = generateKeyPairSync('ed25519');
  const jwk = pair.publicKey.export({ format: 'jwk' }) as { kty: string; crv: string; x: string };
  const hash = (text: string) => createHash('sha256').update(text).digest('base64url');
  const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  function proof(credential: string, path: string) {
    const h = b64({ typ: 'openkey-session-proof+jwt', alg: 'EdDSA', kid: hash(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: jwk.x })) });
    const p = b64({ jti: randomUUID(), iat: Math.floor(Date.now() / 1000), htm: 'POST', htu: `${api}/api/auth${path}`, client_id: clientId, cred_hash: hash(credential) });
    return `${h}.${p}.${sign(null, Buffer.from(`${h}.${p}`), pair.privateKey).toString('base64url')}`;
  }
  const call = (path: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}) => app.fetch(new Request(api + path, {
    method, headers: { origin: 'https://openkey.test', 'content-type': 'application/json', ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }));
  const form = (path: string, body: Record<string, string>, headers: Record<string, string> = {}) => app.fetch(new Request(api + path, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams(body),
  }));

  beforeAll(async () => {
    process.stdout.write = ((chunk: any, ...args: any[]) => { capturedOutput += String(chunk); return (originalWrite as any).call(process.stdout, chunk, ...args); }) as typeof process.stdout.write;
    directory = await mkdtemp('/var/tmp/tc2775-apple-db.');
    const pg = new PGlite(directory);
    try {
      for (const name of (await readdir(join(root, 'packages/db/prisma/migrations'))).sort()) {
        if (name !== 'migration_lock.toml') await pg.exec(await readFile(join(root, 'packages/db/prisma/migrations', name, 'migration.sql'), 'utf8'));
      }
    } finally { await pg.close(); }
    process.env.DATABASE_URL = 'pglite:' + directory;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    database = (await import('../auth')).prisma;
    app = (await import('../index')).default;
    accounts = await import('../services/reviewer-accounts');
    policy = await import('../services/reviewer-apple-policy');
    seed = await import('../services/reviewer-apple-seed');
    cleanup = await import('../services/reviewer-cleanup');
    await database.oauthClient.create({ data: { id: randomUUID(), clientId, name: 'Home fixture', public: true, type: 'native', tokenEndpointAuthMethod: 'none', redirectUris: [redirect], scopes: ['openid', 'email', 'offline_access', 'tinycloud:delegation'], contacts: [], tinycloudNativeDelegation: ceiling } });
    await database.user.create({ data: { id: 'apple-review-owner', email, name: 'App review', emailVerified: true, reviewerHoldAt: new Date() } });
    const tee = await import('@openkey/tee');
    const privateKey = tee.generatePrivateKey();
    const address = tee.getAddressFromPrivateKey(privateKey);
    const sealingContext = (await import('../services/key-sealing')).createSealingContext();
    key = await database.ethereumKey.create({ data: { id: 'apple-review-key', userId: 'apple-review-owner', address, publicKey: address,
      sealingContext, sealedBlob: await tee.seal(privateKey, await tee.createTeeClient().deriveKey('openkey/key/' + sealingContext)), isCanonicalTinyCloud: true } });
    spaceId = `tinycloud:pkh:eip155:1:${address}:applications`;
    await database.reviewerAccount.update({ where: { store: 'apple' }, data: { userId: key.userId, keyId: key.id, spaceId, clientId, redirectUri: redirect, nodeHost: host } });
    await database.tinyCloudBootstrapState.create({ data: { userId: key.userId, keyId: key.id, address, chainId: 1, tinycloudHost: host,
      bootstrapVersion: 'test', status: 'complete', checkedAt: new Date(), completedAt: new Date() } });
    globalThis.fetch = ((input: RequestInfo | URL) => {
      if (String(input) === host + '/delegate') return Promise.resolve(Response.json({ activated: [spaceId] }));
      return Promise.reject(new Error('External network disabled in Apple reviewer test'));
    }) as typeof fetch;
  }, 90_000);
  afterAll(async () => { process.stdout.write = originalWrite; expect(capturedOutput.includes(code)).toBe(false); expect(capturedOutput.includes(accounts.credentialDigest(code).toString('base64url'))).toBe(false); setSystemTime(); globalThis.fetch = originalFetch; await database?.$disconnect(); if (directory) await rm(directory, { recursive: true, force: true }); });

  test('fixed seed request, decoded signed authority, retry deadline and spent-run hold', async () => {
    const { reviewerSessionDid } = await import('../services/reviewer-delegation');
    const sessionDid = reviewerSessionDid(jwk)!;
    const request = { kind: 'tinycloud.auth.request', version: 1, requestId: 'reviewer-seed-' + randomUUID(), createdAt: new Date().toISOString(), sessionDid, requested: policy.reviewerSeedPermissions(false), requestedExpiry: '1h' };
    for (const mutation of [{ ...request, owner: 'foreign' }, { ...request, requested: [...request.requested, { service: 'tinycloud.kv', space: 'applications', path: '', actions: ['tinycloud.kv/put'] }] }]) {
      await expect(seed.reviewerSeedGrant(database, mutation as any, false)).rejects.toThrow();
    }
    const signed = await seed.buildReviewerGrant(key, spaceId, host, sessionDid, request.requested, new Date(Date.now() + 3600_000));
    const { parseStrictSiwe } = await import('../services/signed-subset');
    const decoded = parseStrictSiwe(signed.siwe);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) throw new Error('Invalid signed seed grant');
    expect(await verifyMessage({ address: key.address, message: signed.siwe, signature: signed.signature })).toBe(true);
    expect(decoded.siwe.uri.split('#')[0]).toBe(sessionDid);
    expect(Date.parse(decoded.siwe.expirationTime!) - Date.parse(decoded.siwe.issuedAt)).toBeLessThanOrEqual(3600_000);
    const { parsePreparedRecap } = await import('../routes/delegate-session');
    expect(parsePreparedRecap(signed.siwe).map(p => ({ ...p, service: 'tinycloud.' + p.service, space: 'applications', actions: [...p.actions].sort() })).sort((a,b) => a.path.localeCompare(b.path)))
      .toEqual(request.requested.map(p => ({ ...p, actions: [...p.actions].sort() })).sort((a,b) => a.path.localeCompare(b.path)));
    const first = await seed.reviewerSeedGrant(database, request, false);
    expect((await seed.reviewerSeedGrant(database, request, false)).expiry).toBe(first.expiry);
    await expect(seed.reviewerSeedGrant(database, { ...request, requestId: 'reviewer-seed-' + randomUUID() }, false)).rejects.toThrow();
    setSystemTime(Date.parse(first.expiry) + 1);
    await expect(seed.reviewerSeedGrant(database, request, false)).rejects.toThrow();
    setSystemTime();
    await accounts.unsetReviewer(database, 'apple');
    const held = await database.reviewerAccount.findUniqueOrThrow({ where: { store: 'apple' } });
    expect(held.seedRun).toBeNull();
    expect(held.seedStartedAt).not.toBeNull();
    await expect(seed.reviewerSeedGrant(database, request, false)).rejects.toThrow();
    // The following tests exercise authentication independently of the node
    // fixture writer; only operator seed verification may set this in use.
    await database.reviewerAccount.update({ where: { store: 'apple' }, data: { seededAt: new Date() } });
  });

  test('default-off, exact Home policy, and a typo cannot create a user with the review code', async () => {
    process.env.APPLE_REVIEW_ENABLED = 'false';
    await expect(accounts.installReviewer(database, 'apple', code)).rejects.toThrow();
    process.env.APPLE_REVIEW_ENABLED = 'true';
    expect(policy.reviewerHomePermissions(policy.REVIEWER_HOME_PERMISSIONS)).toBe(true);
    expect(policy.reviewerHomePermissions([...policy.REVIEWER_HOME_PERMISSIONS, policy.REVIEWER_HOME_PERMISSIONS[0]])).toBe(false);
    expect(policy.reviewerHomePermissions(policy.REVIEWER_HOME_PERMISSIONS.map((p, i) => i === 0 ? { ...p, extra: true } : p))).toBe(false);
    const typo = await call('/api/auth/sign-in/email-otp', 'POST', { email: 'apprevieew@tinycloud.xyz', otp: code });
    expect(typo.status).toBeGreaterThanOrEqual(400);
    expect(await database.user.count({ where: { email: 'apprevieew@tinycloud.xyz' } })).toBe(0);
  });

  test('native PAR -> normalized email code -> consent -> proof/PKCE exchange, bounded to source session', async () => {
    await accounts.installReviewer(database, 'apple', code);
    const verifier = randomBytes(32).toString('base64url');
    const par = await form('/api/auth/oauth2/par', { client_id: clientId, response_type: 'code', redirect_uri: redirect, state: randomUUID(),
      code_challenge: await generateCodeChallenge(verifier), code_challenge_method: 'S256', scope: 'openid email offline_access tinycloud:delegation',
      login_method: 'email', login_hint: email, authorization_details: JSON.stringify([{ type: 'tinycloud_delegation', session_key: jwk, permissions: policy.REVIEWER_HOME_PERMISSIONS, ttl_seconds: 3600 }]) });
    expect(par.status, await par.clone().text()).toBe(201);
    const requestUri = (await par.json() as any).request_uri;
    const start = await call('/api/auth/oauth2/authorize?' + new URLSearchParams({ client_id: clientId, request_uri: requestUri }));
    expect(start.status).toBe(302);
    const query = new URL(start.headers.get('location')!).searchParams.toString();
    const signed = await (await import('../services/reviewer-auth')).signedReviewerQuery(query, process.env.BETTER_AUTH_SECRET!);
    expect(signed).not.toBeNull();
    const row = await database.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id: requestUri.split(':').at(-1)! } });
    expect(row.status).toBe('RESOLVED');
    expect(policy.reviewerHomePermissions(row.requestedPermissions)).toBe(true);
    const { authoritativeQuery, matchesAuthoritativeQuery } = await import('../services/native-delegation/par');
    expect(matchesAuthoritativeQuery(signed!, authoritativeQuery(row)), JSON.stringify(Object.fromEntries(signed!))).toBe(true);

    const crossSite = await call('/api/auth/sign-in/email-otp', 'POST', { email, otp: code, oauth_query: query }, { origin: 'https://foreign.test' });
    expect(crossSite.status).toBe(403);
    const login = await call('/api/auth/sign-in/email-otp', 'POST', { email: '  AppReview@TinyCloud.XYZ ', otp: code, oauth_query: query });
    expect(login.status, await login.clone().text()).toBe(200);
    cookie = login.headers.get('set-cookie')!.split(';')[0]!;
    const resumed = (await login.json() as any).url;
    const consentRedirect = await app.fetch(new Request(resumed, { headers: { cookie } }));
    expect(consentRedirect.status, await consentRedirect.clone().text()).toBe(302);
    const consentQuery = new URL(consentRedirect.headers.get('location')!).searchParams.toString();
    const requestId = requestUri.split(':').at(-1);
    const prepare = await call(`/api/oauth/tinycloud/requests/${requestId}/prepare`, 'POST', {}, { cookie });
    expect(prepare.status, await prepare.clone().text()).toBe(200);
    const preview = await prepare.json() as any;
    expect(preview.hostPlan).toBeNull();
    const approved = await call(`/api/oauth/tinycloud/requests/${requestId}/approve`, 'POST', { revision: preview.revision, digest: preview.digest, sessionSiwe: preview.sessionSiwe }, { cookie });
    expect(approved.status, await approved.clone().text()).toBe(200);
    const consentSigned = await (await import('../services/reviewer-auth')).signedReviewerQuery(consentQuery, process.env.BETTER_AUTH_SECRET!);
    expect(consentSigned).not.toBeNull();
    const consentExpected = authoritativeQuery(row);
    consentExpected.delete('login_hint');
    expect(matchesAuthoritativeQuery(consentSigned!, consentExpected)).toBe(true);
    const consent = await call('/api/auth/oauth2/consent', 'POST', { accept: true, oauth_query: consentQuery }, { cookie });
    expect(consent.status, await consent.clone().text()).toBe(200);
    const authCode = new URL((await consent.json() as any).url).searchParams.get('code')!;
    const exchange = await form('/api/auth/oauth2/token', { grant_type: 'authorization_code', code: authCode, client_id: clientId, redirect_uri: redirect, code_verifier: verifier }, { 'OpenKey-Session-Proof': proof(authCode, '/oauth2/token') });
    expect(exchange.status, await exchange.clone().text()).toBe(200);
    const tokens = await exchange.json() as any;
    const binding = await database.reviewerAccount.findUniqueOrThrow({ where: { store: 'apple' } });
    const grant = await database.tinyCloudNativeGrant.findFirstOrThrow({ where: { userId: binding.userId! } });
    const source = await database.session.findUniqueOrThrow({ where: { id: binding.grantSessionId! } });
    sourceCreatedAt = source.createdAt.getTime();
    expect(grant.absoluteExpiresAt.getTime()).toBe(sourceCreatedAt + 3600_000);
    expect(grant.reviewerEpoch).toBe(binding.installEpoch);
    expect(tokens.tinycloud_delegation.spaceId).toBe(spaceId);
    expect(Date.parse(tokens.tinycloud_delegation.expiresAt)).toBeLessThanOrEqual(sourceCreatedAt + 3600_000);
    expect((await call('/api/delegate/prepare', 'POST', {}, { cookie })).status).toBe(403);
    const refreshRow = await database.oauthRefreshToken.findFirstOrThrow({ where: { userId: binding.userId! } });
    expect(refreshRow.expiresAt.getTime() - sourceCreatedAt).toBeGreaterThan(3599_000);
    expect(refreshRow.token).toBe(grant.refreshTokenHash!);
    for (const seconds of [3599, 3600, 3601]) {
      setSystemTime(sourceCreatedAt + seconds * 1000);
      const renew = await form('/api/auth/oauth2/tinycloud/renew', { client_id: clientId, refresh_token: tokens.refresh_token }, { 'OpenKey-Session-Proof': proof(tokens.refresh_token, '/oauth2/tinycloud/renew'), ...(seconds === 3599 ? { cookie } : {}) });
      expect(renew.status, await renew.clone().text()).toBe(seconds === 3599 ? 200 : 400);
      if (renew.ok) tokens.refresh_token = (await renew.json() as any).refresh_token;
    }
    setSystemTime();
  });

  test('TC-2720 stays unchanged for an ordinary user on the very same Home client', async () => {
    const { serializeSignedCookie } = await import('better-call');
    const userId = 'ordinary-home-owner';
    await database.user.create({ data: { id: userId, email: 'ordinary@tinycloud.test', name: 'Ordinary', emailVerified: true } });
    const ownKey = await database.ethereumKey.create({ data: { id: 'ordinary-home-key', userId, address: '0x0000000000000000000000000000000000000001', publicKey: '0x1', sealedBlob: 'not-used-for-prepare', isCanonicalTinyCloud: true } });
    await database.tinyCloudBootstrapState.create({ data: { userId, keyId: ownKey.id, address: ownKey.address, chainId: 1, tinycloudHost: host, bootstrapVersion: 'test', status: 'complete', checkedAt: new Date() } });
    const token = randomUUID();
    await database.session.create({ data: { id: 'ordinary-home-session', userId, token, expiresAt: new Date(Date.now() + 86400_000) } });
    const ctx = await (await import('../auth')).auth.$context;
    const ordinaryCookie = (await serializeSignedCookie(ctx.authCookies.sessionToken.name, token, ctx.secret)).split(';')[0]!;
    const verifier = randomBytes(32).toString('base64url');
    const par = await form('/api/auth/oauth2/par', { client_id: clientId, response_type: 'code', redirect_uri: redirect, state: randomUUID(),
      code_challenge: await generateCodeChallenge(verifier), code_challenge_method: 'S256', scope: 'openid email offline_access tinycloud:delegation',
      authorization_details: JSON.stringify([{ type: 'tinycloud_delegation', session_key: jwk, permissions: policy.REVIEWER_HOME_PERMISSIONS, ttl_seconds: 3600 }]) });
    expect(par.status).toBe(201);
    const uri = (await par.json() as any).request_uri;
    const start = await call('/api/auth/oauth2/authorize?' + new URLSearchParams({ client_id: clientId, request_uri: uri }), 'GET', undefined, { cookie: ordinaryCookie });
    expect(start.status).toBe(302);
    const preview = await call(`/api/oauth/tinycloud/requests/${uri.split(':').at(-1)}/prepare`, 'POST', {}, { cookie: ordinaryCookie });
    expect(preview.status, await preview.clone().text()).toBe(200);
    const body = await preview.json() as any;
    expect(body.ttlSeconds).toBe(3600);
    expect(body.grantLifetimeSeconds).toBe(30 * 86400);
    expect(body.permissionOptions).toHaveLength(19);
    expect((await database.oauthClient.findUniqueOrThrow({ where: { clientId } })).tinycloudNativeDelegation).toEqual(ceiling);
  });

  test('unset/reinstall keeps the fixture, clears native authority and rejects a late old-epoch row and intent', async () => {
    const old = await database.tinyCloudNativeRequest.findFirstOrThrow({ where: { userId: key.userId, status: 'REDEEMED' } });
    const oldBinding = await database.reviewerAccount.findUniqueOrThrow({ where: { store: 'apple' } });
    const intent = await call('/api/review-account/delete-intent', 'POST', {});
    const oldIntentCookie = intent.headers.get('set-cookie')!.split(';')[0]!;
    await accounts.unsetReviewer(database, 'apple');
    expect(await database.session.count({ where: { userId: key.userId } })).toBe(0);
    expect(await database.tinyCloudNativeGrant.count({ where: { userId: key.userId } })).toBe(0);
    expect(await database.oauthRefreshToken.count({ where: { userId: key.userId } })).toBe(0);
    expect(await database.ethereumKey.count({ where: { id: key.id } })).toBe(1);
    expect(await database.reviewerCleanup.count()).toBe(0);
    const disabled = await database.reviewerAccount.findUniqueOrThrow({ where: { store: 'apple' } });
    expect(disabled.writerExpiresAt).toEqual(oldBinding.writerExpiresAt);
    await accounts.installReviewer(database, 'apple', code);
    await expect(Promise.resolve(database.tinyCloudNativeRequest.create({ data: { ...old, id: randomUUID() } as Prisma.TinyCloudNativeRequestUncheckedCreateInput }))).rejects.toThrow('Reviewer authority ended');
    const stale = await call('/api/review-account/delete', 'POST', { email, code, confirmation: 'DELETE MY ACCOUNT' }, { cookie: oldIntentCookie });
    expect(stale.status).toBe(403);
    expect(await database.user.count({ where: { id: key.userId } })).toBe(1);
  });

  test('sessionless deletion needs fresh code, typed confirmation and single-use intent; retirement retains cleanup key', async () => {
    expect(accounts.reviewerCodeMatches(await accounts.reviewerForEmail(database, email), code)).toBe(true);
    const intent = await call('/api/review-account/delete-intent', 'POST', {});
    expect(intent.status, await intent.clone().text()).toBe(200);
    const intentCookie = intent.headers.get('set-cookie')!.split(';')[0]!;
    expect(intent.headers.get('set-cookie')).toContain('SameSite=Strict');
    expect(intentCookie).not.toContain('session_token');
    const wrong = await call('/api/review-account/delete', 'POST', { email: 'ordinary@tinycloud.test', code, confirmation: 'DELETE MY ACCOUNT' }, { cookie: intentCookie });
    expect(wrong.status).toBe(403);
    expect(await database.user.count({ where: { id: key.userId } })).toBe(1);
    const response = await call('/api/review-account/delete', 'POST', { email, code, confirmation: 'DELETE MY ACCOUNT' }, { cookie: intentCookie });
    expect(response.status, await response.clone().text()).toBe(200);
    expect(await database.user.count({ where: { id: key.userId } })).toBe(0);
    expect(await database.user.count({ where: { id: 'ordinary-home-owner' } })).toBe(1);
    expect(await database.session.count({ where: { userId: key.userId } })).toBe(0);
    const retired = await database.reviewerCleanup.findUniqueOrThrow({ where: { spaceId } });
    expect(retired.sealedBlob).toBe(key.sealedBlob);
    expect(retired.completedAt).toBeNull();
    expect(retired.tombstoneUntil.getTime()).toBeLessThanOrEqual(sourceCreatedAt + 3600_000);
    const replay = await call('/api/review-account/delete', 'POST', { email, code, confirmation: 'DELETE MY ACCOUNT' }, { cookie: intentCookie });
    expect(replay.status).toBe(403);
  });

  test('cleanup mints only a job-private 45-second grant for the retired space and fixed wipe operations', async () => {
    const module = await import('../services/reviewer-cleanup-node');
    expect(Object.keys(module)).toEqual(['reviewerCleanupNode']);
    const { TinyCloudNode } = await import('@tinycloud/node-sdk');
    const original = TinyCloudNode.prototype.useDelegation;
    let grant: any;
    TinyCloudNode.prototype.useDelegation = async function (delegation: any) {
      grant = delegation;
      return { spaceId, kv: { list: async () => ({ ok: true, data: { keys: [] } }) },
        sql: { db: () => ({ query: async () => ({ ok: true, data: { rows: [] } }) }) } } as any;
    };
    try {
      const row = await database.reviewerCleanup.findUniqueOrThrow({ where: { spaceId } });
      await expect(module.reviewerCleanupNode.wipe({ ...row, spaceId: spaceId + '-foreign' })).rejects.toThrow();
      expect(grant).toBeUndefined();
      const started = Date.now();
      expect(await module.reviewerCleanupNode.wipe(row)).toBeUndefined();
      expect(grant.expiry.getTime() - started).toBeLessThanOrEqual(45_000);
      const expectedSql = ['xyz.tinycloud.tinychat/threads', 'xyz.tinycloud.tinychat/home_feed', 'xyz.tinycloud.tinychat/feed/', 'xyz.tinycloud.tinychat/canvas', 'xyz.tinycloud.tinychat/connectors', 'xyz.tinycloud.tinychat/details', 'xyz.tinycloud.tinychat/summaries', 'xyz.tinycloud.tinychat/transcripts', 'xyz.tinycloud.sample.healthlog/healthlog', 'xyz.tinycloud.sample.recipes/recipes'];
      const expected = [{ service: 'kv', space: spaceId, path: '', actions: ['tinycloud.kv/del', 'tinycloud.kv/get', 'tinycloud.kv/list'] },
        ...expectedSql.map(path => ({ service: 'sql', space: spaceId, path, actions: ['tinycloud.sql/read', 'tinycloud.sql/schema', 'tinycloud.sql/write'] }))];
      const sorted = (entries: any[]) => entries.map(p => ({ ...p, actions: [...p.actions].sort() })).sort((a, b) => (a.service + a.path).localeCompare(b.service + b.path));
      expect(sorted(grant.resources)).toEqual(sorted(expected));
      expect(await module.reviewerCleanupNode.empty(row)).toBe(false); // TC-2817: no SQL completeness proof.
    } finally { TinyCloudNode.prototype.useDelegation = original; }
  });

  test('final cleanup removes an old-grant write; errors and over-bound expiry retain the key', async () => {
    const row = await database.reviewerCleanup.findUniqueOrThrow({ where: { spaceId } });
    const values = new Set(['first-write']);
    let emptyFails = false;
    const adapter = { wipe: async () => { values.clear(); }, empty: async () => !emptyFails && values.size === 0 };
    await cleanup.runReviewerCleanup(database, adapter);
    expect((await database.reviewerCleanup.findUniqueOrThrow({ where: { id: row.id } })).sealedBlob).not.toBeNull();
    values.add('old-grant-write-after-first-wipe');
    setSystemTime(row.tombstoneUntil.getTime() + 1);
    emptyFails = true;
    await cleanup.runReviewerCleanup(database, adapter);
    expect((await database.reviewerCleanup.findUniqueOrThrow({ where: { id: row.id } })).sealedBlob).not.toBeNull();
    setSystemTime(Date.now() + 60_001);
    emptyFails = false;
    await cleanup.runReviewerCleanup(database, adapter);
    expect(values.size).toBe(0);
    expect((await database.reviewerCleanup.findUniqueOrThrow({ where: { id: row.id } })).sealedBlob).toBeNull();
    const overExpiry = new Date(Date.now() + 7200_000);
    await database.user.create({ data: { id: 'over-bound-owner', email, name: 'Over-bound fixture', emailVerified: true, reviewerHoldAt: new Date() } });
    const overKey = await database.ethereumKey.create({ data: { id: 'over-bound-key', userId: 'over-bound-owner', address: '0x0000000000000000000000000000000000000002', publicKey: '0x2', sealedBlob: 'retained-opaque-test-blob' } });
    await database.reviewerAccount.update({ where: { store: 'apple' }, data: { userId: 'over-bound-owner', keyId: overKey.id, spaceId: `tinycloud:pkh:eip155:1:${overKey.address}:applications`, writerExpiresAt: overExpiry } });
    const over = await database.$transaction(async tx => {
      const binding = await accounts.lockReviewer(tx, 'apple');
      const tombstone = await cleanup.retireReviewerOwner(tx, binding);
      await accounts.holdReviewer(tx, binding);
      await tx.ethereumKey.deleteMany({ where: { userId: binding.userId! } });
      await tx.user.delete({ where: { id: binding.userId! } });
      return tombstone;
    });
    expect(over.boundExceeded).toBe(true);
    expect(over.tombstoneUntil.getTime()).toBe(overExpiry.getTime());
    await cleanup.runReviewerCleanup(database, adapter);
    expect((await database.reviewerCleanup.findUniqueOrThrow({ where: { id: over.id } })).sealedBlob).not.toBeNull();
    setSystemTime();
  });
  test('deletion intent uses the same 3-per-minute Better Auth limiter without verification-table writes', async () => {
    const ctx = await (await import('../auth')).auth.$context;
    const previous = ctx.rateLimit.enabled;
    ctx.rateLimit.enabled = true;
    const before = await database.verification.count();
    try {
      for (let attempt = 0; attempt < 4; attempt++) {
        const response = await call('/api/review-account/delete-intent', 'POST', {}, { 'x-forwarded-for': '192.0.2.77' });
        expect(response.status).toBe(attempt < 3 ? 200 : 429);
      }
      expect(await database.verification.count()).toBe(before);
    } finally { ctx.rateLimit.enabled = previous; }
  });

}
