import './tc1777-test-env';
import { afterAll, beforeAll, expect, test, setSystemTime } from 'bun:test';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { generateCodeChallenge } from 'better-auth/oauth2';
import { decodeJwt } from 'jose';
import type { PrismaClient } from '@openkey/db';

// The provider stamps a token's iat from one clock read and asks for the reviewer's capped lifetime later; the refresh
// token's lifetime is read only after the native code exchange has run its database work. This test makes a second
// boundary fall inside that work, which is where wall time passes on a slow machine, and checks that the refresh token
// issued for an Apple reviewer is still valid one second before the source session's deadline.
const root = resolve(import.meta.dir, '../../../..');
if (!process.env.OPENKEY_APPLE_TOKEN_SECOND_TEST_CHILD) {
  test('Apple reviewer token lifetimes across a second boundary through the real provider', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], { cwd: root, env: {
      ...process.env, OPENKEY_APPLE_TOKEN_SECOND_TEST_CHILD: '1', APPLE_REVIEW_ENABLED: 'true', NODE_ENV: 'test', TEE_MODE: 'development',
      BETTER_AUTH_URL: 'https://api.openkey.test', BETTER_AUTH_SECRET: 'apple-token-second-test-secret-0123456789012345',
      WEBAUTHN_RP_ID: 'openkey.test', WEBAUTHN_ORIGIN: 'https://openkey.test', CORS_ORIGIN: 'https://openkey.test',
      ADMIN_API_KEY: 'isolated-apple-token-second-test-admin', RESEND_API_KEY: '', GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '',
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
  let policy: typeof import('../services/reviewer-apple-policy');
  let spaceId: string;
  const originalFetch = globalThis.fetch;
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
    directory = await mkdtemp('/var/tmp/tc3828-apple-db.');
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
    policy = await import('../services/reviewer-apple-policy');
    await database.oauthClient.create({ data: { id: randomUUID(), clientId, name: 'Home fixture', public: true, type: 'native', tokenEndpointAuthMethod: 'none', redirectUris: [redirect], scopes: ['openid', 'email', 'offline_access', 'tinycloud:delegation'], contacts: [], tinycloudNativeDelegation: ceiling } });
    await database.user.create({ data: { id: 'apple-review-owner', email, name: 'App review', emailVerified: true, reviewerHoldAt: new Date() } });
    const tee = await import('@openkey/tee');
    const privateKey = tee.generatePrivateKey();
    const address = tee.getAddressFromPrivateKey(privateKey);
    const sealingContext = (await import('../services/key-sealing')).createSealingContext();
    const key = await database.ethereumKey.create({ data: { id: 'apple-review-key', userId: 'apple-review-owner', address, publicKey: address,
      sealingContext, sealedBlob: await tee.seal(privateKey, await tee.createTeeClient().deriveKey('openkey/key/' + sealingContext)), isCanonicalTinyCloud: true } });
    spaceId = `tinycloud:pkh:eip155:1:${address}:applications`;
    await database.reviewerAccount.update({ where: { store: 'apple' }, data: { userId: 'apple-review-owner', keyId: key.id, spaceId, clientId, redirectUri: redirect, nodeHost: host, seededAt: new Date() } });
    await database.tinyCloudBootstrapState.create({ data: { userId: 'apple-review-owner', keyId: key.id, address, chainId: 1, tinycloudHost: host,
      bootstrapVersion: 'test', status: 'complete', checkedAt: new Date(), completedAt: new Date() } });
    globalThis.fetch = ((input: RequestInfo | URL) => {
      if (String(input) === host + '/delegate') return Promise.resolve(Response.json({ activated: [spaceId] }));
      return Promise.reject(new Error('External network disabled in Apple reviewer test'));
    }) as typeof fetch;
    await (await import('../services/reviewer-accounts')).installReviewer(database, 'apple', code);
  }, 90_000);
  afterAll(async () => { setSystemTime(); globalThis.fetch = originalFetch; await database?.$disconnect(); if (directory) await rm(directory, { recursive: true, force: true }); });

  test('a second boundary between iat and the refresh lifetime leaves the refresh token valid at source age 3599 s', async () => {
    const verifier = randomBytes(32).toString('base64url');
    const par = await form('/api/auth/oauth2/par', { client_id: clientId, response_type: 'code', redirect_uri: redirect, state: randomUUID(),
      code_challenge: await generateCodeChallenge(verifier), code_challenge_method: 'S256', scope: 'openid email offline_access tinycloud:delegation',
      login_method: 'email', login_hint: email, authorization_details: JSON.stringify([{ type: 'tinycloud_delegation', session_key: jwk, permissions: policy.REVIEWER_HOME_PERMISSIONS, ttl_seconds: 3600 }]) });
    expect(par.status, await par.clone().text()).toBe(201);
    const requestUri = (await par.json() as any).request_uri;
    const requestId = requestUri.split(':').at(-1);
    const start = await call('/api/auth/oauth2/authorize?' + new URLSearchParams({ client_id: clientId, request_uri: requestUri }));
    const query = new URL(start.headers.get('location')!).searchParams.toString();
    const login = await call('/api/auth/sign-in/email-otp', 'POST', { email, otp: code, oauth_query: query });
    expect(login.status, await login.clone().text()).toBe(200);
    const cookie = login.headers.get('set-cookie')!.split(';')[0]!;
    const consentRedirect = await app.fetch(new Request((await login.json() as any).url, { headers: { cookie } }));
    expect(consentRedirect.status, await consentRedirect.clone().text()).toBe(302);
    const consentQuery = new URL(consentRedirect.headers.get('location')!).searchParams.toString();
    const prepare = await call(`/api/oauth/tinycloud/requests/${requestId}/prepare`, 'POST', {}, { cookie });
    expect(prepare.status, await prepare.clone().text()).toBe(200);
    const preview = await prepare.json() as any;
    const approved = await call(`/api/oauth/tinycloud/requests/${requestId}/approve`, 'POST', { revision: preview.revision, digest: preview.digest, sessionSiwe: preview.sessionSiwe }, { cookie });
    expect(approved.status, await approved.clone().text()).toBe(200);
    const consent = await call('/api/auth/oauth2/consent', 'POST', { accept: true, oauth_query: consentQuery }, { cookie });
    expect(consent.status, await consent.clone().text()).toBe(200);
    const authCode = new URL((await consent.json() as any).url).searchParams.get('code')!;

    // Stop the clock on the last millisecond of a second, so the provider's iat is that second, and let it tick
    // into the next second while the token request does its own work, before any token is created.
    const options = (await import('../auth')).auth.options.plugins.find((plugin: { id: string }) => plugin.id === 'oauth-provider')!.options as any;
    const customTokenResponseFields = options.customTokenResponseFields;
    let ticked = false;
    options.customTokenResponseFields = async (...args: unknown[]) => {
      const fields = await customTokenResponseFields(...args);
      setSystemTime(Date.now() + 1);
      ticked = true;
      return fields;
    };
    const iat = Math.floor(Date.now() / 1000) + 1;
    setSystemTime(iat * 1000 + 999);
    let exchange: Response;
    try {
      exchange = await form('/api/auth/oauth2/token', { grant_type: 'authorization_code', code: authCode, client_id: clientId, redirect_uri: redirect, code_verifier: verifier }, { 'OpenKey-Session-Proof': proof(authCode, '/oauth2/token') });
    } finally { options.customTokenResponseFields = customTokenResponseFields; }
    expect(ticked).toBe(true);
    expect(exchange.status, await exchange.clone().text()).toBe(200);
    const tokens = await exchange.json() as any;

    const binding = await database.reviewerAccount.findUniqueOrThrow({ where: { store: 'apple' } });
    const source = await database.session.findUniqueOrThrow({ where: { id: binding.grantSessionId! } });
    const deadline = source.createdAt.getTime() + 3600_000;
    const deadlineSecond = Math.floor(deadline / 1000);
    const refreshRow = await database.oauthRefreshToken.findFirstOrThrow({ where: { userId: binding.userId!, revoked: null } });
    const accessRow = await database.oauthAccessToken.findFirstOrThrow({ where: { userId: binding.userId! } });

    try {
      for (const seconds of [3599, 3600]) {
        setSystemTime(source.createdAt.getTime() + seconds * 1000);
        const renew = await form('/api/auth/oauth2/tinycloud/renew', { client_id: clientId, refresh_token: tokens.refresh_token }, { 'OpenKey-Session-Proof': proof(tokens.refresh_token, '/oauth2/tinycloud/renew'), ...(seconds === 3599 ? { cookie } : {}) });
        expect(renew.status, seconds + ': ' + await renew.clone().text()).toBe(seconds === 3599 ? 200 : 400);
        if (renew.ok) tokens.refresh_token = (await renew.json() as any).refresh_token;
      }
    } finally { setSystemTime(); }
    // exp = min(deadline, iat + lifetime) in whole seconds, wherever the second ticked.
    expect(refreshRow.createdAt.getTime()).toBe(iat * 1000);
    expect(refreshRow.expiresAt.getTime()).toBe(deadlineSecond * 1000);
    expect(accessRow.expiresAt!.getTime()).toBeLessThanOrEqual(deadline);
    expect(tokens.expires_at).toBeLessThanOrEqual(deadline / 1000);
    expect(decodeJwt(tokens.id_token).exp!).toBeLessThanOrEqual(deadline / 1000);
  });
}
