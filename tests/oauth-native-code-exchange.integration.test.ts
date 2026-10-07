import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { createHash, generateKeyPairSync, randomUUID, sign, type KeyObject } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { Client } from 'pg';
import { serializeSignedCookie } from 'better-call';
import { generateCodeChallenge } from 'better-auth/oauth2';
import { decodeJwt } from 'jose';
import { SiweMessage } from 'siwe';
import { getAddress, recoverMessageAddress } from 'viem';
import { completeSessionSetup, parseRecapFromSiwe } from '@tinycloud/node-sdk-wasm';
import type * as DatabaseModule from '@openkey/db';
import type * as AuthModule from '../apps/api/src/auth';

// TC-773 O4: native code exchange, proven through the API's public HTTP
// interface (the real Hono app in index.ts) on the tracked migration chain:
// PAR -> authorize -> login -> consent approve -> token with session proof.
// Runs in a fresh process: other API tests replace @openkey/db and Better
// Auth globally.
const backend = process.env.TC773_O4_TEST_CHILD;
const postgresUrl = process.env.OPENKEY_TEST_POSTGRES_URL;
const root = resolve(import.meta.dir, '..');

if (!backend) {
  for (const engine of ['pglite', 'postgres']) {
    test.skipIf(engine === 'postgres' && !postgresUrl)(
      `TC-773 native code exchange (${engine})`,
      async () => {
        const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
          cwd: root,
          env: {
            ...process.env,
            TC773_O4_TEST_CHILD: engine,
            NODE_ENV: 'test',
            TEE_MODE: 'development',
            // Production-shaped: the issuer is the API origin + /api/auth.
            BETTER_AUTH_URL: 'https://api.openkey.test',
            BETTER_AUTH_SECRET: 'tc773-o4-isolated-regression-secret-not-for-production',
            WEBAUTHN_RP_ID: 'openkey.test',
            WEBAUTHN_ORIGIN: 'https://openkey.test',
            CORS_ORIGIN: 'https://openkey.test',
            ADMIN_API_KEY: 'tc773-admin-key',
            RESEND_API_KEY: '',
            GOOGLE_CLIENT_ID: '',
            GOOGLE_CLIENT_SECRET: '',
            TINYCLOUD_SQL_ISOLATED_HOSTS: '',
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
      300_000,
    );
  }
} else {
  const directory = await mkdtemp(join(tmpdir(), 'openkey-tc773-o4-'));
  const databaseName = `tc773_o4_${randomUUID().replaceAll('-', '')}`;
  let admin: Client | undefined;
  let connectionString: string;
  let prisma: DatabaseModule.PrismaClient;
  let auth: typeof AuthModule.auth;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let cookie: string;
  let nativeClient: string;
  let canonicalAddress: string;

  const API = 'https://api.openkey.test';
  const ISSUER = `${API}/api/auth`;
  const WEB_ORIGIN = 'https://openkey.test';
  const NATIVE_REDIRECT = 'xyz.tinycloud.exo://openkey/callback';
  const DELEGATION = 'tinycloud:delegation';
  const SCOPE = `openid offline_access ${DELEGATION}`;
  const HOST = 'https://tee.node.tinycloud.xyz';
  const alice = 'tc773-alice';
  const ceiling = {
    version: 1,
    appId: 'xyz.tinycloud.tinychat',
    tinycloudHost: HOST,
    kv: {
      paths: ['xyz.tinycloud.tinychat/threads/', 'xyz.tinycloud.tinychat/connectors/'],
      actions: ['get', 'put', 'list', 'del', 'metadata'],
    },
    sql: null,
    maxDelegationTtlSeconds: 3600,
  };
  const permissions = [
    { service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] },
    { service: 'tinycloud.kv', space: 'applications', path: 'xyz.tinycloud.tinychat/threads/', actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] },
  ];

  const hash = (value: string) => createHash('sha256').update(value).digest('base64url');
  const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

  /** did:key for an Ed25519 public key: base58btc(0xed01 || key). */
  function didKey(x: string) {
    const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    const bytes = [0xed, 0x01, ...Buffer.from(x, 'base64url')];
    let value = BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
    let encoded = '';
    while (value > 0n) { encoded = alphabet[Number(value % 58n)] + encoded; value /= 58n; }
    return `did:key:z${encoded}`;
  }

  function call(path: string, init: RequestInit = {}) {
    return app.fetch(new Request(`${API}${path}`, init));
  }

  function json(path: string, body: unknown, headers: Record<string, string> = {}) {
    return call(path, { method: 'POST', headers: { origin: WEB_ORIGIN, 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
  }

  function form(path: string, body: URLSearchParams, headers: Record<string, string> = {}) {
    return call(path, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, body: body.toString() });
  }

  interface SessionKey { privateKey: KeyObject; publicJwk: { kty: 'OKP'; crv: 'Ed25519'; x: string }; jkt: string }

  function sessionKey(): SessionKey {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const { x } = publicKey.export({ format: 'jwk' }) as { x: string };
    return {
      privateKey,
      publicJwk: { kty: 'OKP', crv: 'Ed25519', x },
      jkt: hash(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x })),
    };
  }

  type ProofClaims = { jti: string; iat: number; htm: string; htu: string; client_id: string; cred_hash: string };
  function proof(key: SessionKey, code: string, overrides: {
    header?: Record<string, unknown>;
    claims?: Partial<ProofClaims> & Record<string, unknown>;
    signer?: KeyObject;
  } = {}) {
    const header = b64({ typ: 'openkey-session-proof+jwt', alg: 'EdDSA', kid: key.jkt, ...overrides.header });
    const payload = b64({
      jti: randomUUID().replaceAll('-', ''), iat: Math.floor(Date.now() / 1000), htm: 'POST',
      htu: `${ISSUER}/oauth2/token`, client_id: nativeClient, cred_hash: hash(code), ...overrides.claims,
    });
    const signature = sign(null, Buffer.from(`${header}.${payload}`), overrides.signer ?? key.privateKey).toString('base64url');
    return `${header}.${payload}.${signature}`;
  }

  function exchange(code: string, verifier: string, sessionProof?: string, overrides: Record<string, string> = {}) {
    return form('/api/auth/oauth2/token', new URLSearchParams({
      grant_type: 'authorization_code', code, client_id: nativeClient, redirect_uri: NATIVE_REDIRECT, code_verifier: verifier, ...overrides,
    }), sessionProof === undefined ? {} : { 'OpenKey-Session-Proof': sessionProof });
  }

  async function oauthError(response: Response) {
    return await response.json() as { error?: string; error_description?: string };
  }

  async function ensureCanonicalKey() {
    const existing = await prisma.ethereumKey.findFirst({ where: { userId: alice, isCanonicalTinyCloud: true, archivedAt: null } });
    if (existing) return existing;
    const { createTeeClient, generatePrivateKey, getAddressFromPrivateKey, seal } = await import('@openkey/tee');
    const privateKey = generatePrivateKey();
    const address = getAddressFromPrivateKey(privateKey);
    const sealingContext = randomUUID().replaceAll('-', '').padEnd(43, 'A').slice(0, 43);
    const sealingKey = await createTeeClient().deriveKey(`openkey/key/${sealingContext}`);
    return prisma.ethereumKey.create({ data: { id: 'tc773-native-key', userId: alice, address, publicKey: '0x1',
      sealedBlob: await seal(privateKey, sealingKey), sealingContext, keyType: 'MANAGED', isCanonicalTinyCloud: true } });
  }

  /** PAR, then authorize with the request_uri. */
  async function par(key: SessionKey, ttlSeconds = 3600) {
    const verifier = `tc773-o4-verifier-${randomUUID()}-${randomUUID()}`;
    const state = randomUUID();
    const response = await form('/api/auth/oauth2/par', new URLSearchParams({
      client_id: nativeClient, response_type: 'code', redirect_uri: NATIVE_REDIRECT, state,
      code_challenge: await generateCodeChallenge(verifier), code_challenge_method: 'S256', scope: SCOPE,
      authorization_details: JSON.stringify([{ type: 'tinycloud_delegation', session_key: key.publicJwk, permissions, ttl_seconds: ttlSeconds }]),
    }));
    expect(response.status, await response.clone().text()).toBe(201);
    const { request_uri } = await response.json() as { request_uri: string };
    return { verifier, state, requestUri: request_uri, requestId: request_uri.split(':').at(-1)! };
  }

  /** Prepare, approve, and provider consent; returns the callback. */
  async function approve(requestId: string, consentQuery: string, userCookie = cookie) {
    const prepare = await json(`/api/oauth/tinycloud/requests/${requestId}/prepare`, {}, { cookie: userCookie });
    expect(prepare.status, await prepare.clone().text()).toBe(200);
    const preview = await prepare.json() as { revision: number; digest: string; sessionSiwe: string; hostPlan: { hostSiwe: string } | null };
    const approved = await json(`/api/oauth/tinycloud/requests/${requestId}/approve`, {
      revision: preview.revision, digest: preview.digest, sessionSiwe: preview.sessionSiwe, hostSiwe: preview.hostPlan?.hostSiwe,
    }, { cookie: userCookie });
    expect(approved.status, await approved.clone().text()).toBe(200);
    const consent = await json('/api/auth/oauth2/consent', { accept: true, oauth_query: consentQuery }, { cookie: userCookie });
    expect(consent.status, await consent.clone().text()).toBe(200);
    return new URL((await consent.json() as { url: string }).url);
  }

  /** A signed-in flow up to an issued code (session cookie already present). */
  async function approvedCode(key = sessionKey(), ttlSeconds = 3600, authorizeParams: Record<string, string> = {}) {
    const request = await par(key, ttlSeconds);
    const authorize = await call(`/api/auth/oauth2/authorize?${new URLSearchParams({ client_id: nativeClient, request_uri: request.requestUri, ...authorizeParams })}`, { headers: { cookie } });
    expect(authorize.status, await authorize.clone().text()).toBe(302);
    const consentUrl = new URL(authorize.headers.get('location')!);
    expect(consentUrl.pathname).toBe('/oauth/consent');
    const callback = await approve(request.requestId, consentUrl.searchParams.toString());
    const code = callback.searchParams.get('code')!;
    expect(code).toBeTruthy();
    return { ...request, key, code, callback };
  }

  /**
   * Replaces an issued code with a forged one whose stored query is mutated:
   * the shape social sign-in's after-hook could store without the guard.
   */
  async function forgeCode(code: string, mutate: (query: Record<string, unknown>) => void) {
    const row = await prisma.verification.findFirstOrThrow({ where: { identifier: hash(code) } });
    const value = JSON.parse(row.value) as { query: Record<string, unknown> };
    mutate(value.query);
    const forged = `forged${randomUUID().replaceAll('-', '')}`;
    await prisma.verification.delete({ where: { id: row.id } });
    await prisma.verification.create({ data: { id: randomUUID(), identifier: hash(forged), value: JSON.stringify(value), expiresAt: row.expiresAt } });
    return forged;
  }

  async function requestStatus(id: string) {
    return (await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id } })).status;
  }

  /** The failed exchange spent the code and changed nothing else. */
  async function expectSpentWithoutRedemption(flow: Awaited<ReturnType<typeof approvedCode>>, code = flow.code) {
    expect(await requestStatus(flow.requestId)).toBe('APPROVED');
    expect(await prisma.tinyCloudNativeGrant.count()).toBe(0);
    expect(await prisma.oauthRefreshToken.count()).toBe(0);
    expect(await prisma.oauthAccessToken.count()).toBe(0);
    const retry = await exchange(code, flow.verifier, proof(flow.key, code));
    expect(retry.status).toBe(401);
    expect((await oauthError(retry)).error).toBe('invalid_verification');
  }

  const originalFetch = globalThis.fetch;

  beforeAll(async () => {
    const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
    if (backend === 'postgres') {
      if (!postgresUrl) throw new Error('OPENKEY_TEST_POSTGRES_URL is required for PostgreSQL coverage');
      // Never migrate the supplied database; all data lives in a disposable one.
      admin = new Client({ connectionString: postgresUrl });
      await admin.connect();
      await admin.query(`CREATE DATABASE "${databaseName}"`);
      const target = new URL(postgresUrl);
      target.pathname = `/${databaseName}`;
      connectionString = target.toString();
      const migrationConnection = new Client({ connectionString });
      await migrationConnection.connect();
      try {
        for (const migration of migrations) {
          await migrationConnection.query(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
        }
      } finally {
        await migrationConnection.end();
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
    // Route singletons capture DATABASE_URL on import, so the app loads only
    // after the disposable database exists.
    const { createPrismaClient } = await import('@openkey/db');
    prisma = createPrismaClient();
    ({ auth } = await import('../apps/api/src/auth'));
    app = (await import('../apps/api/src/index')).default;

    await prisma.user.create({ data: { id: alice, email: 'test@openkey.dev', name: 'Alice', emailVerified: true } });
    const sessionToken = randomUUID();
    await prisma.session.create({ data: {
      id: 'tc773-o4-session', token: sessionToken, userId: alice, expiresAt: new Date(Date.now() + 3_600_000),
    } });
    const context = await auth.$context;
    cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, sessionToken, context.secret)).split(';')[0]!;

    const native = await call('/api/admin/oauth/clients', {
      method: 'POST',
      headers: { authorization: 'Bearer tc773-admin-key', 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Exo native', type: 'native', redirectUris: [NATIVE_REDIRECT], tinycloudNativeDelegation: ceiling }),
    });
    expect(native.status).toBe(201);
    nativeClient = (await native.json() as { client: { clientId: string } }).client.clientId;
    canonicalAddress = getAddress((await ensureCanonicalKey()).address);

    // The configured node: the space already exists, so no hosting signature.
    globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.startsWith(`${HOST}/peer/generate/`)) return Promise.resolve(new Response('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'));
      if (url === `${HOST}/delegate`) return Promise.resolve(Response.json({ activated: [`tinycloud:pkh:eip155:1:${canonicalAddress}:applications`] }));
      return originalFetch(input, init);
    }) as typeof fetch;
  }, 120_000);

  afterAll(async () => {
    globalThis.fetch = originalFetch;
    await prisma?.$disconnect();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
      await admin.end();
    }
    await rm(directory, { recursive: true, force: true });
  });

  // TRUNCATE fires no row triggers, so resetting never touches generations.
  beforeEach(async () => {
    await prisma.$executeRawUnsafe(`TRUNCATE TABLE "oauth_refresh_token", "oauth_access_token", "oauth_consent",
      "tinycloud_native_grant", "tinycloud_native_request", "tinycloud_native_consent_generation", "verification" CASCADE`);
  });

  test(`PAR -> authorize -> login -> consent -> token with proof, through HTTP (${backend})`, async () => {
    const metadata = await (await call('/.well-known/oauth-authorization-server/api/auth')).json() as Record<string, string>;
    expect(metadata.issuer).toBe(ISSUER);
    expect(metadata.token_endpoint).toBe(`${ISSUER}/oauth2/token`);
    expect(metadata.authorization_response_iss_parameter_supported).toBe(true as unknown as string);

    const key = sessionKey();
    const request = await par(key);
    const first = await call(`/api/auth/oauth2/authorize?${new URLSearchParams({ client_id: nativeClient, request_uri: request.requestUri })}`);
    expect(first.status, await first.clone().text()).toBe(302);
    const login = new URL(first.headers.get('location')!);
    expect(login.origin + login.pathname).toBe(`${WEB_ORIGIN}/auth/login`);
    const signed = login.searchParams.toString();

    // Login: email OTP, with the signed authorize envelope verified.
    const otp = await json('/api/auth/email-otp/send-verification-otp', { email: 'test@openkey.dev', type: 'sign-in' });
    expect(otp.status, await otp.clone().text()).toBe(200);
    const signIn = await json('/api/auth/sign-in/email-otp', { email: 'test@openkey.dev', otp: '000000', oauth_query: signed });
    expect(signIn.status, await signIn.clone().text()).toBe(200);
    const sessionCookie = signIn.headers.getSetCookie().find((value) => value.includes('session_token='))!.split(';')[0]!;

    const reentry = await call(`/api/auth/oauth2/authorize?${signed}`, { headers: { cookie: sessionCookie } });
    expect(reentry.status, await reentry.clone().text()).toBe(302);
    const consentUrl = new URL(reentry.headers.get('location')!);
    expect(consentUrl.pathname).toBe('/oauth/consent');
    const callback = await approve(request.requestId, consentUrl.searchParams.toString(), sessionCookie);

    // RFC 9207 callback: production-shaped issuer.
    expect(`${callback.protocol}//${callback.host}${callback.pathname}`).toBe(NATIVE_REDIRECT);
    expect(callback.searchParams.get('state')).toBe(request.state);
    expect(callback.searchParams.get('iss')).toBe(ISSUER);
    const code = callback.searchParams.get('code')!;

    const response = await exchange(code, request.verifier, proof(key, code, { claims: { htu: metadata.token_endpoint } }));
    expect(response.status, await response.clone().text()).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    const body = await response.json() as Record<string, unknown> & {
      tinycloud_delegation: Record<string, unknown> & {
        siwe: string; signature: `0x${string}`; spaceId: string; verificationMethod: string; grantId: string;
        delegationHeader: { Authorization: string }; delegationCid: string; issuedAt: string; expiresAt: string; renewableUntil: string;
      };
    };

    expect(body.token_type).toBe('Bearer');
    expect(body.expires_in).toBe(300);
    expect(typeof body.expires_at).toBe('number');
    expect(typeof body.access_token).toBe('string');
    expect(typeof body.refresh_token).toBe('string');
    expect(body.scope).toBe(SCOPE);
    expect(decodeJwt(body.id_token as string).iss).toBe(ISSUER);
    expect(body.authorization_details).toEqual([{ type: 'tinycloud_delegation', session_key: key.publicJwk, permissions, ttl_seconds: 3600 }]);

    const delegation = body.tinycloud_delegation;
    const requestRow = await prisma.tinyCloudNativeRequest.findUniqueOrThrow({ where: { id: request.requestId } });
    expect(Object.keys(delegation).sort()).toEqual([
      'address', 'chainId', 'delegationCid', 'delegationHeader', 'expiresAt', 'grantId', 'hosting', 'issuedAt', 'ownerDid',
      'permissions', 'renewableUntil', 'signature', 'siwe', 'spaceId', 'tinycloudHost', 'verificationMethod', 'version',
    ]);
    expect(delegation).toMatchObject({
      version: 1, address: canonicalAddress, chainId: 1, ownerDid: `did:pkh:eip155:1:${canonicalAddress}`,
      spaceId: `tinycloud:pkh:eip155:1:${canonicalAddress}:applications`, permissions, tinycloudHost: HOST, hosting: 'existing',
    });
    // The session did:key, derived here from the public key, as the DID URL
    // TinyCloud uses for the session verification method.
    const did = didKey(key.publicJwk.x);
    const sessionVerificationMethod = `${did}#${did.slice('did:key:'.length)}`;
    expect(requestRow.sessionDid).toBe(sessionVerificationMethod);
    expect(delegation.verificationMethod).toBe(sessionVerificationMethod);
    expect(Date.parse(delegation.expiresAt) - Date.parse(delegation.issuedAt)).toBe(3_600_000);

    // The signed session SIWE.
    expect(await recoverMessageAddress({ message: delegation.siwe, signature: delegation.signature })).toBe(canonicalAddress);
    const siwe = new SiweMessage(delegation.siwe);
    expect(siwe.address).toBe(canonicalAddress);
    expect(siwe.uri).toBe(sessionVerificationMethod);
    expect(siwe.domain).toBe('openkey.so');
    expect(siwe.chainId).toBe(1);
    expect(siwe.issuedAt).toBe(delegation.issuedAt);
    expect(siwe.expirationTime).toBe(delegation.expiresAt);
    const recap = (parseRecapFromSiwe(delegation.siwe) as { service: string; space: string; path: string; actions: string[] }[])
      .map((entry) => ({ service: entry.service.startsWith('tinycloud.') ? entry.service : `tinycloud.${entry.service}`, path: entry.path, actions: [...entry.actions].sort() }))
      .sort((a, b) => a.service.localeCompare(b.service));
    expect(recap).toEqual(permissions.map((entry) => ({ service: entry.service, path: entry.path, actions: [...entry.actions].sort() })));
    const rebuilt = completeSessionSetup({
      siwe: delegation.siwe, signature: delegation.signature, jwk: key.publicJwk,
      spaceId: delegation.spaceId, verificationMethod: delegation.verificationMethod,
    }) as { delegationHeader: { Authorization: string }; delegationCid: string };
    expect(rebuilt.delegationHeader).toEqual(delegation.delegationHeader);
    expect(rebuilt.delegationCid).toBe(delegation.delegationCid);

    // Redemption state: request REDEEMED, grant created and linked.
    expect(requestRow.status).toBe('REDEEMED');
    const grant = await prisma.tinyCloudNativeGrant.findUniqueOrThrow({ where: { id: delegation.grantId } });
    const consent = await prisma.oauthConsent.findFirstOrThrow({ where: { userId: alice, clientId: nativeClient } });
    expect(grant).toMatchObject({
      userId: alice, clientId: nativeClient, consentId: consent.id, consentGeneration: 0n, keyId: 'tc773-native-key',
      address: canonicalAddress, sessionDid: requestRow.sessionDid, sessionJkt: key.jkt, spaceId: delegation.spaceId,
      approvedPermissions: permissions, ttlSeconds: 3600, tinycloudHost: HOST, status: 'ACTIVE',
      refreshTokenHash: hash(body.refresh_token as string), previousRefreshTokenHash: null,
    });
    expect(grant.sessionJwk).toEqual(key.publicJwk);
    expect(Math.abs(grant.absoluteExpiresAt.getTime() - (Date.now() + 30 * 86_400_000))).toBeLessThan(60_000);
    expect(Date.parse(delegation.renewableUntil)).toBe(grant.absoluteExpiresAt.getTime() - 300_000);
    const refreshRow = await prisma.oauthRefreshToken.findFirstOrThrow({ where: { token: hash(body.refresh_token as string) } });
    expect(refreshRow).toMatchObject({ clientId: nativeClient, userId: alice, revoked: null });
    expect(refreshRow.scopes).toEqual(SCOPE.split(' '));

    // Double redemption: the provider already spent the code.
    const replay = await exchange(code, request.verifier, proof(key, code));
    expect(replay.status).toBe(401);
    expect((await oauthError(replay)).error).toBe('invalid_verification');
    expect(await prisma.tinyCloudNativeGrant.count()).toBe(1);
  }, 120_000);

  describe(`code exchange failures (${backend})`, () => {
    test('missing, malformed, foreign-key, stale and misbound proofs get 401 invalid_session_proof', async () => {
      const other = sessionKey();
      const variants: [string, (flow: Awaited<ReturnType<typeof approvedCode>>) => string | undefined][] = [
        ['missing', () => undefined],
        ['empty', () => ''],
        ['malformed', () => 'not.a.jws'],
        ['two proofs', (flow) => `${proof(flow.key, flow.code)}, ${proof(flow.key, flow.code)}`],
        ['signed by another key with the stored kid', (flow) => proof(flow.key, flow.code, { signer: other.privateKey })],
        ['another key and its own kid', (flow) => proof(other, flow.code)],
        ['tampered signature', (flow) => {
          const [header, payload] = proof(flow.key, flow.code).split('.');
          const forged = proof(flow.key, flow.code, { claims: { client_id: 'other' } }).split('.')[2];
          return `${header}.${payload}.${forged}`;
        }],
        ['stale iat', (flow) => proof(flow.key, flow.code, { claims: { iat: Math.floor(Date.now() / 1000) - 61 } })],
        ['future iat', (flow) => proof(flow.key, flow.code, { claims: { iat: Math.floor(Date.now() / 1000) + 61 } })],
        ['wrong htu', (flow) => proof(flow.key, flow.code, { claims: { htu: `${ISSUER}/oauth2/tinycloud/renew` } })],
        ['origin-relative htu', (flow) => proof(flow.key, flow.code, { claims: { htu: `${API}/oauth2/token` } })],
        ['wrong htm', (flow) => proof(flow.key, flow.code, { claims: { htm: 'GET' } })],
        ['wrong client_id', (flow) => proof(flow.key, flow.code, { claims: { client_id: 'other-client' } })],
        ['cred_hash of another code', (flow) => proof(flow.key, 'another-code')],
        ['short jti', (flow) => proof(flow.key, flow.code, { claims: { jti: 'short' } })],
        ['extra claim', (flow) => proof(flow.key, flow.code, { claims: { scope: 'openid' } })],
        ['wrong typ', (flow) => proof(flow.key, flow.code, { header: { typ: 'JWT' } })],
        ['wrong alg', (flow) => proof(flow.key, flow.code, { header: { alg: 'ES256' } })],
      ];
      for (const [name, build] of variants) {
        await prisma.$executeRawUnsafe('TRUNCATE TABLE "tinycloud_native_request", "verification" CASCADE');
        const flow = await approvedCode();
        const response = await exchange(flow.code, flow.verifier, build(flow));
        expect(response.status, name).toBe(401);
        expect(await oauthError(response), name).toEqual({ error: 'invalid_session_proof', error_description: 'missing or invalid OpenKey-Session-Proof' });
        await expectSpentWithoutRedemption(flow);
      }
    }, 240_000);

    test('a proof inside the ±60 s window is accepted', async () => {
      const flow = await approvedCode();
      const response = await exchange(flow.code, flow.verifier, proof(flow.key, flow.code, { claims: { iat: Math.floor(Date.now() / 1000) - 55 } }));
      expect(response.status, await response.clone().text()).toBe(200);
    }, 60_000);

    test('two codes bound to one approved request: exactly one redemption succeeds', async () => {
      const flow = await approvedCode();
      const row = await prisma.verification.findFirstOrThrow({ where: { identifier: hash(flow.code) } });
      const twin = `twin${randomUUID().replaceAll('-', '')}`;
      await prisma.verification.create({ data: { id: randomUUID(), identifier: hash(twin), value: row.value, expiresAt: row.expiresAt } });
      const responses = await Promise.all([flow.code, twin].map((code) => exchange(code, flow.verifier, proof(flow.key, code))));
      const statuses = responses.map((response) => response.status).sort();
      expect(statuses).toEqual([200, 400]);
      const loser = responses.find((response) => response.status === 400)!;
      expect((await oauthError(loser)).error).toBe('invalid_grant');
      expect(await requestStatus(flow.requestId)).toBe('REDEEMED');
      expect(await prisma.tinyCloudNativeGrant.count()).toBe(1);
      expect(await prisma.oauthRefreshToken.count()).toBe(1);
    }, 60_000);

    test('delete consent -> re-consent: codes approved under the old consent fail', async () => {
      const withdrawn = await approvedCode();
      const forcedBack = await approvedCode();
      const consent = await prisma.oauthConsent.findFirstOrThrow({ where: { userId: alice, clientId: nativeClient } });
      const deleted = await json('/api/auth/oauth2/delete-consent', { id: consent.id }, { cookie });
      expect(deleted.status, await deleted.clone().text()).toBe(200);
      expect(await requestStatus(withdrawn.requestId)).toBe('WITHDRAWN');
      expect(await requestStatus(forcedBack.requestId)).toBe('WITHDRAWN');

      // Re-consent through a new authorization: a new consent row and generation.
      const fresh = await approvedCode();
      expect(await prisma.oauthConsent.count({ where: { userId: alice, clientId: nativeClient } })).toBe(1);

      const old = await exchange(withdrawn.code, withdrawn.verifier, proof(withdrawn.key, withdrawn.code));
      expect(old.status).toBe(400);
      expect((await oauthError(old)).error).toBe('invalid_grant');

      // Even an approved status cannot attach the old generation to the new consent.
      await prisma.tinyCloudNativeRequest.update({ where: { id: forcedBack.requestId }, data: { status: 'APPROVED' } });
      const generationChanged = await exchange(forcedBack.code, forcedBack.verifier, proof(forcedBack.key, forcedBack.code));
      expect(generationChanged.status).toBe(400);
      expect((await oauthError(generationChanged)).error).toBe('invalid_grant');
      expect(await requestStatus(forcedBack.requestId)).toBe('APPROVED');
      expect(await prisma.tinyCloudNativeGrant.count()).toBe(0);

      const current = await exchange(fresh.code, fresh.verifier, proof(fresh.key, fresh.code));
      expect(current.status, await current.clone().text()).toBe(200);
      const grant = await prisma.tinyCloudNativeGrant.findFirstOrThrow();
      expect(grant.consentGeneration).toBe(1n);
      expect(grant.consentId).not.toBe(consent.id);
    }, 120_000);

    test('a missing consent or a consent without the delegation scope fails', async () => {
      const flow = await approvedCode();
      // Bypass the withdrawal trigger's request update, to reach the consent check itself.
      await prisma.$executeRawUnsafe(`ALTER TABLE "oauth_consent" DISABLE TRIGGER USER`);
      try {
        await prisma.oauthConsent.updateMany({ where: { userId: alice, clientId: nativeClient }, data: { scopes: ['openid', 'offline_access'] } });
      } finally {
        await prisma.$executeRawUnsafe(`ALTER TABLE "oauth_consent" ENABLE TRIGGER USER`);
      }
      const response = await exchange(flow.code, flow.verifier, proof(flow.key, flow.code));
      expect(response.status).toBe(400);
      expect(await oauthError(response)).toEqual({ error: 'invalid_grant', error_description: 'consent is missing or withdrawn' });
      await expectSpentWithoutRedemption(flow);
    }, 60_000);

    test('a mismatched redirect, state, challenge, scope or request reference fails', async () => {
      const redirect = await approvedCode();
      const wrongRedirect = await exchange(redirect.code, redirect.verifier, proof(redirect.key, redirect.code), { redirect_uri: 'xyz.tinycloud.exo://other' });
      expect(wrongRedirect.status).toBe(400);
      expect((await oauthError(wrongRedirect)).error).toBe('invalid_request');
      await expectSpentWithoutRedemption(redirect);

      // Codes whose stored query no longer matches the request row: the
      // shape social sign-in's after-hook could store without the guard.
      const otherVerifier = `tc773-o4-other-verifier-${randomUUID()}-${randomUUID()}`;
      const otherChallenge = await generateCodeChallenge(otherVerifier);
      const forgeries: [string, (query: Record<string, unknown>) => void, Record<string, string>, string?][] = [
        ['redirect_uri', (query) => { query.redirect_uri = 'xyz.tinycloud.exo://other'; }, { redirect_uri: 'xyz.tinycloud.exo://other' }],
        ['state', (query) => { query.state = 'attacker-state-0123456789'; }, {}],
        ['code_challenge', (query) => { query.code_challenge = otherChallenge; }, {}, otherVerifier],
        ['scope', (query) => { query.scope = `openid ${DELEGATION}`; }, {}],
        ['no request reference', (query) => { delete query.tinycloud_request; }, {}],
        ['empty request reference', (query) => { query.tinycloud_request = ''; query.scope = 'openid offline_access'; }, {}],
        ['unknown request', (query) => { query.tinycloud_request = 'no-such-request'; }, {}],
      ];
      for (const [name, mutate, overrides, verifier] of forgeries) {
        await prisma.$executeRawUnsafe('TRUNCATE TABLE "tinycloud_native_request", "verification" CASCADE');
        const flow = await approvedCode();
        const forged = await forgeCode(flow.code, mutate);
        const response = await exchange(forged, verifier ?? flow.verifier, proof(flow.key, forged), overrides);
        expect(response.status, `${name}: ${await response.clone().text()}`).toBe(400);
        expect((await oauthError(response)).error, name).toBe('invalid_grant');
        expect(await requestStatus(flow.requestId), name).toBe('APPROVED');
        expect(await prisma.tinyCloudNativeGrant.count(), name).toBe(0);
        expect(await prisma.oauthRefreshToken.count(), name).toBe(0);
      }
    }, 240_000);

    test('the delegation may not outlive the new grant', async () => {
      const client = await prisma.oauthClient.findUniqueOrThrow({ where: { clientId: nativeClient } });
      const config = client.tinycloudNativeDelegation as Record<string, unknown>;
      try {
        const long = await approvedCode(sessionKey(), 3600);
        await prisma.oauthClient.update({ where: { clientId: nativeClient }, data: { tinycloudNativeDelegation: { ...config, grantLifetimeSeconds: 300 } } });
        const outlives = await exchange(long.code, long.verifier, proof(long.key, long.code));
        expect(outlives.status).toBe(400);
        expect(await oauthError(outlives)).toEqual({ error: 'invalid_grant', error_description: 'the approved delegation would outlive the grant' });
        await expectSpentWithoutRedemption(long);

        // Approved under the shorter lifetime: capped to 300 s, so it fits.
        const capped = await approvedCode(sessionKey(), 3600);
        const fits = await exchange(capped.code, capped.verifier, proof(capped.key, capped.code));
        expect(fits.status, await fits.clone().text()).toBe(200);
        const body = await fits.json() as { tinycloud_delegation: { issuedAt: string; expiresAt: string; renewableUntil: string } };
        expect(Date.parse(body.tinycloud_delegation.expiresAt) - Date.parse(body.tinycloud_delegation.issuedAt)).toBe(300_000);
        const grant = await prisma.tinyCloudNativeGrant.findFirstOrThrow();
        expect(Date.parse(body.tinycloud_delegation.expiresAt)).toBeLessThanOrEqual(grant.absoluteExpiresAt.getTime());
        expect(Date.parse(body.tinycloud_delegation.renewableUntil)).toBe(grant.absoluteExpiresAt.getTime() - 300_000);
      } finally {
        await prisma.oauthClient.update({ where: { clientId: nativeClient }, data: { tinycloudNativeDelegation: config as object } });
      }
    }, 120_000);

    test('a client whose delegation ceiling was removed fails the exchange', async () => {
      const client = await prisma.oauthClient.findUniqueOrThrow({ where: { clientId: nativeClient } });
      const flow = await approvedCode();
      await prisma.$executeRawUnsafe('UPDATE "oauth_client" SET "tinycloudNativeDelegation" = NULL WHERE "clientId" = $1', nativeClient);
      try {
        const response = await exchange(flow.code, flow.verifier, proof(flow.key, flow.code));
        expect(response.status).toBe(400);
        expect(await oauthError(response)).toEqual({ error: 'invalid_grant', error_description: 'native delegation is no longer enabled for this client' });
        await expectSpentWithoutRedemption(flow);
      } finally {
        await prisma.oauthClient.update({ where: { clientId: nativeClient }, data: { tinycloudNativeDelegation: client.tinycloudNativeDelegation as object } });
      }
    }, 60_000);

    /** No live token of any kind for the native client, and the grant is revoked. */
    async function expectWithdrawnWithoutLiveTokens(flow: Awaited<ReturnType<typeof approvedCode>>, response: Response) {
      expect(response.status, await response.clone().text()).toBe(400);
      expect(await oauthError(response)).toEqual({
        error: 'invalid_grant',
        error_description: 'consent was withdrawn while the tokens were issued; the authorization code is already spent, start a new authorization',
      });
      expect(await prisma.oauthRefreshToken.count({ where: { clientId: nativeClient } })).toBe(0);
      expect(await prisma.oauthAccessToken.count({ where: { clientId: nativeClient } })).toBe(0);
      const grant = await prisma.tinyCloudNativeGrant.findFirstOrThrow();
      expect(grant).toMatchObject({ status: 'REVOKED', revokedReason: 'consent_withdrawn' });
      expect(await requestStatus(flow.requestId)).toBe('REDEEMED');
      const retry = await exchange(flow.code, flow.verifier, proof(flow.key, flow.code));
      expect((await oauthError(retry)).error).toBe('invalid_verification');
    }

    /**
     * Runs `body` with a test-only trigger that withdraws the native consent
     * (through the real withdrawal trigger) at an exact point of the exchange.
     */
    async function withWithdrawalAt(table: string, event: string, when: string, body: () => Promise<void>) {
      await prisma.$executeRawUnsafe(`CREATE FUNCTION tc773_o4_withdraw_now() RETURNS TRIGGER AS $$
        BEGIN
          DELETE FROM "oauth_consent" WHERE "userId" = '${alice}' AND "clientId" = '${nativeClient}';
          RETURN NULL;
        END; $$ LANGUAGE plpgsql`);
      await prisma.$executeRawUnsafe(`CREATE TRIGGER tc773_o4_withdraw_now AFTER ${event} ON "${table}"
        FOR EACH ROW WHEN (${when}) EXECUTE FUNCTION tc773_o4_withdraw_now()`);
      try {
        await body();
      } finally {
        await prisma.$executeRawUnsafe(`DROP TRIGGER tc773_o4_withdraw_now ON "${table}"`);
        await prisma.$executeRawUnsafe('DROP FUNCTION tc773_o4_withdraw_now()');
      }
    }

    test('a withdrawal between grant linking and the refresh-token insert leaves no live token', async () => {
      const flow = await approvedCode();
      await withWithdrawalAt('tinycloud_native_grant', 'UPDATE OF "refreshTokenHash"',
        'OLD."refreshTokenHash" IS NULL AND NEW."refreshTokenHash" IS NOT NULL', async () => {
          await expectWithdrawnWithoutLiveTokens(flow, await exchange(flow.code, flow.verifier, proof(flow.key, flow.code)));
        });
    }, 60_000);

    test('a withdrawal between the refresh-token and access-token inserts leaves no live token', async () => {
      const flow = await approvedCode();
      await withWithdrawalAt('oauth_refresh_token', 'INSERT', `NEW."clientId" = '${nativeClient}'`, async () => {
        await expectWithdrawnWithoutLiveTokens(flow, await exchange(flow.code, flow.verifier, proof(flow.key, flow.code)));
      });
    }, 60_000);

    test.skipIf(backend !== 'postgres')('a concurrent withdrawal after linking: the blocked token insert is refused', async () => {
      const flow = await approvedCode();
      const holder = new Client({ connectionString });
      await holder.connect();
      try {
        // Park the provider's refresh-token INSERT after linking, then withdraw
        // consent from another session while it waits.
        await holder.query('BEGIN');
        await holder.query('LOCK TABLE "oauth_refresh_token" IN SHARE MODE');
        const pending = exchange(flow.code, flow.verifier, proof(flow.key, flow.code));
        const deadline = Date.now() + 10_000;
        while (!(await prisma.tinyCloudNativeGrant.findFirst({ where: { refreshTokenHash: { not: null } } }))) {
          if (Date.now() > deadline) throw new Error('grant was never linked');
          await Bun.sleep(20);
        }
        await holder.query('DELETE FROM "oauth_consent" WHERE "userId" = $1 AND "clientId" = $2', [alice, nativeClient]);
        await holder.query('COMMIT');
        await expectWithdrawnWithoutLiveTokens(flow, await pending);
      } finally {
        await holder.end();
      }
    }, 60_000);

    test.skipIf(backend !== 'postgres')('lock contention while linking the refresh token returns 503 and the code stays spent', async () => {
      const flow = await approvedCode();
      // Any lock wait inside the linking transaction: the test trigger waits
      // for an advisory lock the holder keeps past the 5 s lock_timeout.
      await prisma.$executeRawUnsafe(`CREATE FUNCTION tc773_o4_block_link() RETURNS TRIGGER AS $$
        BEGIN PERFORM pg_advisory_xact_lock(773004); RETURN NEW; END; $$ LANGUAGE plpgsql`);
      await prisma.$executeRawUnsafe(`CREATE TRIGGER tc773_o4_block_link BEFORE UPDATE OF "refreshTokenHash" ON "tinycloud_native_grant"
        FOR EACH ROW EXECUTE FUNCTION tc773_o4_block_link()`);
      const holder = new Client({ connectionString });
      await holder.connect();
      try {
        await holder.query('SELECT pg_advisory_lock(773004)');
        const started = Date.now();
        const response = await exchange(flow.code, flow.verifier, proof(flow.key, flow.code));
        expect(Date.now() - started).toBeLessThan(12_000);
        expect(response.status, await response.clone().text()).toBe(503);
        expect(response.headers.get('retry-after')).toBe('2');
        const body = await oauthError(response);
        expect(body.error).toBe('temporarily_unavailable');
        expect(body.error_description).toContain('cannot be retried');
      } finally {
        await holder.end();
        await prisma.$executeRawUnsafe('DROP TRIGGER tc773_o4_block_link ON "tinycloud_native_grant"');
        await prisma.$executeRawUnsafe('DROP FUNCTION tc773_o4_block_link()');
      }
      // The grant committed by the hook stays unlinked; no token was issued.
      const grant = await prisma.tinyCloudNativeGrant.findFirstOrThrow();
      expect(grant.refreshTokenHash).toBeNull();
      expect(await prisma.oauthRefreshToken.count()).toBe(0);
      expect(await prisma.oauthAccessToken.count()).toBe(0);
      const retry = await exchange(flow.code, flow.verifier, proof(flow.key, flow.code));
      expect((await oauthError(retry)).error).toBe('invalid_verification');
    }, 60_000);

    test.skipIf(backend !== 'postgres')('lock contention returns 503 temporarily_unavailable and the code stays spent', async () => {
      const flow = await approvedCode();
      const holder = new Client({ connectionString });
      await holder.connect();
      try {
        await holder.query('BEGIN');
        await holder.query('SELECT id FROM oauth_consent WHERE "userId" = $1 AND "clientId" = $2 FOR UPDATE', [alice, nativeClient]);
        const response = await exchange(flow.code, flow.verifier, proof(flow.key, flow.code));
        await holder.query('ROLLBACK');
        expect(response.status, await response.clone().text()).toBe(503);
        expect(response.headers.get('retry-after')).toBe('2');
        const body = await oauthError(response);
        expect(body.error).toBe('temporarily_unavailable');
        expect(body.error_description).toContain('cannot be retried');
      } finally {
        await holder.end();
      }
      await expectSpentWithoutRedemption(flow);
    }, 60_000);
  });

  // A `resource` makes the provider issue a JWT access token, which has no
  // token row, so consent withdrawal could not revoke it. A native delegation
  // client only ever receives opaque, row-backed access tokens.
  describe(`no JWT access tokens for native clients (${backend})`, () => {
    const resourceRefused = { error: 'invalid_request', error_description: 'resource is not supported for native delegation clients' };

    function userinfo(accessToken: string) {
      return call('/api/auth/oauth2/userinfo', { headers: { authorization: `Bearer ${accessToken}` } });
    }

    /** The exchange succeeded with an opaque access token backed by a token row. */
    async function expectOpaqueAccessToken(response: Response) {
      expect(response.status, await response.clone().text()).toBe(200);
      const body = await response.json() as { access_token: string; refresh_token: string };
      expect(() => decodeJwt(body.access_token)).toThrow();
      const row = await prisma.oauthAccessToken.findFirst({ where: { token: hash(body.access_token) } });
      expect(row).toMatchObject({ clientId: nativeClient, userId: alice });
      return body;
    }

    test('an exchange or refresh with resource is refused before the provider issues anything', async () => {
      const flow = await approvedCode();
      for (const resource of [API, ISSUER, `${ISSUER}/oauth2/userinfo`, '']) {
        const response = await exchange(flow.code, flow.verifier, proof(flow.key, flow.code), { resource });
        expect(response.status, resource).toBe(400);
        expect(await oauthError(response), resource).toEqual(resourceRefused);
      }
      expect(await requestStatus(flow.requestId)).toBe('APPROVED');
      expect(await prisma.tinyCloudNativeGrant.count()).toBe(0);
      expect(await prisma.oauthRefreshToken.count()).toBe(0);
      expect(await prisma.oauthAccessToken.count()).toBe(0);

      const issued = await expectOpaqueAccessToken(await exchange(flow.code, flow.verifier, proof(flow.key, flow.code)));
      const refresh = await form('/api/auth/oauth2/token', new URLSearchParams({
        grant_type: 'refresh_token', client_id: nativeClient, refresh_token: issued.refresh_token, resource: API,
      }));
      expect(refresh.status).toBe(400);
      expect(await oauthError(refresh)).toEqual({ error: 'invalid_grant', error_description: 'use the renew endpoint' });
      expect(await prisma.oauthAccessToken.count()).toBe(1);
    }, 60_000);

    test('the exchange hook refuses resource on a path around the interceptor', async () => {
      const flow = await approvedCode();
      // auth.handler is the provider without the Hono interceptors.
      const response = await auth.handler(new Request(`${ISSUER}/oauth2/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', 'OpenKey-Session-Proof': proof(flow.key, flow.code) },
        body: new URLSearchParams({
          grant_type: 'authorization_code', code: flow.code, client_id: nativeClient, redirect_uri: NATIVE_REDIRECT,
          code_verifier: flow.verifier, resource: API,
        }).toString(),
      }));
      expect(response.status).toBe(400);
      expect(await oauthError(response)).toEqual(resourceRefused);
      await expectSpentWithoutRedemption(flow);
    }, 60_000);

    test('a code minted with an authorize-time resource yields only an opaque access token', async () => {
      // On the authorize URL, next to the request_uri.
      const viaAuthorize = await approvedCode(sessionKey(), 3600, { resource: API });
      await expectOpaqueAccessToken(await exchange(viaAuthorize.code, viaAuthorize.verifier, proof(viaAuthorize.key, viaAuthorize.code)));

      // In the code's stored query, as a path around the authorize guard could store it.
      const flow = await approvedCode();
      const forged = await forgeCode(flow.code, (query) => { query.resource = API; });
      await expectOpaqueAccessToken(await exchange(forged, flow.verifier, proof(flow.key, forged)));
    }, 60_000);

    test('after withdrawal no access token the native client received works at userinfo', async () => {
      const received: string[] = [];
      for (const authorizeParams of [{}, { resource: API }]) {
        const flow = await approvedCode(sessionKey(), 3600, authorizeParams);
        const body = await expectOpaqueAccessToken(await exchange(flow.code, flow.verifier, proof(flow.key, flow.code)));
        received.push(body.access_token);
      }
      // The JWT route stays closed for a still-approved code.
      const pending = await approvedCode();
      const jwt = await exchange(pending.code, pending.verifier, proof(pending.key, pending.code), { resource: API });
      expect(await oauthError(jwt)).toEqual(resourceRefused);
      for (const accessToken of received) {
        const live = await userinfo(accessToken);
        expect(live.status, await live.clone().text()).toBe(200);
      }

      const consent = await prisma.oauthConsent.findFirstOrThrow({ where: { userId: alice, clientId: nativeClient } });
      const deleted = await json('/api/auth/oauth2/delete-consent', { id: consent.id }, { cookie });
      expect(deleted.status, await deleted.clone().text()).toBe(200);

      for (const accessToken of received) {
        const dead = await userinfo(accessToken);
        expect(dead.status).toBe(400);
        expect(await oauthError(dead)).toEqual({ error: 'invalid_request', error_description: 'Invalid access token' });
      }
      expect(await prisma.oauthAccessToken.count({ where: { clientId: nativeClient } })).toBe(0);
      expect(await requestStatus(pending.requestId)).toBe('WITHDRAWN');
      for (const overrides of [{ resource: API }, {}]) {
        const late = await exchange(pending.code, pending.verifier, proof(pending.key, pending.code), overrides);
        expect(late.status).toBe(400);
      }
      expect(await prisma.oauthAccessToken.count({ where: { clientId: nativeClient } })).toBe(0);
    }, 120_000);
  });
}
