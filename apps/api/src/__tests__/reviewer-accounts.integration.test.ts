import './tc1777-test-env';
import { afterAll, beforeAll, expect, test, setSystemTime } from 'bun:test';
import { decodeJwt, createLocalJWKSet, jwtVerify } from 'jose';
import { PGlite } from '@electric-sql/pglite';
import { verifyMessage, type Hex } from 'viem';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { serializeSignedCookie } from 'better-call';
import { generateCodeChallenge } from 'better-auth/oauth2';
import type { PrismaClient } from '@openkey/db';

const root = resolve(import.meta.dir, '../../../..');
if (process.env.OPENKEY_REVIEWER_TEST_CHILD !== '1') {
  test('reviewer sign-in and revocation through the real provider', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env, OPENKEY_REVIEWER_TEST_CHILD: '1', NODE_ENV: 'test', TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test', BETTER_AUTH_SECRET: 'reviewer-isolated-test-secret-0123456789',
        WEBAUTHN_RP_ID: 'openkey.test', WEBAUTHN_ORIGIN: 'https://openkey.test', CORS_ORIGIN: 'https://openkey.test',
        ADMIN_API_KEY: 'reviewer-isolated-admin-test', RESEND_API_KEY: '', GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '',
      },
      stdout: 'pipe', stderr: 'pipe',
    });
    const [stdout, stderr, status] = await Promise.all([
      new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
    ]);
    expect(status, stdout + stderr).toBe(0);
  }, 180_000);
} else {
  let directory: string;
  let database: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let accounts: typeof import('../services/reviewer-accounts');
  const code = randomBytes(32).toString('base64url');
  const callback = 'https://chatgpt.com/connector_platform_oauth_redirect';
  const resource = 'https://mcp.tinycloud.xyz/chatgpt/mcp';
  const verifier = 'reviewer-pkce-0123456789012345678901234567890';
  let clientId: string;
  let signedQuery: string;
  let cookie: string;
  let accessToken: string;
  let idToken: string;
  let signedDelegation: string;
  let capturedLogs = '';
  const writeStdout = process.stdout.write;
  let address: string;
  const sessionJwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
  const originalFetch = globalThis.fetch;

  const call = (path: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}) =>
    app.fetch(new Request('https://api.openkey.test' + path, {
      method, headers: { 'content-type': 'application/json', origin: 'https://openkey.test', ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }));

  beforeAll(async () => {
    process.stdout.write = ((chunk: any, ...args: any[]) => {
      capturedLogs += String(chunk);
      return (writeStdout as any).call(process.stdout, chunk, ...args);
    }) as typeof process.stdout.write;
    directory = await mkdtemp('/var/tmp/tc2775-db.');
    const pglite = new PGlite(directory);
    try {
      const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
        .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
      for (const migration of migrations) await pglite.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
    } finally { await pglite.close(); }
    globalThis.fetch = (() => Promise.reject(new Error('External network disabled in reviewer integration tests'))) as unknown as typeof fetch;
    process.env.DATABASE_URL = 'pglite:' + directory;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    database = (await import('../auth')).prisma;
    app = (await import('../index')).default;
    accounts = await import('../services/reviewer-accounts');
    const registration = await call('/api/auth/oauth2/register', 'POST', {
      client_name: 'Reviewer fixture', redirect_uris: [callback], token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
    });
    expect(registration.status).toBe(200);
    clientId = (await registration.json() as { client_id: string }).client_id;
    await database.user.create({ data: {
      id: 'reviewer-owner', email: 'openai-review@tinycloud.xyz', emailVerified: true, name: 'App review', reviewerHoldAt: new Date(),
    } });
    const tee = await import('@openkey/tee');
    const privateKey = tee.generatePrivateKey();
    address = tee.getAddressFromPrivateKey(privateKey);
    const sealingContext = (await import('../services/key-sealing')).createSealingContext();
    const sealedBlob = await tee.seal(privateKey, await tee.createTeeClient().deriveKey('openkey/key/' + sealingContext));
    await database.ethereumKey.create({ data: {
      id: 'fixture-key', userId: 'reviewer-owner', address, publicKey: address, sealedBlob,
      sealingContext, isCanonicalTinyCloud: true, keyIndex: 0,
    } });
    const { reviewerSessionDid } = await import('../services/reviewer-delegation');
    await database.reviewerAccount.update({ where: { store: 'openai' }, data: {
      userId: 'reviewer-owner', clientId, redirectUri: callback, resource, callbackUri: 'https://mcp.tinycloud.xyz/chatgpt/connect/callback',
      nodeHost: 'https://node.tinycloud.xyz', sessionDid: reviewerSessionDid(sessionJwk), keyId: 'fixture-key',
      spaceId: `tinycloud:pkh:eip155:1:${address}:applications`, seededAt: new Date(),
    } });
    const query = new URLSearchParams({
      client_id: clientId, response_type: 'code', redirect_uri: callback, resource,
      scope: 'openid email offline_access tinycloud:mcp', state: 'reviewer-state',
      code_challenge_method: 'S256', code_challenge: await generateCodeChallenge(verifier),
    });
    const authorization = await call('/api/auth/oauth2/authorize?' + query);
    expect(authorization.status).toBe(302);
    signedQuery = new URL(authorization.headers.get('location')!).searchParams.toString();
  }, 90_000);

  afterAll(async () => {
    setSystemTime();
    process.stdout.write = writeStdout;
    globalThis.fetch = originalFetch;
    await database?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  test('all addresses are reserved and Apple stays disabled', async () => {
    expect(await database.reviewerAccount.count()).toBe(3);
    const result = await call('/api/admin/review-accounts/apple/code', 'PUT', { code }, { authorization: 'Bearer reviewer-isolated-admin-test' });
    expect(result.status).toBe(400);
  });

  test('only the admin installs a well-formed credential', async () => {
    expect((await call('/api/admin/review-accounts/openai/code', 'PUT', { code })).status).toBe(401);
    expect((await call('/api/admin/review-accounts/openai/code', 'PUT', { code: 'short' }, { authorization: 'Bearer reviewer-isolated-admin-test' })).status).toBe(400);
    expect((await call('/api/admin/review-accounts/openai/code', 'PUT', { code }, { authorization: 'Bearer reviewer-isolated-admin-test' })).status).toBe(200);
  });

  test('cross-site sign-in is refused', async () => {
    const result = await call('/api/auth/sign-in/reviewer', 'POST', {
      email: 'openai-review@tinycloud.xyz', code, oauth_query: signedQuery,
    }, { origin: 'https://foreign.test' });
    expect(result.status).toBe(403);
    expect(await database.session.count({ where: { userId: 'reviewer-owner' } })).toBe(0);
  });

  test('reserved email sends no OTP and refuses recovery and registration', async () => {
    const before = await database.verification.count();
    expect((await call('/api/auth/email-otp/send-verification-otp', 'POST', {
      email: 'openai-review@tinycloud.xyz', type: 'sign-in',
    })).status).toBe(200);
    expect(await database.verification.count()).toBe(before);
    expect((await call('/api/auth/sign-up/email-otp', 'POST', {
      email: 'openai-review@tinycloud.xyz', signupToken: code,
    })).status).toBe(403);
    expect((await call('/api/auth/email-otp/reset-password', 'POST', {
      email: 'openai-review@tinycloud.xyz', otp: code, password: 'unused-test-password',
    })).status).toBe(403);
  });

  test('failure delay does not prevent a correct code during failed attempts', async () => {
    const attempts = Array.from({ length: 5 }, () => call('/api/auth/sign-in/reviewer', 'POST', {
      email: 'openai-review@tinycloud.xyz', code: 'incorrect', oauth_query: signedQuery,
    }));
    const correct = await call('/api/auth/sign-in/reviewer', 'POST', {
      email: 'openai-review@tinycloud.xyz', code, oauth_query: signedQuery,
    });
    expect(correct.status).toBe(200);
    for (const attempt of await Promise.all(attempts)) expect(attempt.status).toBe(403);
  });

  test('reviewer sign-in cannot replace a live ordinary session', async () => {
    await database.user.create({ data: { id: 'ordinary-owner', email: 'ordinary@example.test', name: 'Ordinary', emailVerified: true } });
    await database.session.create({ data: { id: 'ordinary-session', token: 'ordinary-test-token',
      userId: 'ordinary-owner', expiresAt: new Date(Date.now() + 3600_000) } });
    const runtime = await import('../auth');
    const context = await runtime.auth.$context;
    const ordinaryCookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, 'ordinary-test-token', context.secret)).split(';')[0]!;
    const result = await call('/api/auth/sign-in/reviewer', 'POST', {
      email: 'openai-review@tinycloud.xyz', code, oauth_query: signedQuery,
    }, { cookie: ordinaryCookie });
    expect(result.status).toBe(403);
    expect(await database.session.findUnique({ where: { id: 'ordinary-session' } })).not.toBeNull();
  });

  test('the reserved email-code endpoint uses the reviewer verifier', async () => {
    const { signedReviewerQuery, reviewerQueryMatches } = await import('../services/reviewer-auth');
    const bindingBefore = await accounts.reviewerForUser(database, 'reviewer-owner');
    expect(accounts.reviewerActive(bindingBefore)).toBe(true);
    expect(accounts.reviewerCodeMatches(bindingBefore, code)).toBe(true);
    const parsed = await signedReviewerQuery(signedQuery, process.env.BETTER_AUTH_SECRET!);
    expect(parsed !== null).toBe(true);
    expect(reviewerQueryMatches(bindingBefore!, parsed!), JSON.stringify([...parsed!.entries()].filter(([key]) => !['sig', 'code_challenge'].includes(key)))).toBe(true);
    const result = await call('/api/auth/sign-in/email-otp', 'POST', {
      email: 'openai-review@tinycloud.xyz', otp: code, oauth_query: signedQuery,
    });
    expect(result.status, await result.clone().text()).toBe(200);
    const cookies = result.headers.getSetCookie();
    cookie = cookies.map((value) => value.split(';')[0]).join('; ');
    expect(cookie.includes('session_token')).toBe(true);
    const refreshed = await call('/api/auth/get-session', 'GET', undefined, { cookie });
    expect(refreshed.status).toBe(200);
    const current = await refreshed.json() as { session: { id: string } };
    const session = await database.session.findUniqueOrThrow({ where: { id: current.session.id } });
    const binding = await database.reviewerAccount.findUniqueOrThrow({ where: { store: 'openai' } });
    expect(session.reviewerEpoch).toBe(binding.installEpoch);
    expect(session.expiresAt.getTime() - session.createdAt.getTime()).toBeLessThanOrEqual(3_600_000);
  });

  test('the consent page can load public client metadata with a reviewer session', async () => {
    const result = await call('/api/auth/oauth2/public-client?client_id=' + encodeURIComponent(clientId), 'GET', undefined, { cookie });
    expect(result.status, await result.clone().text()).toBe(200);
    const client = await result.json() as Record<string, unknown>;
    expect(client.client_id).toBe(clientId);
    expect(client.client_name).toBe('Reviewer fixture');
    // The provider's public projection: display fields only (it also emits an empty `redirect_uris`).
    const publicFields = ['client_id', 'client_name', 'client_uri', 'logo_uri', 'contacts', 'tos_uri', 'policy_uri', 'redirect_uris'];
    expect(Object.keys(client).filter((field) => !publicFields.includes(field))).toEqual([]);
    expect(client.redirect_uris ?? []).toEqual([]);
    // The neighbouring full-client read stays outside the reviewer allowlist.
    expect((await call('/api/auth/oauth2/get-client?client_id=' + encodeURIComponent(clientId), 'GET', undefined, { cookie })).status).toBe(403);
  });

  test('consent and PKCE exchange issue only one-hour reviewer credentials', async () => {
    const authorization = await call('/api/auth/oauth2/authorize?' + signedQuery, 'GET', undefined, { cookie });
    expect(authorization.status, await authorization.clone().text()).toBe(302);
    const consentQuery = new URL(authorization.headers.get('location')!).searchParams.toString();
    const consent = await call('/api/auth/oauth2/consent', 'POST', { accept: true, oauth_query: consentQuery }, { cookie });
    expect(consent.status, await consent.clone().text()).toBe(200);
    const consentRow = await database.oauthConsent.findUniqueOrThrow({ where: { userId_clientId: { userId: 'reviewer-owner', clientId } } });
    const binding = await database.reviewerAccount.findUniqueOrThrow({ where: { store: 'openai' } });
    expect(consentRow.reviewerEpoch).toBe(binding.installEpoch);
    const authorizationCode = new URL((await consent.json() as { url: string }).url).searchParams.get('code')!;
    const exchange = await app.fetch(new Request('https://api.openkey.test/api/auth/oauth2/token', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', client_id: clientId,
        code: authorizationCode, redirect_uri: callback, code_verifier: verifier, resource }),
    }));
    expect(exchange.status, await exchange.clone().text()).toBe(200);
    const tokens = await exchange.json() as { access_token: string; expires_in: number; id_token: string };
    accessToken = tokens.access_token;
    idToken = tokens.id_token;
    expect(tokens.expires_in).toBeLessThanOrEqual(3600);
    const claims = decodeJwt(accessToken);
    expect(claims.exp! - claims.iat!).toBeLessThanOrEqual(3600);
    const idClaims = decodeJwt(tokens.id_token);
    expect(idClaims.exp! - idClaims.iat!).toBeLessThanOrEqual(3600);
    const refresh = await database.oauthRefreshToken.findFirstOrThrow({ where: { userId: 'reviewer-owner' } });
    const source = await database.session.findUniqueOrThrow({ where: { id: refresh.sessionId! } });
    expect(refresh.expiresAt.getTime()).toBeLessThanOrEqual(source.createdAt.getTime() + 3600_000);
  });

  test('a non-reset provision retry leaves an installed account intact', async () => {
    const before = await accounts.reviewerForUser(database, 'reviewer-owner');
    const sessions = await database.session.count({ where: { userId: 'reviewer-owner' } });
    const { provisionReviewer } = await import('../services/reviewer-fixtures');
    await expect(provisionReviewer(database, 'openai', {
      clientId, nodeHost: 'https://node.tinycloud.xyz',
    }, false)).rejects.toThrow();
    const after = await accounts.reviewerForUser(database, 'reviewer-owner');
    expect(after!.installEpoch).toBe(before!.installEpoch);
    expect(accounts.reviewerActive(after)).toBe(true);
    expect(await database.session.count({ where: { userId: 'reviewer-owner' } })).toBe(sessions);
  });

  test('reviewer cannot use key generation or organization routes', async () => {
    expect((await call('/api/keys/generate', 'POST', {}, { cookie })).status).toBe(403);
    expect((await call('/api/organizations', 'POST', {}, { cookie })).status).toBe(403);
  });

  test('reviewer key metadata is public and other signing surfaces are denied', async () => {
    const display = await call('/api/delegate/prepare', 'GET', undefined, { cookie });
    expect(display.status).toBe(200);
    expect(await display.json()).toEqual({ key: { address, did: `did:pkh:eip155:1:${address}` } });
    for (const path of ['/api/delegate/host', '/api/delegate/sign', '/api/delegate/authorize-sign', '/api/delegation-codes', '/api/device-authorizations', '/api/keys/fixture-key/sign']) {
      expect((await call(path, 'POST', {}, { cookie })).status).toBe(403);
    }
  });

  test('signed reviewer delegations contain only the bound audience and space and expire within an hour', async () => {
    const { reviewerSessionDid } = await import('../services/reviewer-delegation');
    expect(reviewerSessionDid({ ...sessionJwk, constructor: 'invalid' })).toBeNull();
    expect(reviewerSessionDid({ ...sessionJwk, kid: {} })).toBeNull();
    const permissions = [{ service: 'tinycloud.kv', space: 'applications',
      path: 'xyz.tinycloud.tinyapps.todos/', actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] }];
    const body = { keyId: 'reviewer', jwk: sessionJwk, host: 'https://node.tinycloud.xyz', prefix: 'default',
      permissions, expiry: '9999-01-01T00:00:00Z' };
    const foreign = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
    expect((await call('/api/delegate/prepare', 'POST', { ...body, jwk: foreign }, { cookie })).status).toBe(403);
    expect((await call('/api/delegate/prepare', 'POST', { ...body, permissions: [
      { ...permissions[0], space: 'secrets' },
    ] }, { cookie })).status).toBe(403);
    expect((await call('/api/delegate/prepare', 'POST', { ...body, permissions: [
      { ...permissions[0], actions: ['tinycloud.kv/delegate'] },
    ] }, { cookie })).status).toBe(403);
    const prepared = await call('/api/delegate/prepare', 'POST', body, { cookie });
    expect(prepared.status, await prepared.clone().text()).toBe(200);
    const preview = await prepared.json() as any;
    const signed = await call('/api/delegate', 'POST', {
      ...body, prepared: preview.prepared, authorizationContextToken: preview.authorizationContext.token,
      selectedActionIds: preview.selectedActionKeys, protocolVersion: 1,
    }, { cookie });
    expect(signed.status, await signed.clone().text()).toBe(200);
    const result = await signed.json() as { signedMessage: string; signature: Hex };
    signedDelegation = result.signedMessage;
    expect(await verifyMessage({ address: address as Hex, message: result.signedMessage, signature: result.signature })).toBe(true);
    const { parseStrictSiwe } = await import('../services/signed-subset');
    const { parsePreparedRecap } = await import('../routes/delegate-session');
    const decoded = parseStrictSiwe(result.signedMessage);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) throw new Error('Invalid signed reviewer delegation');
    const binding = await accounts.reviewerForUser(database, 'reviewer-owner');
    expect(decoded.siwe.uri.split('#')[0]).toBe(binding!.sessionDid!);
    expect(Date.parse(decoded.siwe.expirationTime!) - Date.parse(decoded.siwe.issuedAt)).toBeLessThanOrEqual(3600_000);
    for (const entry of parsePreparedRecap(result.signedMessage)) {
      expect(entry.space).toBe(binding!.spaceId!);
      expect(entry.path).toBe('xyz.tinycloud.tinyapps.todos/');
      expect(entry.actions.every((action) => ['tinycloud.kv/get', 'tinycloud.kv/list'].includes(action))).toBe(true);
    }
  });

  const todos = 'xyz.tinycloud.tinyapps.todos';
  const workouts = 'xyz.tinycloud.tinyapps.workouts';
  const kvRecords = ['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/put', 'tinycloud.kv/del'];
  const kvRead = ['tinycloud.kv/get', 'tinycloud.kv/list'];
  const sqlCopy = ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'];
  const delegateBody = (permissions: unknown[]) => ({
    keyId: 'reviewer', jwk: sessionJwk, host: 'https://node.tinycloud.xyz', prefix: 'default', permissions, expiry: '1h',
  });
  const prepareStatus = async (permissions: unknown[]) =>
    (await call('/api/delegate/prepare', 'POST', delegateBody(permissions), { cookie })).status;
  let approvedSpaceId = '';
  /** Prepare and sign as the approval page does; returns the entries the signed message carries. */
  async function approve(permissions: unknown[]) {
    const body = delegateBody(permissions);
    const prepared = await call('/api/delegate/prepare', 'POST', body, { cookie });
    expect(prepared.status, await prepared.clone().text()).toBe(200);
    const preview = await prepared.json() as any;
    const signed = await call('/api/delegate', 'POST', {
      ...body, prepared: preview.prepared, authorizationContextToken: preview.authorizationContext.token,
      selectedActionIds: preview.selectedActionKeys, protocolVersion: 1,
    }, { cookie });
    expect(signed.status, await signed.clone().text()).toBe(200);
    const result = await signed.json() as { signedMessage: string; signature: Hex; spaceId: string };
    approvedSpaceId = result.spaceId;
    expect(await verifyMessage({ address: address as Hex, message: result.signedMessage, signature: result.signature })).toBe(true);
    const { parsePreparedRecap } = await import('../routes/delegate-session');
    return parsePreparedRecap(result.signedMessage)
      .map((entry) => ({ ...entry, actions: [...entry.actions].sort() }))
      .sort((a, b) => (a.service + a.path).localeCompare(b.service + b.path));
  }

  test('the hosted MCP bootstrap grant is prepared and signed, and nothing else in the account space is', async () => {
    const accountSpace = `tinycloud:pkh:eip155:1:${address}:account`;
    // js-sdk 0c09ed52d packages/mcp/src/remote-store.ts BOOTSTRAP_PERMISSIONS, verbatim.
    const bootstrap = [
      { service: 'tinycloud.kv', space: 'account', path: 'spaces/', actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] },
      { service: 'tinycloud.kv', space: 'account', path: 'applications/', actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] },
    ];
    expect(await approve(bootstrap)).toEqual([
      { service: 'kv', space: accountSpace, path: 'applications/', actions: kvRead },
      { service: 'kv', space: accountSpace, path: 'spaces/', actions: kvRead },
    ]);
    // The MCP stores this as the session's space and probes `spaces/` in it, so it must be the account space.
    expect(approvedSpaceId).toBe(accountSpace);
    expect(await prepareStatus([{ ...bootstrap[0], path: 'profile/' }])).toBe(403);
    expect(await prepareStatus([{ ...bootstrap[0], path: 'spaces/other/' }])).toBe(403);
    expect(await prepareStatus([{ ...bootstrap[0], path: '' }])).toBe(403);
    expect(await prepareStatus([{ ...bootstrap[0], actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] }])).toBe(403);
    expect(await prepareStatus([{ ...bootstrap[0], actions: ['tinycloud.kv/metadata'] }])).toBe(403);
    expect(await prepareStatus([{ ...bootstrap[0], service: 'tinycloud.sql', actions: ['tinycloud.sql/read'] }])).toBe(403);
    const foreignAccount = 'tinycloud:pkh:eip155:1:0x00000000000000000000000000000000000000aa:account';
    expect(await prepareStatus([{ ...bootstrap[0], space: foreignAccount }])).toBe(403);
    const { reviewerPermissionAllowed } = await import('../services/reviewer-delegation');
    const binding = await accounts.reviewerForUser(database, 'reviewer-owner');
    expect(reviewerPermissionAllowed(binding!, { service: 'kv', space: accountSpace, path: 'spaces/', actions: kvRead })).toBe(true);
    expect(reviewerPermissionAllowed(binding!, { service: 'kv', space: foreignAccount, path: 'spaces/', actions: kvRead })).toBe(false);
  });

  test('the narrowed app approval and the searchable-copy approval are signed in the shapes the MCP sends', async () => {
    const space = `tinycloud:pkh:eip155:1:${address}:applications`;
    expect(await approve([
      { service: 'tinycloud.kv', space: 'applications', path: 'xyz.tinycloud.tinyapps.catalog/', actions: kvRead },
      { service: 'tinycloud.kv', space: 'applications', path: 'xyz.tinycloud.tinyapps.catalog/todos/entry', actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] },
      { service: 'tinycloud.kv', space: 'applications', path: todos + '/', actions: kvRecords },
    ])).toEqual([
      { service: 'kv', space, path: 'xyz.tinycloud.tinyapps.catalog/', actions: kvRead },
      { service: 'kv', space, path: 'xyz.tinycloud.tinyapps.catalog/todos/entry', actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] },
      { service: 'kv', space, path: todos + '/', actions: [...kvRecords].sort() },
    ]);
    expect(await approve([
      { service: 'tinycloud.kv', space: 'applications', path: todos + '/', actions: kvRecords },
      { service: 'tinycloud.sql', space: 'applications', path: todos + '/index', actions: sqlCopy },
    ])).toEqual([
      { service: 'kv', space, path: todos + '/', actions: [...kvRecords].sort() },
      { service: 'sql', space, path: todos + '/index', actions: [...sqlCopy].sort() },
    ]);
    const sql = { service: 'tinycloud.sql', space: 'applications', path: todos + '/index', actions: sqlCopy };
    expect(await prepareStatus([sql])).toBe(200);
    expect(await prepareStatus([{ ...sql, path: todos + '/other' }])).toBe(403);
    expect(await prepareStatus([{ ...sql, path: todos + '/index/extra' }])).toBe(403);
    expect(await prepareStatus([{ ...sql, path: todos }])).toBe(403);
    expect(await prepareStatus([{ ...sql, path: 'xyz.tinycloud.sample.healthlog/healthlog' }])).toBe(403);
    expect(await prepareStatus([{ ...sql, path: 'xyz.tinycloud.agent-data.index' }])).toBe(403);
    expect(await prepareStatus([{ ...sql, actions: ['tinycloud.sql/export'] }])).toBe(403);
  });

  test('any valid personal app is admitted inside the bound space and everything else stays refused', async () => {
    const space = `tinycloud:pkh:eip155:1:${address}:applications`;
    expect(await approve([
      { service: 'tinycloud.kv', space: 'applications', path: 'xyz.tinycloud.tinyapps.catalog/workouts/entry', actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] },
      { service: 'tinycloud.kv', space: 'applications', path: workouts + '/', actions: kvRecords },
      { service: 'tinycloud.sql', space: 'applications', path: workouts + '/index', actions: sqlCopy },
    ])).toEqual([
      { service: 'kv', space, path: 'xyz.tinycloud.tinyapps.catalog/workouts/entry', actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] },
      { service: 'kv', space, path: workouts + '/', actions: [...kvRecords].sort() },
      { service: 'sql', space, path: workouts + '/index', actions: [...sqlCopy].sort() },
    ]);
    const records = { service: 'tinycloud.kv', space: 'applications', path: workouts + '/', actions: kvRecords };
    expect(await prepareStatus([{ ...records, path: 'xyz.tinycloud.tinyapps.goals-2027/' }])).toBe(200);
    for (const app of ['healthlog', 'recipes', 'catalog', 'index-stale', 'Workouts', '1workouts', 'work_outs', '']) {
      expect(await prepareStatus([{ ...records, path: `xyz.tinycloud.tinyapps.${app}/` }]), app).toBe(403);
      expect(await prepareStatus([{ ...records, path: `xyz.tinycloud.tinyapps.catalog/${app}/entry`, actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] }]), app).toBe(403);
      expect(await prepareStatus([{ service: 'tinycloud.sql', space: 'applications', path: `xyz.tinycloud.tinyapps.${app}/index`, actions: sqlCopy }]), app).toBe(403);
    }
    // Catalog root is read-only; a discovery entry cannot be deleted or widened to its siblings.
    expect(await prepareStatus([{ ...records, path: 'xyz.tinycloud.tinyapps.catalog/', actions: ['tinycloud.kv/put'] }])).toBe(403);
    expect(await prepareStatus([{ ...records, path: 'xyz.tinycloud.tinyapps.catalog/workouts/entry', actions: ['tinycloud.kv/del'] }])).toBe(403);
    expect(await prepareStatus([{ ...records, path: 'xyz.tinycloud.tinyapps.catalog/workouts/' }])).toBe(403);
    expect(await prepareStatus([{ service: 'tinycloud.sql', space: 'applications', path: workouts + '/other', actions: sqlCopy }])).toBe(403);
    // Outside the personal-app namespace, and outside the bound space.
    expect(await prepareStatus([{ ...records, path: '' }])).toBe(403);
    expect(await prepareStatus([{ ...records, path: 'xyz.tinycloud.agent-data/' }])).toBe(403);
    expect(await prepareStatus([{ ...records, path: 'xyz.tinycloud.tinyapps.' }])).toBe(403);
    for (const other of ['default', 'secrets', 'public', 'account']) {
      expect(await prepareStatus([{ ...records, space: other }]), other).toBe(403);
    }
    expect(await prepareStatus([{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/delegate'] }])).toBe(403);
    // One refused entry refuses the whole request.
    expect(await prepareStatus([records, { ...records, space: 'secrets' }])).toBe(403);
  });

  test('a present approval-request id is refused for a reviewer even when it is falsy', async () => {
    const permissions = [{ service: 'tinycloud.kv', space: 'applications', path: todos + '/', actions: kvRead }];
    for (const approvalRequestId of ['', 0, null, false]) {
      const result = await call('/api/delegate/prepare', 'POST', { ...delegateBody(permissions), approvalRequestId }, { cookie });
      expect(result.status, String(approvalRequestId)).toBe(403);
    }
  });

  test('the route guard refuses a reviewer token beside another session and reads the bearer scheme in any case', async () => {
    const runtime = await import('../auth');
    const context = await runtime.auth.$context;
    const ordinaryCookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, 'ordinary-test-token', context.secret)).split(';')[0]!;
    expect((await call('/api/keys', 'GET', undefined, { cookie: ordinaryCookie })).status).toBe(200);
    expect((await call('/api/keys', 'GET', undefined, { cookie: ordinaryCookie, authorization: 'Bearer ' + accessToken })).status).toBe(403);
    for (const scheme of ['Bearer', 'bearer', 'BEARER']) {
      expect((await call('/api/keys', 'GET', undefined, { authorization: scheme + ' ' + accessToken })).status, scheme).toBe(403);
    }
    // The allowlisted token endpoint still answers the reviewer's own token.
    expect((await call('/api/auth/oauth2/userinfo', 'GET', undefined, { authorization: 'Bearer ' + accessToken })).status).toBe(200);
  });

  test('refresh cannot extend reviewer sign-in and an overlong row cannot authorize after one hour', async () => {
    const result = await call('/api/auth/sign-in/reviewer', 'POST', {
      email: 'openai-review@tinycloud.xyz', code, oauth_query: signedQuery,
    });
    expect(result.status).toBe(200);
    const testCookie = result.headers.getSetCookie().map((value) => value.split(';')[0]).join('; ');
    const refreshed = await call('/api/auth/get-session', 'GET', undefined, { cookie: testCookie });
    expect(refreshed.status).toBe(200);
    const current = await refreshed.json() as { session: { id: string } };
    const session = await database.session.findUniqueOrThrow({ where: { id: current.session.id } });
    expect(session.expiresAt.getTime() - session.createdAt.getTime()).toBeLessThanOrEqual(3600_000);
    // A legacy or direct-database extension must also be refused at every signing entry.
    await database.session.update({ where: { id: session.id }, data: {
      expiresAt: new Date(session.createdAt.getTime() + 7 * 86400_000),
    } });
    const before = await database.reviewerAccount.findUniqueOrThrow({ where: { store: 'openai' } });
    await database.reviewerAccount.update({ where: { store: 'openai' }, data: { grantSessionId: session.id } });
    const runtime = await import('../auth');
    const authorizationQuery = new URLSearchParams(signedQuery);
    authorizationQuery.delete('sig');
    authorizationQuery.delete('exp');
    const authorize = () => accounts.reviewerRequest.run({}, () => runtime.auth.handler(new Request('https://api.openkey.test/api/auth/oauth2/authorize?' + authorizationQuery, {
      headers: { cookie: testCookie },
    })));
    const { currentReviewerDelegate } = await import('../services/reviewer-delegation');
    try {
      expect((await authorize()).status).toBe(302);
      const binding = await accounts.reviewerForUser(database, 'reviewer-owner');
      await accounts.reviewerRequest.run({}, async () => {
        accounts.captureReviewer(binding!, session.id, session.createdAt.getTime() + 3600_000);
        expect((await currentReviewerDelegate(database, 'reviewer-owner'))?.userId).toBe('reviewer-owner');
      });
      await database.session.update({ where: { id: session.id }, data: {
        expiresAt: new Date(session.createdAt.getTime() + 7 * 86400_000),
      } });
      setSystemTime(new Date(session.createdAt.getTime() + 3601_000));
      for (const path of ['/api/delegate/prepare', '/api/delegate', '/api/delegate/complete']) {
        expect((await call(path, 'POST', {}, { cookie: testCookie })).status).toBe(403);
      }
      expect((await authorize()).status).toBe(403);
      await accounts.reviewerRequest.run({}, async () => {
        accounts.captureReviewer(binding!, session.id, session.createdAt.getTime() + 3600_000);
        await expect(currentReviewerDelegate(database, 'reviewer-owner')).rejects.toThrow();
      });
    } finally {
      setSystemTime();
      await database.reviewerAccount.update({ where: { store: 'openai' }, data: { grantSessionId: before.grantSessionId } });
    }
  });

  test('changing the operator audience pin unsets the code and ends old sessions', async () => {
    const { reviewerSessionDid } = await import('../services/reviewer-delegation');
    const replacement = reviewerSessionDid(generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }));
    expect((await call('/api/admin/review-accounts/openai/audience', 'PUT', {
      sessionDid: replacement,
    }, { cookie })).status).toBe(403);
    const result = await call('/api/admin/review-accounts/openai/audience', 'PUT', {
      sessionDid: replacement,
    }, { authorization: 'Bearer reviewer-isolated-admin-test' });
    expect(result.status).toBe(200);
    expect(await database.session.count({ where: { userId: 'reviewer-owner' } })).toBe(0);
    expect((await call('/api/delegate/prepare', 'POST', {}, { cookie })).status).not.toBe(200);
    const binding = await accounts.reviewerForUser(database, 'reviewer-owner');
    expect(binding!.sessionDid).toBe(replacement);
    expect(accounts.reviewerActive(binding)).toBe(false);
    await accounts.installReviewer(database, 'openai', code);
  });

  test('unset deletes authority and prevents late epoch revival on reinstall', async () => {
    const binding = await database.reviewerAccount.findUniqueOrThrow({ where: { store: 'openai' } });
    await accounts.unsetReviewer(database, 'openai');
    expect(await database.session.count({ where: { userId: 'reviewer-owner' } })).toBe(0);
    expect((await database.user.findUniqueOrThrow({ where: { id: 'reviewer-owner' } })).reviewerHoldAt).not.toBeNull();
    await expect(Promise.resolve(database.session.create({ data: {
      id: 'late-session', userId: 'reviewer-owner', token: 'late-test-token', reviewerEpoch: binding.installEpoch,
      expiresAt: new Date(Date.now() + 3600_000),
    } }))).rejects.toThrow();
    await accounts.installReviewer(database, 'openai', code);
    expect(await database.session.findUnique({ where: { id: 'late-session' } })).toBeNull();
    await expect(Promise.resolve(database.session.create({ data: {
      id: 'after-cleanup-session', userId: 'reviewer-owner', token: 'late-after-cleanup-token',
      reviewerEpoch: binding.installEpoch, expiresAt: new Date(Date.now() + 3600_000),
    } }))).rejects.toThrow();
    const runtime = await import('../auth');
    const context = await runtime.auth.$context;
    const lateCookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, 'late-after-cleanup-token', context.secret)).split(';')[0]!;
    const lateRead = await call('/api/auth/get-session', 'GET', undefined, { cookie: lateCookie });
    expect(await lateRead.json()).toBeNull();

    expect((await call('/api/auth/get-session', 'GET', undefined, { cookie })).status).toBe(200);
  });

  test('provider introspection cannot revive a token after reinstall', async () => {
    const secret = randomBytes(32).toString('base64url');
    const { hashOAuthClientSecret } = await import('../services/oauth-client-secrets');
    await database.oauthClient.update({ where: { clientId }, data: {
      public: false, type: 'web', tokenEndpointAuthMethod: 'client_secret_post',
      clientSecret: await hashOAuthClientSecret(secret),
    } });
    const response = await app.fetch(new Request('https://api.openkey.test/api/auth/oauth2/introspect', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: clientId, client_secret: secret, token: accessToken }),
    }));
    expect(response.status, await response.clone().text()).toBe(200);
    expect((await response.json() as { active: boolean }).active).toBe(false);
  });

  test('all enabled credentials are ended one hour after unset with a fake clock', async () => {
    setSystemTime(new Date(Date.now() + 3601_000));
    const keys = await call('/api/auth/jwks');
    const jwks = createLocalJWKSet(await keys.json() as { keys: any[] });
    await expect(jwtVerify(accessToken, jwks)).rejects.toThrow();
    await expect(jwtVerify(idToken, jwks)).rejects.toThrow();
    const { parseStrictSiwe } = await import('../services/signed-subset');
    const signed = parseStrictSiwe(signedDelegation);
    expect(signed.ok).toBe(true);
    if (!signed.ok) throw new Error('Missing signed delegation');
    expect(Date.parse(signed.siwe.expirationTime!)).toBeLessThan(Date.now());
    expect(await database.oauthRefreshToken.count({ where: { userId: 'reviewer-owner' } })).toBe(0);
    expect(await (await call('/api/auth/get-session', 'GET', undefined, { cookie })).json()).toBeNull();
    setSystemTime();
  });

  test('audit output contains neither the code nor its verifier', () => {
    expect(capturedLogs.includes(code)).toBe(false);
    expect(capturedLogs.includes(accounts.credentialDigest(code).toString('hex'))).toBe(false);
    expect(capturedLogs.includes(accounts.credentialDigest(code).toString('base64url'))).toBe(false);
    expect(capturedLogs.includes('reviewer_sign_in')).toBe(true);
  });

  test('the reset log line carries no space id', async () => {
    const { logReviewer } = await import('../log');
    const before = capturedLogs.length;
    (logReviewer as (...values: string[]) => void)('reviewer_admin', 'reset', 'openai', `tinycloud:pkh:eip155:1:${address}:applications`);
    const line = capturedLogs.slice(before);
    expect(line.includes('"result":"reset"')).toBe(true);
    expect(line.includes('space_id')).toBe(false);
    expect(line.includes(address)).toBe(false);
  });

  test('the native delegation schema guard accepts the schema with the reviewer migration applied', async () => {
    const { assertNativeDelegationSchema } = await import('../../../../scripts/native-delegation-schema-guards');
    await expect(assertNativeDelegationSchema(database)).resolves.toBeUndefined();
  });

  test('a restart restores the installed code and keeps live sessions inside their one-hour cap', async () => {
    const signedIn = await call('/api/auth/sign-in/reviewer', 'POST', {
      email: 'openai-review@tinycloud.xyz', code, oauth_query: signedQuery,
    });
    expect(signedIn.status).toBe(200);
    const liveCookie = signedIn.headers.getSetCookie().map((value) => value.split(';')[0]).join('; ');
    const before = await database.reviewerAccount.findUniqueOrThrow({ where: { store: 'openai' } });
    const digest = accounts.credentialDigest(code).toString('hex');
    expect(before.codeDigest).toBe(digest);
    const logged = capturedLogs.length;
    // A new process starts with an empty verifier map and runs this once.
    await accounts.initializeReviewers(database);
    const after = await accounts.reviewerForUser(database, 'reviewer-owner');
    expect(after!.installEpoch).toBe(before.installEpoch);
    expect(after!.codeDigest).toBe(digest);
    expect(after!.user!.reviewerHoldAt).toBeNull();
    expect(accounts.reviewerActive(after)).toBe(true);
    expect(accounts.reviewerCodeMatches(after, code)).toBe(true);
    expect(accounts.reviewerCodeMatches(after, randomBytes(32).toString('base64url'))).toBe(false);
    const current = await call('/api/auth/get-session', 'GET', undefined, { cookie: liveCookie });
    const session = await database.session.findUniqueOrThrow({ where: { id: (await current.json() as { session: { id: string } }).session.id } });
    expect(session.expiresAt.getTime() - session.createdAt.getTime()).toBeLessThanOrEqual(3_600_000);
    expect((await call('/api/auth/sign-in/reviewer', 'POST', {
      email: 'openai-review@tinycloud.xyz', code, oauth_query: signedQuery,
    }, { cookie: liveCookie })).status).toBe(200);
    expect((await call('/api/auth/sign-in/reviewer', 'POST', {
      email: 'openai-review@tinycloud.xyz', code: randomBytes(32).toString('base64url'), oauth_query: signedQuery,
    })).status).toBe(403);
    const lines = capturedLogs.slice(logged);
    expect(lines.includes('boot_restored')).toBe(true);
    expect(capturedLogs.includes(digest)).toBe(false);
    setSystemTime(new Date(session.createdAt.getTime() + 3601_000));
    try {
      expect(await (await call('/api/auth/get-session', 'GET', undefined, { cookie: liveCookie })).json()).toBeNull();
    } finally { setSystemTime(); }
  });

  test('an unset survives a restart', async () => {
    await accounts.unsetReviewer(database, 'openai');
    expect((await database.reviewerAccount.findUniqueOrThrow({ where: { store: 'openai' } })).codeDigest).toBeNull();
    await accounts.initializeReviewers(database);
    const binding = await accounts.reviewerForUser(database, 'reviewer-owner');
    expect(accounts.reviewerActive(binding)).toBe(false);
    expect(binding!.codeDigest).toBeNull();
    expect(binding!.user!.reviewerHoldAt).not.toBeNull();
    expect((await call('/api/auth/sign-in/reviewer', 'POST', {
      email: 'openai-review@tinycloud.xyz', code, oauth_query: signedQuery,
    })).status).toBe(403);
  });

  test('boot durably holds an account that has no persisted code digest', async () => {
    await accounts.installReviewer(database, 'openai', code);
    await database.reviewerAccount.update({ where: { store: 'openai' }, data: { codeDigest: null } });
    await accounts.initializeReviewers(database);
    const binding = await accounts.reviewerForUser(database, 'reviewer-owner');
    expect(accounts.reviewerActive(binding)).toBe(false);
    expect(binding!.user!.reviewerHoldAt).not.toBeNull();
  });

  test('an audience change, a held user and a locked user do not come back after a restart', async () => {
    const pinned = (await database.reviewerAccount.findUniqueOrThrow({ where: { store: 'openai' } })).sessionDid;
    await accounts.installReviewer(database, 'openai', code);
    await accounts.pinReviewerAudience(database, 'openai', pinned);
    expect((await database.reviewerAccount.findUniqueOrThrow({ where: { store: 'openai' } })).codeDigest).toBeNull();
    await accounts.initializeReviewers(database);
    expect(accounts.reviewerActive(await accounts.reviewerForUser(database, 'reviewer-owner'))).toBe(false);

    await accounts.installReviewer(database, 'openai', code);
    await database.user.update({ where: { id: 'reviewer-owner' }, data: { lockedAt: new Date() } });
    await accounts.initializeReviewers(database);
    await database.user.update({ where: { id: 'reviewer-owner' }, data: { lockedAt: null } });
    const binding = await accounts.reviewerForUser(database, 'reviewer-owner');
    expect(accounts.reviewerActive(binding)).toBe(false);
    expect(binding!.codeDigest).toBeNull();
    expect(binding!.user!.reviewerHoldAt).not.toBeNull();
  });

  test('a failed boot initialisation leaves the API serving and every reviewer refused', async () => {
    await accounts.installReviewer(database, 'openai', code);
    expect(accounts.reviewerActive(await accounts.reviewerForUser(database, 'reviewer-owner'))).toBe(true);
    const before = capturedLogs.length;
    const failing = { $transaction: () => Promise.reject(new Error('database unreachable for reviewer-owner')) } as unknown as PrismaClient;
    await expect(accounts.initializeReviewersAtBoot(failing)).resolves.toBeUndefined();
    const line = capturedLogs.slice(before);
    expect(line.includes('reviewer_boot_failed')).toBe(true);
    expect(line.includes('reviewer-owner')).toBe(false);
    expect(line.includes('unreachable')).toBe(false);
    const binding = await accounts.reviewerForUser(database, 'reviewer-owner');
    expect(accounts.reviewerActive(binding)).toBe(false);
    expect(accounts.reviewerCodeMatches(binding, code)).toBe(false);
    expect((await call('/api/auth/sign-in/reviewer', 'POST', {
      email: 'openai-review@tinycloud.xyz', code, oauth_query: signedQuery,
    })).status).toBe(403);
    const runtime = await import('../auth');
    const context = await runtime.auth.$context;
    const ordinaryCookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, 'ordinary-test-token', context.secret)).split(';')[0]!;
    expect((await call('/api/keys', 'GET', undefined, { cookie: ordinaryCookie })).status).toBe(200);
  });

  test('a reset clears the persisted code digest', async () => {
    await accounts.installReviewer(database, 'openai', code);
    const { provisionReviewer } = await import('../services/reviewer-fixtures');
    // The binding transaction commits; the node sign-in then fails because the network is disabled.
    await expect(provisionReviewer(database, 'openai', { clientId, nodeHost: 'https://node.tinycloud.xyz' }, true)).rejects.toThrow();
    const binding = await database.reviewerAccount.findUniqueOrThrow({ where: { store: 'openai' }, include: { user: true } });
    expect(binding.userId).not.toBe('reviewer-owner');
    expect(binding.codeDigest).toBeNull();
    expect(accounts.reviewerActive(binding)).toBe(false);
    await accounts.initializeReviewers(database);
    expect(accounts.reviewerActive(await database.reviewerAccount.findUniqueOrThrow({ where: { store: 'openai' }, include: { user: true } }))).toBe(false);
  });
}
