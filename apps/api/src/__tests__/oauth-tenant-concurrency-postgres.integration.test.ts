import { afterAll, beforeAll, expect, mock, test } from 'bun:test';
import { Client } from 'pg';
import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { generateCodeChallenge } from 'better-auth/oauth2';
import { serializeSignedCookie } from 'better-call';

let createPrismaClient: typeof import('@openkey/db')['createPrismaClient'];
let createTeeClient: typeof import('@openkey/tee')['createTeeClient'];
let authenticateOrganizationCredential: typeof import('../services/organization-credentials')['authenticateOrganizationCredential'];
let issueOrganizationCredential: typeof import('../services/organization-credentials')['issueOrganizationCredential'];
let bindAccountsForVerifiedEmail: typeof import('../services/tenant-managed-accounts')['bindAccountsForVerifiedEmail'];
let createTenantManagedAccount: typeof import('../services/tenant-managed-accounts')['createTenantManagedAccount'];
let disableTenantManagedAccount: typeof import('../services/tenant-managed-accounts')['disableTenantManagedAccount'];
let ejectManagedAccount: typeof import('../services/eject-managed-account')['ejectManagedAccount'];

beforeAll(async () => {
  mock.restore();
  const dbPath = '../../../../packages/db/src/index?oauth-postgres-race';
  const db = await import(dbPath);
  createPrismaClient = db.createPrismaClient;
  mock.module('@openkey/db', () => ({ ...db }));
  const teePath = '../../../../packages/tee/src/index?oauth-postgres-race';
  const tee = await import(teePath);
  createTeeClient = tee.createTeeClient;
  mock.module('@openkey/tee', () => ({ ...tee }));
  const credentialsPath = '../services/organization-credentials?oauth-postgres-race';
  const credentials = await import(credentialsPath);
  authenticateOrganizationCredential = credentials.authenticateOrganizationCredential;
  issueOrganizationCredential = credentials.issueOrganizationCredential;
  const accountsPath = '../services/tenant-managed-accounts?oauth-postgres-race';
  const accounts = await import(accountsPath);
  bindAccountsForVerifiedEmail = accounts.bindAccountsForVerifiedEmail;
  createTenantManagedAccount = accounts.createTenantManagedAccount;
  disableTenantManagedAccount = accounts.disableTenantManagedAccount;
  const ejectPath = '../services/eject-managed-account?oauth-postgres-race';
  const eject = await import(ejectPath);
  ejectManagedAccount = eject.ejectManagedAccount;
});

afterAll(() => mock.restore());

const externalUrl = process.env.MIGRATION_DATABASE_URL ?? (
  process.env.DATABASE_URL && !process.env.DATABASE_URL.startsWith('pglite:')
    ? process.env.DATABASE_URL
    : undefined
);

const migrationNames = [
  '0_init',
  '20260303_add_user_encryption_key',
  '20260628_add_auto_sign_enabled',
  '20260630_add_tinycloud_bootstrap_state',
  '20260714_origin_main_schema_catchup',
  '20260714_zz_origin_main_db_push_reconciliation',
  '20260715_0001_managed_accounts_phase_a_fix',
  '20260715_0002_managed_accounts_registration_api',
  '20260715_0003_managed_accounts_eject_api',
  '20260715_0004_managed_accounts_webhooks',
  '20260720_0001_tenant_managed_email_accounts',
  '20260720_0002_management_credential_default',
  '20260720_0003_tenant_managed_account_guard_fixes',
  '20260720_0004_drop_registration_intent',
  '20260721_0001_better_auth_1_6_oauth_refresh_tokens',
  '20260728_0001_oauth_tenant_lifecycle_guard',
  '20260728_0002_coordinationos_session_grants',
  '20260730_0001_oauth_client_tinycloud_session_policy',
  '20260805_0001_canonical_tinycloud_key',
  '20260805_0002_tinycloud_manage_key_app_preferences',
  '20260805_0003_tinycloud_manage_key_global_preference',
  '20260806_0001_tinycloud_manage_key_lifecycle',
] as const;

const verifier = 'postgres-race-code-verifier-123456789012345678901234567890';
const secret = 'oauth-postgres-race-secret';
const cookieName = '__Secure-better-auth.session_token';

async function waitForAdvisoryWaiters(client: Client, holderPid: number, expected: number): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const result = await client.query<{ count: string }>(`
      SELECT count(*)::text AS count
      FROM pg_locks
      WHERE locktype = 'advisory'
        AND NOT granted
        AND pid <> ${holderPid}
    `);
    if (Number(result.rows[0]?.count ?? 0) >= expected) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`production lifecycle operation did not reach advisory lock queue (expected ${expected} waiter(s))`);
}

async function applyMigrations(client: Client, schema: string) {
  await client.query(`CREATE SCHEMA "${schema}"`);
  await client.query(`SET search_path TO "${schema}"`);
  for (const name of migrationNames) {
    await client.query(await readFile(`packages/db/prisma/migrations/${name}/migration.sql`, 'utf8'));
  }
}

async function setup() {
  if (!externalUrl) throw new Error('PostgreSQL is not configured');
  const schema = `openkey_oauth_race_${randomUUID().replaceAll('-', '')}`;
  const setupClient = new Client({ connectionString: externalUrl });
  await setupClient.connect();
  await applyMigrations(setupClient, schema);
  const now = new Date();
  const timestamp = now.toISOString();
  await setupClient.query(`
    INSERT INTO "user" ("id", "email", "emailVerified", "name", "updatedAt")
      VALUES ('race-user', 'race@example.test', true, 'Race User', '${timestamp}');
    INSERT INTO "session" ("id", "userId", "token", "expiresAt", "createdAt", "updatedAt", "lastPasskeyAt")
      VALUES ('race-session', 'race-user', 'race-session-token', '2099-01-01T00:00:00.000Z', '${timestamp}', '${timestamp}', '${timestamp}');
    INSERT INTO "passkey" ("id", "userId", "publicKey", "credentialID", "deviceType", "backedUp", "createdAt")
      VALUES ('race-passkey', 'race-user', 'race-public-key', 'race-credential', 'singleDevice', false, '${timestamp}');
    INSERT INTO "organization" ("id", "name", "updatedAt")
      VALUES ('race-org', 'Race Org', '${timestamp}');
    INSERT INTO "organization_membership" ("id", "organizationId", "userId", "role", "status", "validFrom")
      VALUES ('race-membership', 'race-org', 'race-user', 'ADMIN', 'ACTIVE', '${timestamp}');
    INSERT INTO "plan_entitlements" ("id", "organizationId", "maxApps", "maxOrganizationMembers", "maxManagedAccounts", "monthlyActiveManagedUsers", "storageBytesPerManagedAccount", "requestsPerMinute", "maxTenantDelegationTtlSeconds", "maxTenantPolicyVersion", "auditRetentionDays", "updatedAt")
      VALUES ('race-entitlements', 'race-org', 3, 3, 3, 3, 1000, 10, 3600, 1, 30, '${timestamp}');
    INSERT INTO "oauth_client" ("id", "clientId", "mode", "name", "redirectUris", "scopes", "skipConsent", "tokenEndpointAuthMethod", "grantTypes", "responseTypes", "type", "public", "contacts", "organizationId", "updatedAt")
      VALUES ('race-client-row', 'race-client', 'TENANT_MANAGED', 'Race Client', ARRAY['https://race.example/callback'], ARRAY['email', 'offline_access'], true, 'none', ARRAY['authorization_code', 'refresh_token'], ARRAY['code'], 'spa', true, ARRAY[]::TEXT[], 'race-org', '${timestamp}');
  `);

  const db = createPrismaClient({ connectionString: externalUrl, schema });
  const tee = createTeeClient();
  const issued = await issueOrganizationCredential(db, {
    organizationId: 'race-org',
    subjectUserId: 'race-user',
    name: 'Race Credential',
  }, now);
  const actor = await authenticateOrganizationCredential(db, issued.secret, now);
  if (actor.kind !== 'MANAGEMENT') throw new Error('Expected management credential');
  const managementCredential = { ...actor, kind: 'MANAGEMENT' as const };
  const account = await createTenantManagedAccount(db, {
    credential: managementCredential,
    idempotencyKey: 'race-account-create',
    email: 'race@example.test',
  }, tee, now);
  await bindAccountsForVerifiedEmail(db, { email: 'race@example.test', userId: 'race-user' });

  const previousDatabaseUrl = process.env.DATABASE_URL;
  const previousDatabaseSchema = process.env.OPENKEY_DATABASE_SCHEMA;
  process.env.DATABASE_URL = externalUrl;
  process.env.OPENKEY_DATABASE_SCHEMA = schema;
  process.env.BETTER_AUTH_URL = 'https://api.openkey.test';
  process.env.BETTER_AUTH_SECRET = secret;
  process.env.WEBAUTHN_RP_ID = 'openkey.test';
  process.env.WEBAUTHN_ORIGIN = 'https://openkey.test';
  process.env.NODE_ENV = 'test';
  process.env.TEE_MODE = 'development';
  process.env.RESEND_API_KEY = '';
  process.env.GOOGLE_CLIENT_ID = '';
  process.env.GOOGLE_CLIENT_SECRET = '';
  const { auth } = await import(`../auth?oauth-postgres-race-${randomUUID()}`);
  if (previousDatabaseUrl === undefined) delete process.env.DATABASE_URL;
  else process.env.DATABASE_URL = previousDatabaseUrl;
  if (previousDatabaseSchema === undefined) delete process.env.OPENKEY_DATABASE_SCHEMA;
  else process.env.OPENKEY_DATABASE_SCHEMA = previousDatabaseSchema;

  const cookie = (await serializeSignedCookie('', 'race-session-token', secret)).replace('=', '');
  async function request(path: string, init?: RequestInit) {
    return auth.handler(new Request(`https://api.openkey.test/api/auth${path}`, {
      ...init,
      headers: {
        cookie: `${cookieName}=${cookie}`,
        ...init?.headers,
      },
    }));
  }
  const challenge = await generateCodeChallenge(verifier);
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: 'race-client',
    redirect_uri: 'https://race.example/callback',
    scope: 'email offline_access',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: 'race-state',
  });
  const authorization = await request(`/oauth2/authorize?${query}`);
  const location = authorization.headers.get('location');
  if (!location) throw new Error('authorization did not return a callback');
  const code = new URL(location).searchParams.get('code');
  if (!code) throw new Error('authorization did not return a code');
  const authorizationCode = code;

  async function exchange() {
    return request('/oauth2/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: authorizationCode, code_verifier: verifier,
        redirect_uri: 'https://race.example/callback', client_id: 'race-client',
      }),
    });
  }
  return { setupClient, db, schema, account, exchange, managementCredential, request };
}

async function runBlockedTransition(
  kind: 'disable' | 'eject',
  ordering: 'lifecycle-first' | 'token-first',
) {
  const fixture = await setup();
  const holder = new Client({ connectionString: externalUrl! });
  await holder.connect();
  await holder.query(`SET search_path TO "${fixture.schema}"`);
  const holderPid = Number((await holder.query<{ pg_backend_pid: number }>('SELECT pg_backend_pid()')).rows[0]?.pg_backend_pid);
  try {
    await holder.query('BEGIN');
    await holder.query(`SELECT pg_advisory_xact_lock(hashtext('oauth-lifecycle:${fixture.account.id}'))`);

    const transitionRequest = () => kind === 'disable'
      ? disableTenantManagedAccount(fixture.db, {
          credential: fixture.managementCredential,
          managedAccountId: fixture.account.id,
          expectedCustodyEpoch: 1,
          idempotencyKey: `race-${kind}-${ordering}`,
        })
      : ejectManagedAccount(fixture.db, {
          ownerUserId: 'race-user', sessionId: 'race-session', managedAccountId: fixture.account.id,
          expectedEpoch: 1, idempotencyKey: `race-${kind}-${ordering}`,
        }, { tee: createTeeClient() });

    let transition: ReturnType<typeof transitionRequest> | undefined;
    let tokenRequest: ReturnType<typeof fixture.exchange>;
    let transitionResult: PromiseSettledResult<Awaited<ReturnType<typeof transitionRequest>>>;
    let tokenResult: PromiseSettledResult<Response>;
    if (ordering === 'lifecycle-first') {
      transition = transitionRequest();
      await waitForAdvisoryWaiters(holder, holderPid, 1);
      tokenRequest = fixture.exchange();
      await waitForAdvisoryWaiters(holder, holderPid, 2);
      await holder.query('COMMIT');
      [transitionResult, tokenResult] = await Promise.allSettled([transition, tokenRequest]);
    } else {
      tokenRequest = fixture.exchange();
      await waitForAdvisoryWaiters(holder, holderPid, 1);
      await holder.query('COMMIT');
      tokenResult = (await Promise.allSettled([tokenRequest]))[0]!;
      transition = transitionRequest();
      transitionResult = (await Promise.allSettled([transition]))[0]!;
    }
    expect(transitionResult.status).toBe('fulfilled');
    expect(tokenResult.status).toBe('fulfilled');
    if (tokenResult.status !== 'fulfilled') throw tokenResult.reason;
    const tokenResponse = tokenResult.value;
    if (ordering === 'lifecycle-first') expect(tokenResponse.status).not.toBe(200);
    else expect(tokenResponse.status).toBe(200);

    const accessTokens = await fixture.db.oauthAccessToken.findMany({ where: { clientId: 'race-client', userId: 'race-user' } });
    const refreshTokens = await fixture.db.oauthRefreshToken.findMany({ where: { clientId: 'race-client', userId: 'race-user' } });
    if (ordering === 'token-first') {
      expect(accessTokens).toHaveLength(1);
      expect(accessTokens[0]!.expiresAt.getTime()).toBeLessThanOrEqual(Date.now());
      expect(refreshTokens).toHaveLength(1);
      expect(refreshTokens[0]!.revoked).toBeInstanceOf(Date);
    } else {
      expect(accessTokens).toHaveLength(0);
      expect(refreshTokens).toHaveLength(0);
    }
  } finally {
    await holder.end();
    await fixture.db.$disconnect();
    await fixture.setupClient.query(`DROP SCHEMA IF EXISTS "${fixture.schema}" CASCADE`).catch(() => undefined);
    await fixture.setupClient.end();
  }
}

test.skipIf(!externalUrl)('disableTenantManagedAccount revokes access and refresh tokens lifecycle-first', async () => {
  await runBlockedTransition('disable', 'lifecycle-first');
}, 60_000);

test.skipIf(!externalUrl)('disableTenantManagedAccount revokes access and refresh tokens token-first', async () => {
  await runBlockedTransition('disable', 'token-first');
}, 60_000);

test.skipIf(!externalUrl)('ejectManagedAccount revokes access and refresh tokens lifecycle-first', async () => {
  await runBlockedTransition('eject', 'lifecycle-first');
}, 60_000);

test.skipIf(!externalUrl)('ejectManagedAccount revokes access and refresh tokens token-first', async () => {
  await runBlockedTransition('eject', 'token-first');
}, 60_000);

async function authorizationCodeIdentity(
  fixture: Awaited<ReturnType<typeof setup>>,
  input: { clientId: string; clientSecret: string; redirectUri: string; verifier: string },
) {
  const challenge = await generateCodeChallenge(input.verifier);
  const authorization = await fixture.request(`/oauth2/authorize?${new URLSearchParams({
    response_type: 'code',
    client_id: input.clientId,
    redirect_uri: input.redirectUri,
    scope: 'openid keys tinycloud:manage-key',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: `state-${input.clientId}`,
  })}`);
  expect(authorization.status).toBe(302);
  const location = authorization.headers.get('location');
  expect(location).toBeTruthy();
  const code = new URL(location!).searchParams.get('code');
  expect(code).toBeTruthy();

  const basic = Buffer.from(`${input.clientId}:${input.clientSecret}`).toString('base64');
  const token = await fixture.request('/oauth2/token', {
    method: 'POST',
    headers: {
      authorization: `Basic ${basic}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code!,
      code_verifier: input.verifier,
      redirect_uri: input.redirectUri,
      client_id: input.clientId,
    }),
  });
  expect(token.status).toBe(200);
  const tokenBody = await token.json() as { access_token: string };
  expect(tokenBody.access_token).toBeTruthy();

  const userinfo = await fixture.request('/oauth2/userinfo', {
    headers: { authorization: `Bearer ${tokenBody.access_token}` },
  });
  expect(userinfo.status).toBe(200);
  const claims = await userinfo.json() as Record<string, unknown>;
  return claims['https://tinycloud.xyz/canonical_identity'];
}

test.skipIf(!externalUrl)('two independent confidential authorization-code clients receive one user canonical identity', async () => {
  const fixture = await setup();
  const canonicalAddress = '0x1111111111111111111111111111111111111111';
  const clients = [
    {
      id: 'canonical-client-one-row', clientId: 'canonical-client-one', clientSecret: 'canonical-client-one-secret',
      redirectUri: 'https://client-one.example/callback', verifier: 'canonical-client-one-verifier-123456789012345678901234567890',
    },
    {
      id: 'canonical-client-two-row', clientId: 'canonical-client-two', clientSecret: 'canonical-client-two-secret',
      redirectUri: 'https://client-two.example/callback', verifier: 'canonical-client-two-verifier-123456789012345678901234567890',
    },
  ];
  try {
    await fixture.db.ethereumKey.create({
      data: {
        id: 'canonical-personal-key', userId: 'race-user', address: canonicalAddress, publicKey: '0x01',
        sealedBlob: 'sealed', sealingContext: 'canonical-personal-key-context-00000000000Q', keyType: 'MANAGED',
        keyPurpose: 'PERSONAL', isCanonicalTinyCloud: true,
      },
    });
    await Promise.all(clients.map((client) => fixture.db.oauthClient.create({
      data: {
        id: client.id,
        clientId: client.clientId,
        clientSecret: createHash('sha256').update(client.clientSecret).digest('base64url'),
        name: client.clientId,
        redirectUris: [client.redirectUri],
        scopes: ['openid', 'keys', 'tinycloud:manage-key'],
        contacts: [],
        mode: 'PERSONAL',
        skipConsent: true,
        tokenEndpointAuthMethod: 'client_secret_basic',
        grantTypes: ['authorization_code'],
        responseTypes: ['code'],
        type: 'web',
        public: false,
      },
    })));

    const first = await authorizationCodeIdentity(fixture, clients[0]!);
    const second = await authorizationCodeIdentity(fixture, clients[1]!);
    const expected = {
      version: 'v1', keyId: 'canonical-personal-key', address: canonicalAddress, chainId: 1,
      did: `did:pkh:eip155:1:${canonicalAddress}`,
      spaceId: `tinycloud:pkh:eip155:1:${canonicalAddress}:applications`,
    };
    expect(first).toEqual(expected);
    expect(second).toEqual(expected);
  } finally {
    await fixture.db.$disconnect();
    await fixture.setupClient.query(`DROP SCHEMA IF EXISTS "${fixture.schema}" CASCADE`).catch(() => undefined);
    await fixture.setupClient.end();
  }
}, 60_000);
