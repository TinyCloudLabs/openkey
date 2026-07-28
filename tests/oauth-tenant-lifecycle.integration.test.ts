import { afterAll, beforeEach, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { generateCodeChallenge } from 'better-auth/oauth2';
import { serializeSignedCookie } from 'better-call';
import { decodeJwt } from 'jose';

process.env.BETTER_AUTH_URL = 'https://api.openkey.test';
process.env.BETTER_AUTH_SECRET = 'oauth-lifecycle-test-secret';
process.env.WEBAUTHN_RP_ID = 'openkey.test';
process.env.WEBAUTHN_ORIGIN = 'https://openkey.test';
process.env.NODE_ENV = 'test';
process.env.TEE_MODE = 'development';
process.env.RESEND_API_KEY = '';
process.env.GOOGLE_CLIENT_ID = '';
process.env.GOOGLE_CLIENT_SECRET = '';

const originalDatabaseUrl = process.env.DATABASE_URL;
const databaseDirectory = await mkdtemp(join(tmpdir(), 'openkey-oauth-lifecycle-'));
process.env.DATABASE_URL = `pglite:${databaseDirectory}`;

const migrationNames = (await readdir('packages/db/prisma/migrations', { withFileTypes: true }))
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort();
const pglite = new PGlite(databaseDirectory);

for (const migrationName of migrationNames) {
  await pglite.exec(await readFile(`packages/db/prisma/migrations/${migrationName}/migration.sql`, 'utf8'));
}

const sessionToken = 'oauth-session-token';
const clientId = 'tenant-lifecycle-client';
const confidentialClientId = 'tenant-confidential-client';
const confidentialClientSecret = 'tenant-confidential-secret';
const personalClientId = 'personal-oauth-client';
const redirectUri = 'https://consumer.example/callback';
const confidentialRedirectUri = 'https://confidential.example/callback';
const personalRedirectUri = 'https://personal.example/callback';
const verifier = 'oauth-code-verifier-123456789012345678901234567890';
const cookieName = '__Secure-better-auth.session_token';
const hashClientSecret = (secret: string) => createHash('sha256').update(secret).digest('base64url');

await pglite.exec(`
  INSERT INTO "user" ("id", "email", "emailVerified", "name", "updatedAt") VALUES ('oauth-user', 'managed@example.test', true, 'Managed User', '2026-07-28T12:00:00.000Z');
  INSERT INTO "session" ("id", "userId", "token", "expiresAt", "createdAt", "updatedAt") VALUES ('oauth-session', 'oauth-user', '${sessionToken}', '2099-01-01T00:00:00.000Z', '2026-07-28T12:00:00.000Z', '2026-07-28T12:00:00.000Z');
  INSERT INTO "organization" ("id", "name", "updatedAt") VALUES ('oauth-org', 'OAuth Org', '2026-07-28T12:00:00.000Z');
  INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "sealedBlob", "keyType", "keyPurpose", "sealingContext") VALUES ('oauth-key', 'oauth-user', '0x0000000000000000000000000000000000000001', '0x1', 'sealed', 'MANAGED', 'MANAGED_ACCOUNT', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
  INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "sealedBlob", "keyType", "keyPurpose", "sealingContext") VALUES ('oauth-personal-key', 'oauth-user', '0x0000000000000000000000000000000000000002', '0x2', 'sealed', 'MANAGED', 'PERSONAL', 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB0');
  INSERT INTO "managed_account" ("id", "organizationId", "subjectEmail", "keyId", "ownerUserId", "state", "custodyEpoch", "updatedAt") VALUES ('oauth-account', 'oauth-org', 'managed@example.test', 'oauth-key', 'oauth-user', 'PROVISIONED', 0, '2026-07-28T12:00:00.000Z');
  INSERT INTO "key_custody" ("id", "managedAccountId", "custodianType", "custodianId", "epoch", "activatedAt") VALUES ('oauth-custody-1', 'oauth-account', 'ORGANIZATION', 'oauth-org', 1, '2026-07-28T12:00:00.000Z');
  INSERT INTO "possession_event" ("id", "managedAccountId", "keyId", "epoch", "eventHash", "fromPrincipal", "toPrincipal", "reason", "credentialPolicyHash", "accountKeySignature", "createdAt") VALUES ('oauth-event-1', 'oauth-account', 'oauth-key', 1, 'oauth-hash-1', 'none', 'organization:oauth-org', 'INITIAL_ACTIVATION', 'oauth-policy', 'oauth-signature-1', '2026-07-28T12:00:00.000Z');
  UPDATE "managed_account" SET "state" = 'MANAGED', "custodyEpoch" = 1, "custodyHeadId" = 'oauth-custody-1' WHERE "id" = 'oauth-account';
  INSERT INTO "oauth_client" ("id", "clientId", "mode", "name", "redirectUris", "scopes", "skipConsent", "tokenEndpointAuthMethod", "grantTypes", "responseTypes", "type", "public", "contacts", "organizationId", "metadata", "updatedAt") VALUES ('oauth-client-row', '${clientId}', 'TENANT_MANAGED', 'Lifecycle Test', ARRAY['${redirectUri}'], ARRAY['openid', 'email', 'keys', 'offline_access'], true, 'none', ARRAY['authorization_code', 'refresh_token'], ARRAY['code'], 'spa', true, ARRAY[]::TEXT[], 'oauth-org', '{"openkeyClientMode":"TENANT_MANAGED","openkeyOrganizationId":"oauth-org"}'::jsonb, '2026-07-28T12:00:00.000Z');
  INSERT INTO "oauth_client" ("id", "clientId", "clientSecret", "mode", "name", "redirectUris", "scopes", "skipConsent", "tokenEndpointAuthMethod", "grantTypes", "responseTypes", "type", "public", "contacts", "organizationId", "metadata", "updatedAt") VALUES ('oauth-confidential-row', '${confidentialClientId}', '${hashClientSecret(confidentialClientSecret)}', 'TENANT_MANAGED', 'Confidential Lifecycle Test', ARRAY['${confidentialRedirectUri}'], ARRAY['openid', 'email', 'keys', 'offline_access'], true, 'client_secret_basic', ARRAY['authorization_code', 'refresh_token'], ARRAY['code'], 'web', false, ARRAY[]::TEXT[], 'oauth-org', '{"openkeyClientMode":"TENANT_MANAGED","openkeyOrganizationId":"oauth-org"}'::jsonb, '2026-07-28T12:00:00.000Z');
  INSERT INTO "oauth_client" ("id", "clientId", "mode", "name", "redirectUris", "scopes", "skipConsent", "tokenEndpointAuthMethod", "grantTypes", "responseTypes", "type", "public", "contacts", "organizationId", "metadata", "updatedAt") VALUES ('oauth-personal-row', '${personalClientId}', 'PERSONAL', 'Personal Test', ARRAY['${personalRedirectUri}'], ARRAY['openid', 'email', 'keys', 'offline_access', 'tinycloud:mcp'], true, 'none', ARRAY['authorization_code', 'refresh_token'], ARRAY['code'], 'spa', true, ARRAY[]::TEXT[], NULL, '{"openkeyClientMode":"PERSONAL","openkeyOrganizationId":"oauth-org"}'::jsonb, '2026-07-28T12:00:00.000Z');
`);
await pglite.close();

// Query-bust the production module so this disposable PGlite-backed auth
// instance never shares the module singleton with aggregate auth claim tests.
// The instance is still explicitly disconnected below, releasing its PGlite
// reference and allowing the temporary directory to be removed safely.
const { auth, prisma } = await import('../apps/api/src/auth?oauth-lifecycle-isolated');

async function execSql(sql: string) {
  const statements = sql.split(/;\s*(?=\S)/).map((part) => part.trim()).filter(Boolean);
  await prisma.$transaction(async (transaction) => {
    for (const statement of statements) await transaction.$executeRawUnsafe(statement);
  });
}

const signedSessionCookie = (await serializeSignedCookie('', sessionToken, process.env.BETTER_AUTH_SECRET!)).replace('=', '');

async function requestAuth(path: string, init?: RequestInit, sessionCookie: string | null = `${cookieName}=${signedSessionCookie}`) {
  return auth.handler(new Request(`https://api.openkey.test/api/auth${path}`, {
    ...init,
    headers: {
      ...(sessionCookie ? { cookie: sessionCookie } : {}),
      ...init?.headers,
    },
  }));
}

async function authorize(
  sessionCookie = `${cookieName}=${signedSessionCookie}`,
  options: { clientId?: string; redirectUri?: string; scope?: string; state?: string } = {},
) {
  const selectedClientId = options.clientId ?? clientId;
  const selectedRedirectUri = options.redirectUri ?? redirectUri;
  const challenge = await generateCodeChallenge(verifier);
  const query = new URLSearchParams({
    response_type: 'code', client_id: selectedClientId, redirect_uri: selectedRedirectUri,
    scope: options.scope ?? 'email offline_access', code_challenge: challenge,
    code_challenge_method: 'S256', state: options.state ?? 'oauth-state',
  });
  const response = await requestAuth(`/oauth2/authorize?${query}`, undefined, sessionCookie);
  const location = response.headers.get('location');
  return { response, location: location ? new URL(location) : null };
}

async function authorizeForLogin() {
  const challenge = await generateCodeChallenge(verifier);
  const query = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: redirectUri,
    scope: 'email offline_access', code_challenge: challenge,
    code_challenge_method: 'S256', state: 'oauth-login-state',
  });
  const response = await requestAuth(`/oauth2/authorize?${query}`, undefined, null);
  const location = response.headers.get('location');
  return { response, location: location ? new URL(location) : null };
}

async function signInThroughOAuth() {
  const login = await authorizeForLogin();
  expect(login.response.status).toBe(302);
  expect(login.location?.origin).toBe('https://openkey.test');
  expect(login.location?.searchParams.get('client_id')).toBe(clientId);
  expect(login.location?.searchParams.get('sig')).toBeTruthy();
  return requestAuth('/sign-in/email-otp', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      email: 'managed@example.test',
      otp: '000000',
      oauth_query: login.location?.searchParams.toString(),
    }),
  }, null);
}

async function token(body: Record<string, string>, selectedClientId = clientId) {
  return requestAuth('/oauth2/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: selectedClientId, ...body }),
  });
}

async function confidentialToken(body: Record<string, string>) {
  return requestAuth('/oauth2/token', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${Buffer.from(`${confidentialClientId}:${confidentialClientSecret}`).toString('base64')}`,
    },
    body: new URLSearchParams(body),
  });
}

async function exchange(code: string, selectedClientId = clientId, selectedRedirectUri = redirectUri) {
  return token({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: selectedRedirectUri }, selectedClientId);
}

beforeEach(async () => {
  await execSql(`
    UPDATE "managed_account" SET "state" = 'MANAGED' WHERE "id" = 'oauth-account';
    UPDATE "user" SET "emailVerified" = true WHERE "id" = 'oauth-user';
    UPDATE "oauth_client" SET "organizationId" = 'oauth-org' WHERE "clientId" = '${clientId}';
    UPDATE "oauth_client" SET "metadata" = NULL WHERE "clientId" IN ('${clientId}', '${personalClientId}');
    INSERT INTO "verification" ("id", "identifier", "value", "expiresAt", "createdAt", "updatedAt")
      VALUES ('oauth-otp', 'sign-in-otp-managed@example.test', '000000:0', '2099-01-01T00:00:00.000Z', '2026-07-28T12:00:00.000Z', '2026-07-28T12:00:00.000Z')
      ON CONFLICT ("id") DO UPDATE SET "value" = EXCLUDED."value", "expiresAt" = EXCLUDED."expiresAt";
  `);
});

afterAll(async () => {
  await prisma.$disconnect();
  if (originalDatabaseUrl === undefined) delete process.env.DATABASE_URL;
  else process.env.DATABASE_URL = originalDatabaseUrl;
  await rm(databaseDirectory, { recursive: true, force: true });
});

describe('tenant-managed OAuth lifecycle at real provider boundaries', () => {
  test('issues an authorization code through the real post-login session-cookie path', async () => {
    const signInResponse = await signInThroughOAuth();
    expect(signInResponse.status).toBe(200);
    const resumed = await signInResponse.json() as { redirect?: boolean; url?: string };
    expect(resumed.redirect).toBe(true);
    expect(resumed.url).toBeTruthy();
    const callback = new URL(resumed.url!);
    expect(callback.origin + callback.pathname).toBe(redirectUri);
    expect(callback.searchParams.get('state')).toBe('oauth-login-state');
    expect(callback.searchParams.get('iss')).toBe('https://api.openkey.test/api/auth');
    const code = callback.searchParams.get('code');
    expect(code).toBeTruthy();
    const exchanged = await exchange(code!);
    expect(exchanged.status).toBe(200);
    const tokens = await exchanged.json() as { access_token: string; refresh_token: string };
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.refresh_token).toBeTruthy();
  });

  test('issues default opaque tokens while managed, then blocks both code exchange and refresh after disable', async () => {
    const firstAuthorization = await authorize();
    expect(firstAuthorization.response.status).toBe(302);
    const firstCode = firstAuthorization.location?.searchParams.get('code');
    expect(firstCode).toBeTruthy();
    const firstTokenResponse = await exchange(firstCode!);
    expect(firstTokenResponse.status).toBe(200);
    const firstTokens = await firstTokenResponse.json() as { access_token: string; refresh_token: string };
    expect(firstTokens.access_token).toBeTruthy();
    expect(firstTokens.refresh_token).toBeTruthy();

    const secondAuthorization = await authorize();
    const secondCode = secondAuthorization.location?.searchParams.get('code');
    expect(secondCode).toBeTruthy();
    await execSql(`UPDATE "managed_account" SET "state" = 'DISABLED' WHERE "id" = 'oauth-account'`);
    expect((await exchange(secondCode!)).status).not.toBe(200);
    expect((await token({ grant_type: 'refresh_token', refresh_token: firstTokens.refresh_token })).status).not.toBe(200);
  });

  test('blocks disabled identities at the authorize boundary', async () => {
    await execSql(`UPDATE "managed_account" SET "state" = 'DISABLED' WHERE "id" = 'oauth-account'`);
    expect((await authorize()).response.status).not.toBe(302);
  });

  test('fails closed for an unverified tenant identity', async () => {
    await execSql(`UPDATE "user" SET "emailVerified" = false WHERE "id" = 'oauth-user'`);
    expect((await authorize()).response.status).not.toBe(302);
  });

  test('fails closed when tenant mode has no authoritative organization', async () => {
    await execSql(`UPDATE "oauth_client" SET "organizationId" = NULL WHERE "clientId" = '${clientId}'`);
    expect((await authorize()).response.status).not.toBe(302);
  });

  test('uses OAuth client columns instead of inconsistent metadata for ID-token keys', async () => {
    await execSql(`
      UPDATE "oauth_client"
      SET "metadata" = '{"openkeyClientMode":"TENANT_MANAGED","openkeyOrganizationId":"wrong-org"}'::jsonb
      WHERE "clientId" = '${clientId}';
    `);
    const authorization = await authorize(`${cookieName}=${signedSessionCookie}`, { scope: 'openid email keys offline_access' });
    const code = authorization.location?.searchParams.get('code');
    expect(code).toBeTruthy();
    const response = await token({
      grant_type: 'authorization_code',
      code: code!,
      code_verifier: verifier,
      redirect_uri: redirectUri,
      resource: 'https://api.openkey.test',
    });
    expect(response.status).toBe(200);
    const tokens = await response.json() as { id_token: string; access_token: string };
    const idToken = decodeJwt(tokens.id_token) as { keys?: Array<{ keyId: string }> };
    expect(idToken.keys?.map((key) => key.keyId)).toEqual(['oauth-key']);
    const userInfoResponse = await requestAuth('/oauth2/userinfo', {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    }, null);
    expect((await userInfoResponse.json() as { keys?: Array<{ keyId: string }> }).keys?.map((key) => key.keyId)).toEqual(['oauth-key']);
    const otherOrgAccounts = await prisma.managedAccount.count({ where: { organizationId: 'wrong-org' } });
    expect(otherOrgAccounts).toBe(0);
  });

  test('preserves PERSONAL opaque exchange and refresh behavior', async () => {
    const authorization = await authorize(`${cookieName}=${signedSessionCookie}`, {
      clientId: personalClientId,
      redirectUri: personalRedirectUri,
      scope: 'email keys offline_access',
    });
    const code = authorization.location?.searchParams.get('code');
    expect(code).toBeTruthy();
    const response = await exchange(code!, personalClientId, personalRedirectUri);
    expect(response.status).toBe(200);
    const tokens = await response.json() as { access_token: string; refresh_token: string };
    expect(tokens.access_token.split('.')).toHaveLength(1);
    expect((await token({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token }, personalClientId)).status).toBe(200);
  });

  test('preserves TinyCloud owner-DID claims for PERSONAL JWT access tokens', async () => {
    const authorization = await authorize(`${cookieName}=${signedSessionCookie}`, {
      clientId: personalClientId,
      redirectUri: personalRedirectUri,
      scope: 'openid tinycloud:mcp offline_access',
    });
    const code = authorization.location?.searchParams.get('code');
    expect(code).toBeTruthy();
    const response = await token({
      grant_type: 'authorization_code',
      code: code!,
      code_verifier: verifier,
      redirect_uri: personalRedirectUri,
      resource: 'https://mcp.tinycloud.xyz/mcp',
    }, personalClientId);
    expect(response.status).toBe(200);
    const tokens = await response.json() as { access_token: string };
    const accessToken = decodeJwt(tokens.access_token) as { ['https://tinycloud.xyz/owner_dids']?: string[] };
    expect(accessToken['https://tinycloud.xyz/owner_dids']).toEqual([
        'did:pkh:eip155:1:0x0000000000000000000000000000000000000002',
    ]);
  });

  test('runs the post-login lifecycle hook when oauth_query is carried by OTP sign-in', async () => {
    await execSql(`UPDATE "managed_account" SET "state" = 'DISABLED' WHERE "id" = 'oauth-account'`);
    const signInResponse = await signInThroughOAuth();
    expect(signInResponse.status).not.toBe(200);
    expect(signInResponse.headers.get('set-cookie')).toBeNull();
  });

  test('confidential client_secret_basic exchange and refresh are blocked after disable', async () => {
    const authorization = await authorize(`${cookieName}=${signedSessionCookie}`, { clientId: confidentialClientId, redirectUri: confidentialRedirectUri, scope: 'email offline_access' });
    const code = authorization.location?.searchParams.get('code');
    expect(code).toBeTruthy();
    const exchanged = await confidentialToken({ grant_type: 'authorization_code', code: code!, code_verifier: verifier, redirect_uri: confidentialRedirectUri });
    expect(exchanged.status).toBe(200);
    const tokens = await exchanged.json() as { refresh_token: string };
    expect(tokens.refresh_token).toBeTruthy();
    const second = await authorize(`${cookieName}=${signedSessionCookie}`, { clientId: confidentialClientId, redirectUri: confidentialRedirectUri, scope: 'email offline_access' });
    const secondCode = second.location?.searchParams.get('code');
    expect(secondCode).toBeTruthy();
    await execSql(`UPDATE "managed_account" SET "state" = 'DISABLED' WHERE "id" = 'oauth-account'`);
    expect((await confidentialToken({ grant_type: 'authorization_code', code: secondCode!, code_verifier: verifier, redirect_uri: confidentialRedirectUri })).status).not.toBe(200);
    expect((await confidentialToken({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token })).status).not.toBe(200);
  });

  test('blocks USER_OWNED post-login issuance, opaque exchange, and refresh using client columns when metadata is absent', async () => {
    const firstAuthorization = await authorize();
    const firstCode = firstAuthorization.location?.searchParams.get('code');
    expect(firstCode).toBeTruthy();
    const firstTokenResponse = await exchange(firstCode!);
    expect(firstTokenResponse.status).toBe(200);
    const firstTokens = await firstTokenResponse.json() as { refresh_token: string };

    const confidentialAuthorization = await authorize(`${cookieName}=${signedSessionCookie}`, {
      clientId: confidentialClientId,
      redirectUri: confidentialRedirectUri,
      scope: 'email offline_access',
    });
    const confidentialCode = confidentialAuthorization.location?.searchParams.get('code');
    expect(confidentialCode).toBeTruthy();
    const confidentialTokenResponse = await confidentialToken({
      grant_type: 'authorization_code',
      code: confidentialCode!,
      code_verifier: verifier,
      redirect_uri: confidentialRedirectUri,
    });
    expect(confidentialTokenResponse.status).toBe(200);
    const confidentialTokens = await confidentialTokenResponse.json() as { refresh_token: string };
    expect(confidentialTokens.refresh_token).toBeTruthy();

    const secondAuthorization = await authorize();
    const secondCode = secondAuthorization.location?.searchParams.get('code');
    expect(secondCode).toBeTruthy();
    const confidentialSecondAuthorization = await authorize(`${cookieName}=${signedSessionCookie}`, {
      clientId: confidentialClientId,
      redirectUri: confidentialRedirectUri,
      scope: 'email offline_access',
    });
    const confidentialSecondCode = confidentialSecondAuthorization.location?.searchParams.get('code');
    expect(confidentialSecondCode).toBeTruthy();
    await execSql(`
      UPDATE "key_custody" SET "revokedAt" = '2026-07-28T12:01:00.000Z' WHERE "id" = 'oauth-custody-1';
      INSERT INTO "key_custody" ("id", "managedAccountId", "custodianType", "custodianId", "epoch", "activatedAt") VALUES ('oauth-custody-2', 'oauth-account', 'USER', 'oauth-user', 2, '2026-07-28T12:01:00.000Z');
      INSERT INTO "possession_event" ("id", "managedAccountId", "keyId", "epoch", "previousEventHash", "eventHash", "fromPrincipal", "toPrincipal", "reason", "credentialPolicyHash", "accountKeySignature", "createdAt") VALUES ('oauth-event-2', 'oauth-account', 'oauth-key', 2, 'oauth-hash-1', 'oauth-hash-2', 'organization:oauth-org', 'user:oauth-user', 'OWNER_REQUEST', 'oauth-policy', 'oauth-signature-2', '2026-07-28T12:01:00.000Z');
      UPDATE "managed_account" SET "state" = 'USER_OWNED', "custodyEpoch" = 2, "custodyHeadId" = 'oauth-custody-2' WHERE "id" = 'oauth-account';
    `);
    const signInResponse = await signInThroughOAuth();
    expect(signInResponse.status).not.toBe(200);
    expect((await exchange(secondCode!)).status).not.toBe(200);
    expect((await token({ grant_type: 'refresh_token', refresh_token: firstTokens.refresh_token })).status).not.toBe(200);
    expect((await confidentialToken({
      grant_type: 'authorization_code',
      code: confidentialSecondCode!,
      code_verifier: verifier,
      redirect_uri: confidentialRedirectUri,
    })).status).not.toBe(200);
    expect((await confidentialToken({
      grant_type: 'refresh_token',
      refresh_token: confidentialTokens.refresh_token,
    })).status).not.toBe(200);
  });

});
