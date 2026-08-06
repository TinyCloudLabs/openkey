import { afterAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateCodeChallenge } from 'better-auth/oauth2';
import { serializeSignedCookie } from 'better-call';
import { decodeJwt } from 'jose';

process.env.BETTER_AUTH_URL = 'https://api.openkey.test';
process.env.BETTER_AUTH_SECRET = 'coordinationos-oidc-test-secret';
process.env.WEBAUTHN_RP_ID = 'openkey.test';
process.env.WEBAUTHN_ORIGIN = 'https://openkey.test';
process.env.NODE_ENV = 'test';
process.env.TEE_MODE = 'development';
process.env.RESEND_API_KEY = '';
process.env.GOOGLE_CLIENT_ID = '';
process.env.GOOGLE_CLIENT_SECRET = '';
process.env.ADMIN_API_KEY = 'coordinationos-admin-key';
process.env.OPENKEY_COORDINATIONOS_SUPABASE_CALLBACK_URI =
  'https://coordination.example/auth/v1/callback';

const originalDatabaseUrl = process.env.DATABASE_URL;
const databaseDirectory = await mkdtemp(join(tmpdir(), 'openkey-coordinationos-oidc-'));
process.env.DATABASE_URL = `pglite:${databaseDirectory}`;
const pglite = new PGlite(databaseDirectory);
const migrationNames = (await readdir('packages/db/prisma/migrations', { withFileTypes: true }))
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort();
for (const migrationName of migrationNames) {
  await pglite.exec(await readFile(`packages/db/prisma/migrations/${migrationName}/migration.sql`, 'utf8'));
}

const userId = 'coordinationos-user';
const sessionToken = 'coordinationos-session-token';
const callback = 'https://coordination.example/auth/v1/callback';
const verifier = 'coordinationos-code-verifier-12345678901234567890';
const scopes = ['openid', 'email', 'keys', 'tinycloud:session'];

await pglite.exec(`
  INSERT INTO "user" ("id", "email", "emailVerified", "name", "updatedAt")
    VALUES ('${userId}', 'alice@example.test', true, 'Alice', CURRENT_TIMESTAMP);
  INSERT INTO "session" ("id", "userId", "token", "expiresAt", "createdAt", "updatedAt")
    VALUES ('coordinationos-session', '${userId}', '${sessionToken}', '2099-01-01T00:00:00.000Z', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
  INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "sealedBlob", "keyType", "sealingContext", "isCanonicalTinyCloud")
    VALUES ('personal-key', '${userId}', '0x31d40B62C395B9418C4198363619B11c65cD406F', '0x1', 'sealed', 'MANAGED', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', true);
  INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "keyType")
    VALUES ('external-key', '${userId}', '0x2222222222222222222222222222222222222222', '0x3', 'EXTERNAL');
`);

const oauthAdmin = await import('../apps/api/src/routes/oauth-admin?coordinationos-oidc-admin');
oauthAdmin.setOauthAdminDatabaseForTests({
  oauthClient: {
    create: async ({ data }: any) => {
      await pglite.query(`
        INSERT INTO "oauth_client" (
          "id", "clientId", "clientSecret", "name", "uri", "icon",
          "redirectUris", "scopes", "disabled", "skipConsent", "enableEndSession",
          "tokenEndpointAuthMethod", "grantTypes", "responseTypes", "type", "public",
          "contacts", "metadata", "updatedAt"
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7::TEXT[], $8::TEXT[], $9, $10, $11,
          $12, $13::TEXT[], $14::TEXT[], $15, $16, $17::TEXT[], $18::JSONB,
          CURRENT_TIMESTAMP
        )
      `, [
        data.id, data.clientId, data.clientSecret, data.name, data.uri, data.icon,
        data.redirectUris, data.scopes, data.disabled, data.skipConsent, data.enableEndSession,
        data.tokenEndpointAuthMethod, data.grantTypes, data.responseTypes, data.type,
        data.public, data.contacts, JSON.stringify(data.metadata),
      ]);
      return { ...data, createdAt: new Date('2026-07-28T20:00:00.000Z') };
    },
  },
});
const registration = await oauthAdmin.oauthAdminRouter.request('/clients', {
  method: 'POST',
  headers: {
    authorization: 'Bearer coordinationos-admin-key',
    'content-type': 'application/json',
  },
  body: JSON.stringify({
    name: 'CoordinationOS',
    type: 'web',
    redirectUris: [callback],
    scopes,
    autoApprove: true,
  }),
});
if (registration.status !== 201) throw new Error(`web client registration failed: ${registration.status}`);
const registered = await registration.json() as {
  client: { clientId: string };
  clientSecret: string;
};
const clientId = registered.client.clientId;
const secret = registered.clientSecret;
const secretHash = createHash('sha256').update(secret).digest('base64url');
oauthAdmin.setOauthAdminDatabaseForTests();
await pglite.close();

const { auth, prisma } = await import('../apps/api/src/auth?coordinationos-oidc-isolated');
const signedCookie = (await serializeSignedCookie(
  '',
  sessionToken,
  process.env.BETTER_AUTH_SECRET!,
)).replace('=', '');

function requestAuth(path: string, init?: RequestInit, withSession = true) {
  return auth.handler(new Request(`https://api.openkey.test/api/auth${path}`, {
    ...init,
    headers: {
      ...(withSession ? { cookie: `__Secure-better-auth.session_token=${signedCookie}` } : {}),
      ...init?.headers,
    },
  }));
}

afterAll(async () => {
  await prisma.$disconnect();
  await oauthAdmin.disconnectOauthAdminDefaultDatabaseForTests();
  if (originalDatabaseUrl === undefined) delete process.env.DATABASE_URL;
  else process.env.DATABASE_URL = originalDatabaseUrl;
  await rm(databaseDirectory, { recursive: true, force: true });
});

describe('CoordinationOS OIDC provider integration', () => {
  test('admin-created confidential client persists only its hash and migration tables exist', async () => {
    const storedClient = await prisma.oauthClient.findUnique({ where: { clientId } });
    expect(storedClient).toMatchObject({
      clientSecret: secretHash,
      redirectUris: [callback],
      scopes,
      tokenEndpointAuthMethod: 'client_secret_basic',
      grantTypes: ['authorization_code'],
      responseTypes: ['code'],
      type: 'web',
      public: false,
      skipConsent: true,
    });
    expect(storedClient?.clientSecret).not.toBe(secret);
    expect(await prisma.coordinationosSessionGrant.count()).toBe(0);
    expect(await prisma.coordinationosSigningDecision.count()).toBe(0);
  });

  test('auto-approved confidential client redirects directly to its callback and exchanges a PKCE code without consent', async () => {
    oauthAdmin.setOauthAdminDatabaseForTests(prisma);
    const patch = await oauthAdmin.oauthAdminRouter.request(`/clients/${clientId}`, {
      method: 'PATCH',
      headers: {
        authorization: 'Bearer coordinationos-admin-key',
        'content-type': 'application/json',
      },
      body: JSON.stringify({ name: 'CoordinationOS renamed', disabled: false }),
    });
    expect(patch.status).toBe(200);
    expect(JSON.stringify(await patch.json())).not.toContain(secret);
    const listed = await oauthAdmin.oauthAdminRouter.request('/clients', {
      headers: { authorization: 'Bearer coordinationos-admin-key' },
    });
    const fetched = await oauthAdmin.oauthAdminRouter.request(`/clients/${clientId}`, {
      headers: { authorization: 'Bearer coordinationos-admin-key' },
    });
    for (const response of [listed, fetched]) {
      expect(response.status).toBe(200);
      const text = await response.text();
      expect(text).not.toContain(secret);
      expect(text).not.toContain(secretHash);
      expect(text).not.toContain('clientSecret');
    }
    oauthAdmin.setOauthAdminDatabaseForTests();
    expect(await prisma.oauthClient.findUnique({ where: { clientId } })).toMatchObject({
      redirectUris: [callback],
      scopes,
      name: 'CoordinationOS renamed',
    });

    const challenge = await generateCodeChallenge(verifier);
    const nonce = 'coordinationos-oidc-nonce';
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: clientId,
      redirect_uri: callback,
      scope: scopes.join(' '),
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state: 'coordinationos-state',
      nonce,
    });
    const authorization = await requestAuth(`/oauth2/authorize?${query}`);
    expect(authorization.status).toBe(302);
    const location = new URL(authorization.headers.get('location')!);
    expect(location.origin + location.pathname).toBe(callback);
    const code = location.searchParams.get('code');
    expect(code).toBeTruthy();
    expect(location.searchParams.get('state')).toBe('coordinationos-state');
    expect(await prisma.oauthConsent.count({ where: { clientId } })).toBe(0);

    const exchange = await requestAuth('/oauth2/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${Buffer.from(`${clientId}:${secret}`).toString('base64')}`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code!,
        code_verifier: verifier,
        redirect_uri: callback,
      }),
    }, false);
    expect(exchange.status).toBe(200);
    const tokens = await exchange.json() as {
      access_token: string;
      expires_in: number;
      id_token: string;
      refresh_token?: string;
    };
    expect(tokens.expires_in).toBe(300);
    expect(JSON.stringify(tokens)).not.toContain(secret);
    expect(tokens.refresh_token).toBeUndefined();
    expect(tokens.access_token.split('.')).toHaveLength(1);

    const idToken = decodeJwt(tokens.id_token) as any;
    expect(idToken).toMatchObject({
      aud: clientId,
      nonce,
      email: 'alice@example.test',
      email_verified: true,
      emailVerified: true,
    });
    expect(idToken.keys).toEqual([{
      keyId: 'personal-key',
      address: '0x31d40B62C395B9418C4198363619B11c65cD406F',
      keyType: 'MANAGED',
    }]);

    const userinfo = await requestAuth('/oauth2/userinfo', {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    }, false);
    expect(userinfo.status).toBe(200);
    expect(await userinfo.json()).toMatchObject({
      email: 'alice@example.test',
      email_verified: true,
      emailVerified: true,
      keys: [{ keyId: 'personal-key', keyType: 'MANAGED' }],
    });

    const stored = await prisma.oauthAccessToken.findUnique({
      where: { token: createHash('sha256').update(tokens.access_token).digest('base64url') },
    });
    expect(stored).toBeTruthy();
    expect(stored?.token).not.toBe(tokens.access_token);
  });

  test('normal confidential clients still redirect to consent when no consent exists', async () => {
    oauthAdmin.setOauthAdminDatabaseForTests(prisma);
    const registration = await oauthAdmin.oauthAdminRouter.request('/clients', {
      method: 'POST',
      headers: {
        authorization: 'Bearer coordinationos-admin-key',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        name: 'Normal client',
        type: 'web',
        redirectUris: [callback],
        scopes,
        autoApprove: false,
      }),
    });
    expect(registration.status).toBe(201);
    const normal = await registration.json() as { client: { clientId: string; autoApprove: boolean } };
    expect(normal.client.autoApprove).toBeFalse();
    oauthAdmin.setOauthAdminDatabaseForTests();

    const challenge = await generateCodeChallenge(verifier);
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: normal.client.clientId,
      redirect_uri: callback,
      scope: scopes.join(' '),
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state: 'normal-client-state',
      nonce: 'normal-client-nonce',
    });
    const authorization = await requestAuth(`/oauth2/authorize?${query}`);
    expect(authorization.status).toBe(302);
    const location = new URL(authorization.headers.get('location')!);
    expect(location.pathname).toBe('/oauth/consent');
    expect(location.searchParams.get('code')).toBeNull();
    expect(await prisma.oauthConsent.count({ where: { clientId: normal.client.clientId } })).toBe(0);
  });

  test('wrong secret and every non-identical callback fail real Basic-auth code exchange', async () => {
    const challenge = await generateCodeChallenge(verifier);
    const authorize = async () => {
      const query = new URLSearchParams({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: callback,
        scope: scopes.join(' '),
        code_challenge: challenge,
        code_challenge_method: 'S256',
        state: crypto.randomUUID(),
      });
      const response = await requestAuth(`/oauth2/authorize?${query}`);
      return new URL(response.headers.get('location')!).searchParams.get('code')!;
    };
    const exchange = (code: string, suppliedSecret: string, redirectUri: string) =>
      requestAuth('/oauth2/token', {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: `Basic ${Buffer.from(`${clientId}:${suppliedSecret}`).toString('base64')}`,
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          code_verifier: verifier,
          redirect_uri: redirectUri,
        }),
      }, false);

    expect((await exchange(await authorize(), 'wrong-secret', callback)).status).not.toBe(200);
    for (const changedCallback of [
      `${callback}?changed=1`,
      `${callback}#fragment`,
      'https://COORDINATION.example/auth/v1/callback',
      'https://coordination.example:443/auth/v1/callback',
      'https://coordination.example/auth/v1/callback/',
      'https://coordination.example/auth/v1/%63allback',
      'https://alternate.example/auth/v1/callback',
    ]) {
      expect((await exchange(await authorize(), secret, changedCallback)).status).not.toBe(200);
    }
  });
});
