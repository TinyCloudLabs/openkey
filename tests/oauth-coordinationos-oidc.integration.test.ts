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
const clientId = 'coordinationos-client';
const secret = 'coordinationos-client-secret';
const callback = 'https://coordination.example/auth/v1/callback';
const verifier = 'coordinationos-code-verifier-12345678901234567890';
const scopes = ['openid', 'email', 'keys', 'tinycloud:session'];
const secretHash = createHash('sha256').update(secret).digest('base64url');

await pglite.exec(`
  INSERT INTO "user" ("id", "email", "emailVerified", "name", "updatedAt")
    VALUES ('${userId}', 'alice@example.test', true, 'Alice', CURRENT_TIMESTAMP);
  INSERT INTO "session" ("id", "userId", "token", "expiresAt", "createdAt", "updatedAt")
    VALUES ('coordinationos-session', '${userId}', '${sessionToken}', '2099-01-01T00:00:00.000Z', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
  INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "sealedBlob", "keyType", "keyPurpose", "sealingContext")
    VALUES ('personal-key', '${userId}', '0x31d40B62C395B9418C4198363619B11c65cD406F', '0x1', 'sealed', 'MANAGED', 'PERSONAL', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
  INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "sealedBlob", "keyType", "keyPurpose", "sealingContext")
    VALUES ('tenant-key', '${userId}', '0x1111111111111111111111111111111111111111', '0x2', 'sealed', 'MANAGED', 'MANAGED_ACCOUNT', 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA');
  INSERT INTO "ethereum_keys" ("id", "userId", "address", "publicKey", "keyType", "keyPurpose")
    VALUES ('external-key', '${userId}', '0x2222222222222222222222222222222222222222', '0x3', 'EXTERNAL', 'PERSONAL');
  INSERT INTO "oauth_client" (
    "id", "clientId", "clientSecret", "mode", "name", "redirectUris", "scopes",
    "skipConsent", "tokenEndpointAuthMethod", "grantTypes", "responseTypes",
    "type", "public", "contacts", "updatedAt"
  ) VALUES (
    'coordinationos-client-row', '${clientId}', '${secretHash}', 'PERSONAL',
    'CoordinationOS', ARRAY['${callback}'], ARRAY['openid','email','keys','tinycloud:session'],
    false, 'client_secret_basic', ARRAY['authorization_code'], ARRAY['code'],
    'web', false, ARRAY[]::TEXT[], CURRENT_TIMESTAMP
  );
  INSERT INTO "oauth_consent" ("id", "userId", "clientId", "scopes", "updatedAt")
    VALUES ('coordinationos-consent', '${userId}', '${clientId}', ARRAY['openid','email','keys','tinycloud:session'], CURRENT_TIMESTAMP);
`);
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
  if (originalDatabaseUrl === undefined) delete process.env.DATABASE_URL;
  else process.env.DATABASE_URL = originalDatabaseUrl;
  await rm(databaseDirectory, { recursive: true, force: true });
});

describe('CoordinationOS OIDC provider integration', () => {
  test('client_secret_basic issues short-lived opaque token with filtered claims and no refresh token', async () => {
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
    const code = location.searchParams.get('code');
    expect(code).toBeTruthy();

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

  test('wrong secret and non-identical callback fail exchange', async () => {
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
    expect((await exchange(await authorize(), secret, `${callback}?changed=1`)).status).not.toBe(200);
  });
});
