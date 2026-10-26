// The token status check for resource servers against the real OAuth provider and a real
// (PGlite) database, with the MCP's token shape: a JWT access token for a resource
// audience, scope tinycloud:mcp, issued to a public PKCE client with no refresh token.
//
// API unit tests replace modules process-wide, so this runs in a separate process,
// as oauth-mcp-registration.test.ts does.

import './tc1777-test-env';
import { afterAll, beforeAll, describe, expect, setSystemTime, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { generateCodeChallenge } from 'better-auth/oauth2';
import { serializeSignedCookie } from 'better-call';
import type { PrismaClient } from '@openkey/db';

const root = resolve(import.meta.dir, '../../../..');
if (process.env.OPENKEY_RESOURCE_INTROSPECT_TEST_CHILD !== '1') {
  test('token status check for resource servers through the real provider', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_RESOURCE_INTROSPECT_TEST_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: 'resource-introspect-isolated-test-secret-0123456789',
        WEBAUTHN_RP_ID: 'openkey.test',
        WEBAUTHN_ORIGIN: 'https://openkey.test',
        CORS_ORIGIN: 'https://openkey.test',
        OAUTH_DYNAMIC_CLIENT_REGISTRATION: 'true',
        OAUTH_VALID_AUDIENCES: 'https://other.example/mcp,https://mcp.tinycloud.xyz/chatgpt/mcp',
        RESEND_API_KEY: '',
        GOOGLE_CLIENT_ID: '',
        GOOGLE_CLIENT_SECRET: '',
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
  }, 180_000);
} else {
  const { hashClientSecret, resourceServerMetadata } = await import('../services/resource-server');
  const issuer = 'https://api.openkey.test/api/auth';
  const route = 'https://api.openkey.test/api/oauth/resource/introspect';
  const resource = 'https://mcp.tinycloud.xyz/mcp';
  const otherResource = 'https://other.example/mcp';
  const chatgptResource = 'https://mcp.tinycloud.xyz/chatgpt/mcp';
  const publicCallback = 'https://chatgpt.com/connector_platform_oauth_redirect';
  const confidentialCallback = 'https://rs.example/cb';
  const ownerAddress = '0x31d40B62C395B9418C4198363619B11c65cD406F';
  let directory: string;
  let prisma: PrismaClient;
  let authModule: typeof import('../auth');
  let app: { fetch: (request: Request) => Response | Promise<Response> };

  interface Confidential { clientId: string; secret: string }
  let resourceServer: Confidential;
  let plainConfidential: Confidential;

  beforeAll(async () => {
    directory = await mkdtemp('/var/tmp/tc1627-introspect.');
    const database = new PGlite(directory);
    try {
      const migrations = (await readdir(join(root, 'packages/db/prisma/migrations'), { withFileTypes: true }))
        .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
      for (const migration of migrations) {
        await database.exec(await readFile(join(root, 'packages/db/prisma/migrations', migration, 'migration.sql'), 'utf8'));
      }
    } finally {
      await database.close();
    }
    process.env.DATABASE_URL = `pglite:${directory}`;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    authModule = await import('../auth');
    prisma = authModule.prisma;
    app = (await import('../index')).default;
    await prisma.user.create({ data: { id: 'u1', email: 'u1@example.test', name: 'U One', emailVerified: true } });
    await prisma.ethereumKey.create({ data: { id: 'k1', userId: 'u1', address: ownerAddress, publicKey: '0x1', keyType: 'EXTERNAL' } });
    resourceServer = await confidentialClient('MCP resource server', resourceServerMetadata([resource, chatgptResource]));
    plainConfidential = await confidentialClient('Plain confidential client', null);
  }, 90_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  function call(path: string, init: RequestInit = {}, cookie?: string) {
    return app.fetch(new Request(`${issuer}${path}`, { ...init, headers: { ...(cookie ? { cookie } : {}), ...init.headers } }));
  }

  async function confidentialClient(name: string, metadata: object | null): Promise<Confidential> {
    const secret = randomBytes(32).toString('base64url');
    const clientId = `ok_${randomBytes(8).toString('hex')}`;
    await prisma.oauthClient.create({ data: {
      id: randomUUID(), clientId, clientSecret: hashClientSecret(secret), name,
      redirectUris: [confidentialCallback], scopes: ['openid'], disabled: false, skipConsent: false,
      enableEndSession: false, tokenEndpointAuthMethod: 'client_secret_basic', grantTypes: ['authorization_code'],
      responseTypes: ['code'], type: 'web', public: false, contacts: [], ...(metadata ? { metadata } : {}),
    } });
    return { clientId, secret };
  }

  async function newSession(id: string) {
    const token = randomUUID();
    await prisma.session.create({ data: { id, userId: 'u1', token, expiresAt: new Date(Date.now() + 3_600_000) } });
    const context = await authModule.auth.$context;
    const cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, token, context.secret)).split(';')[0]!;
    return { id, cookie };
  }

  async function registerPublicClient(): Promise<string> {
    const response = await call('/oauth2/register', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: 'MCP public client', redirect_uris: [publicCallback], token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code'], response_types: ['code'],
      }),
    });
    expect(response.status, await response.clone().text()).toBe(200);
    return ((await response.json()) as { client_id: string }).client_id;
  }

  /** Authorize with PKCE, consent, and exchange the code, for the given client and audience. */
  async function issue(clientId: string, session: { cookie: string }, audience: string | string[] | null = resource, scope = 'tinycloud:mcp') {
    const verifier = `tc1627-${randomUUID()}${randomUUID()}`;
    const audiences = audience === null ? [] : Array.isArray(audience) ? audience : [audience];
    const query = new URLSearchParams({
      client_id: clientId, response_type: 'code', redirect_uri: publicCallback, scope, state: 'st',
      code_challenge: await generateCodeChallenge(verifier), code_challenge_method: 'S256',
    });
    for (const value of audiences) query.append('resource', value);
    const authorize = await call(`/oauth2/authorize?${query}`, {}, session.cookie);
    let location = new URL(authorize.headers.get('location')!, issuer);
    if (location.pathname === '/oauth/consent') {
      const approve = await call('/oauth2/consent', {
        method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://openkey.test' },
        body: JSON.stringify({ accept: true, oauth_query: location.searchParams.toString() }),
      }, session.cookie);
      expect(approve.status, await approve.clone().text()).toBe(200);
      location = new URL(((await approve.json()) as { url: string }).url);
    }
    const code = location.searchParams.get('code');
    expect(code, location.toString()).toBeTruthy();
    const exchanged = await call('/oauth2/token', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: (() => {
        const form = new URLSearchParams({
          client_id: clientId, grant_type: 'authorization_code', code: code!, redirect_uri: publicCallback, code_verifier: verifier,
        });
        for (const value of audiences) form.append('resource', value);
        return form;
      })(),
    });
    expect(exchanged.status, await exchanged.clone().text()).toBe(200);
    return (await exchanged.json()) as { access_token: string; refresh_token?: string; scope: string; expires_in: number };
  }

  /** A fresh public client, session and MCP-shaped token. */
  async function mcpToken(label: string, audience: string | string[] | null = resource, scope = 'tinycloud:mcp') {
    const clientId = await registerPublicClient();
    const session = await newSession(`session-${label}`);
    const tokens = await issue(clientId, session, audience, scope);
    return { clientId, session, accessToken: tokens.access_token, tokens };
  }

  const basic = (id: string, secret: string) => `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`;
  async function check(token: string, credentials: Confidential | null = resourceServer, how: 'basic' | 'form' = 'basic') {
    const form = new URLSearchParams({ token });
    const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' };
    if (credentials && how === 'basic') headers.authorization = basic(credentials.clientId, credentials.secret);
    if (credentials && how === 'form') { form.set('client_id', credentials.clientId); form.set('client_secret', credentials.secret); }
    const response = await app.fetch(new Request(route, { method: 'POST', headers, body: form }));
    return { status: response.status, headers: response.headers, body: (await response.json()) as Record<string, unknown> };
  }
  const INACTIVE = { active: false };

  describe('a live MCP token', () => {
    test('is active, with exactly the listed fields, and no refresh token was issued', async () => {
      const { clientId, accessToken, tokens } = await mcpToken('live');
      expect(tokens.refresh_token).toBeUndefined();
      const result = await check(accessToken);
      expect(result.status).toBe(200);
      expect(result.headers.get('cache-control')).toBe('no-store');
      expect(Object.keys(result.body).sort()).toEqual(['active', 'aud', 'client_id', 'exp', 'iat', 'iss', 'scope', 'sub', 'token_type']);
      expect(result.body).toMatchObject({
        active: true, scope: 'tinycloud:mcp', client_id: clientId, sub: 'u1', aud: resource, iss: issuer, token_type: 'Bearer',
      });
      expect((result.body.exp as number) - (result.body.iat as number)).toBe(300);
      expect(JSON.stringify(result.body)).not.toContain('did:pkh');
      expect(JSON.stringify(result.body)).not.toContain('session-live');
    });

    test('the form-field client authentication works too', async () => {
      const { accessToken } = await mcpToken('form');
      expect((await check(accessToken, resourceServer, 'form')).body.active).toBe(true);
    });

    test('a token for the chatgpt resource is active for a server registered for both resources', async () => {
      const { accessToken } = await mcpToken('chatgpt', chatgptResource);
      const result = await check(accessToken);
      expect(result.body).toMatchObject({ active: true, aud: chatgptResource });
    });

    test('a token whose audience is an array (an openid scope adds the userinfo audience) reports only the allowed resource, as an array', async () => {
      const { accessToken } = await mcpToken('array-audience', resource, 'openid tinycloud:mcp');
      const [, payload] = accessToken.split('.') as [string, string];
      expect(JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')).aud).toEqual([resource, `${issuer}/oauth2/userinfo`]);
      const result = await check(accessToken);
      expect(result.body).toMatchObject({ active: true, aud: [resource], scope: 'openid tinycloud:mcp' });
    });
  });

  describe('a token whose standing has ended is inactive', () => {
    test('consent deleted', async () => {
      const { clientId, accessToken } = await mcpToken('consent');
      expect((await check(accessToken)).body.active).toBe(true);
      await prisma.oauthConsent.deleteMany({ where: { clientId } });
      expect((await check(accessToken)).body).toEqual(INACTIVE);
    });

    test('consent withdrawn and given again does not bring an earlier token back, and a new token is active', async () => {
      const { clientId, session, accessToken } = await mcpToken('reconnect');
      expect((await check(accessToken)).body.active).toBe(true);
      await prisma.oauthConsent.deleteMany({ where: { clientId } });
      expect((await check(accessToken)).body).toEqual(INACTIVE);
      // Consent times and `iat` are whole seconds: give the new consent a later second than the old token.
      setSystemTime(new Date(Date.now() + 5_000));
      try {
        const again = await issue(clientId, session);
        expect(await prisma.oauthConsent.count({ where: { clientId } })).toBe(1);
        expect((await check(accessToken)).body).toEqual(INACTIVE);
        expect((await check(again.access_token)).body.active).toBe(true);
      } finally {
        setSystemTime();
      }
    });

    test('user signs out', async () => {
      const { session, accessToken } = await mcpToken('signout');
      expect((await check(accessToken)).body.active).toBe(true);
      const out = await call('/sign-out', { method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://openkey.test' }, body: '{}' }, session.cookie);
      expect(out.status).toBe(200);
      expect(await prisma.session.count({ where: { id: session.id } })).toBe(0);
      expect((await check(accessToken)).body).toEqual(INACTIVE);
    });

    test('every session of the user is deleted', async () => {
      const { accessToken } = await mcpToken('sessions');
      expect((await check(accessToken)).body.active).toBe(true);
      await prisma.session.deleteMany({ where: { userId: 'u1' } });
      expect((await check(accessToken)).body).toEqual(INACTIVE);
    });

    test('the issuing client is disabled', async () => {
      const { clientId, accessToken } = await mcpToken('disabled');
      expect((await check(accessToken)).body.active).toBe(true);
      await prisma.oauthClient.update({ where: { clientId }, data: { disabled: true } });
      expect((await check(accessToken)).body).toEqual(INACTIVE);
    });

    test('the issuing client is deleted', async () => {
      const { clientId, accessToken } = await mcpToken('deleted');
      await prisma.oauthConsent.deleteMany({ where: { clientId } });
      await prisma.oauthClient.delete({ where: { clientId } });
      expect((await check(accessToken)).body).toEqual(INACTIVE);
    });
  });

  describe('audience and bad tokens', () => {
    test('a token for another resource, which the server is not allowed to check, is inactive', async () => {
      const { accessToken } = await mcpToken('other-audience', otherResource);
      const result = await check(accessToken);
      expect(result.status).toBe(200);
      expect(result.body).toEqual(INACTIVE);
    });

    test('a tampered, expired or opaque token answers 200 inactive', async () => {
      const { accessToken } = await mcpToken('bad');
      const [header, payload, signature] = accessToken.split('.') as [string, string, string];
      const flipped = signature.slice(0, 8) + (signature[8] === 'A' ? 'B' : 'A') + signature.slice(9);
      for (const token of [`${header}.${payload}.${flipped}`, `${header}.${payload}.`, 'garbage', `${header}.${payload.slice(0, -3)}AAA.${signature}`]) {
        const result = await check(token);
        expect(result.status, token.slice(0, 20)).toBe(200);
        expect(result.body, token.slice(0, 20)).toEqual(INACTIVE);
      }
      const opaque = (await mcpToken('opaque', null)).accessToken;
      expect(opaque.split('.')).toHaveLength(1);
      expect((await check(opaque)).body).toEqual(INACTIVE);
      setSystemTime(new Date(Date.now() + 400_000));
      try {
        expect((await check(accessToken)).body).toEqual(INACTIVE);
      } finally {
        setSystemTime();
      }
    });
  });

  describe('client authentication', () => {
    test('a wrong secret, a public client, a plain confidential client and no credentials are 401', async () => {
      const { clientId, accessToken } = await mcpToken('auth');
      const expected = { error_description: 'invalid client credentials', error: 'invalid_client' };
      for (const credentials of [
        { clientId: resourceServer.clientId, secret: 'not-the-secret' },
        { clientId, secret: 'public-clients-have-none' },
        plainConfidential,
      ]) {
        const result = await check(accessToken, credentials);
        expect(result.status).toBe(401);
        expect(result.body).toEqual(expected);
      }
      const none = await check(accessToken, null);
      expect(none.status).toBe(401);
      expect(none.body).toEqual({ error_description: 'missing required credentials', error: 'invalid_client' });
    });

    test('a disabled resource server is a 401', async () => {
      const disabled = await confidentialClient('Disabled resource server', resourceServerMetadata([resource]));
      const { accessToken } = await mcpToken('disabled-rs');
      expect((await check(accessToken, disabled)).body.active).toBe(true);
      await prisma.oauthClient.update({ where: { clientId: disabled.clientId }, data: { disabled: true } });
      expect((await check(accessToken, disabled)).status).toBe(401);
    });
  });

  describe('the provider endpoint is unchanged', () => {
    async function stock(credentials: Confidential | null, token: string) {
      const form = new URLSearchParams({ token });
      const response = await call('/oauth2/introspect', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', ...(credentials ? { authorization: basic(credentials.clientId, credentials.secret) } : {}) },
        body: form,
      });
      return { status: response.status, body: (await response.json()) as Record<string, unknown> };
    }

    test('a resource server still gets inactive for a token issued to another client, and the issuer still sees the full payload', async () => {
      const { accessToken } = await mcpToken('stock-public');
      expect(await stock(resourceServer, accessToken)).toEqual({ status: 200, body: INACTIVE });
      expect(await stock(null, accessToken)).toEqual({ status: 401, body: { error_description: 'missing required credentials', error: 'invalid_client' } });

      // Issue to a confidential client: its own introspection returns the provider's whole payload.
      const owner = await confidentialClient('Token owner', null);
      await prisma.oauthClient.update({ where: { clientId: owner.clientId }, data: { scopes: ['openid', 'tinycloud:mcp'] } });
      const session = await newSession('session-stock-owner');
      const verifier = `tc1627-${randomUUID()}${randomUUID()}`;
      const query = new URLSearchParams({
        client_id: owner.clientId, response_type: 'code', redirect_uri: confidentialCallback, scope: 'tinycloud:mcp', state: 'st',
        code_challenge: await generateCodeChallenge(verifier), code_challenge_method: 'S256', resource,
      });
      let location = new URL((await call(`/oauth2/authorize?${query}`, {}, session.cookie)).headers.get('location')!, issuer);
      if (location.pathname === '/oauth/consent') {
        const approve = await call('/oauth2/consent', {
          method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://openkey.test' },
          body: JSON.stringify({ accept: true, oauth_query: location.searchParams.toString() }),
        }, session.cookie);
        location = new URL(((await approve.json()) as { url: string }).url);
      }
      const exchanged = await call('/oauth2/token', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic(owner.clientId, owner.secret) },
        body: new URLSearchParams({ grant_type: 'authorization_code', code: location.searchParams.get('code')!, redirect_uri: confidentialCallback, code_verifier: verifier, resource }),
      });
      const ownToken = ((await exchanged.json()) as { access_token: string }).access_token;
      const own = await stock(owner, ownToken);
      expect(own.status).toBe(200);
      expect(own.body.active).toBe(true);
      expect(Object.keys(own.body)).toContain('https://tinycloud.xyz/owner_dids');
      expect(own.body.sid).toBe('session-stock-owner');
      // And the new route treats that same token as any other, for a server allowed its audience.
      expect((await check(ownToken)).body.active).toBe(true);
    });
  });
}
