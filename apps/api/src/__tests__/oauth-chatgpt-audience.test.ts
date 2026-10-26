import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { generateCodeChallenge } from 'better-auth/oauth2';
import { serializeSignedCookie } from 'better-call';
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from 'jose';
import type { PrismaClient } from '@openkey/db';

import { CHATGPT_TINYCLOUD_MCP_AUDIENCE, DEFAULT_TINYCLOUD_MCP_AUDIENCE, oauthValidAudiences } from '../oauth-config';

// API unit tests replace modules process-wide. Exercise the real provider and
// tracked database migrations in a separate process, as the MCP registration
// test does.
const root = resolve(import.meta.dir, '../../../..');
if (process.env.OPENKEY_CHATGPT_AUDIENCE_TEST_CHILD !== '1') {
  describe('ChatGPT MCP resource audience list', () => {
    test('lists the base URL, the default resource, the ChatGPT resource, then configured resources', () => {
      expect(CHATGPT_TINYCLOUD_MCP_AUDIENCE).toBe('https://mcp.tinycloud.xyz/chatgpt/mcp');
      expect(oauthValidAudiences('https://api.openkey.test', ' https://mcp.customer.test/mcp, ')).toEqual([
        'https://api.openkey.test',
        DEFAULT_TINYCLOUD_MCP_AUDIENCE,
        CHATGPT_TINYCLOUD_MCP_AUDIENCE,
        'https://mcp.customer.test/mcp',
      ]);
    });

    test('a configured copy of a built-in resource is listed once', () => {
      const audiences = oauthValidAudiences(
        'https://api.openkey.test',
        `${CHATGPT_TINYCLOUD_MCP_AUDIENCE},${DEFAULT_TINYCLOUD_MCP_AUDIENCE}`,
      );
      expect(audiences.filter((value) => value === CHATGPT_TINYCLOUD_MCP_AUDIENCE)).toHaveLength(1);
      expect(audiences.filter((value) => value === DEFAULT_TINYCLOUD_MCP_AUDIENCE)).toHaveLength(1);
    });

    test('resources that are not exactly a listed value are not listed', () => {
      const audiences = oauthValidAudiences('https://api.openkey.test', '');
      for (const near of [
        'https://mcp.tinycloud.xyz/chatgpt/mcp/x',
        'https://mcp.tinycloud.xyz/chatgpt',
        'https://mcp.tinycloud.xyz/chatgpt/mcp/',
        'http://mcp.tinycloud.xyz/chatgpt/mcp',
        'https://MCP.tinycloud.xyz.evil.test/chatgpt/mcp',
      ]) {
        expect(audiences).not.toContain(near);
      }
    });
  });

  test('ChatGPT MCP resource through the real OAuth provider', async () => {
    const child = Bun.spawn([process.execPath, 'test', import.meta.path], {
      cwd: root,
      env: {
        ...process.env,
        OPENKEY_CHATGPT_AUDIENCE_TEST_CHILD: '1',
        NODE_ENV: 'test',
        TEE_MODE: 'development',
        BETTER_AUTH_URL: 'https://api.openkey.test',
        BETTER_AUTH_SECRET: 'chatgpt-audience-isolated-test-secret',
        WEBAUTHN_RP_ID: 'openkey.test',
        WEBAUTHN_ORIGIN: 'https://openkey.test',
        CORS_ORIGIN: 'https://openkey.test',
        OAUTH_DYNAMIC_CLIENT_REGISTRATION: 'true',
        OAUTH_VALID_AUDIENCES: '',
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
  }, 120_000);
} else {
  const issuer = 'https://api.openkey.test/api/auth';
  const callback = 'https://chatgpt.com/connector_platform_oauth_redirect';
  const verifier = 'chatgpt-audience-pkce-verifier-012345678901234567890';
  const requestedScope = 'openid email offline_access tinycloud:mcp';
  const ownerAddress = '0x31d40B62C395B9418C4198363619B11c65cD406F';
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch: (request: Request) => Response | Promise<Response> };
  let cookie: string;

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'openkey-chatgpt-audience-'));
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
    const authModule = await import('../auth');
    prisma = authModule.prisma;
    app = (await import('../index')).default;
    await prisma.user.create({ data: {
      id: 'audience-owner', email: 'audience-owner@example.test', name: 'Audience Owner', emailVerified: true,
    } });
    await prisma.ethereumKey.create({ data: {
      id: 'audience-owner-key', userId: 'audience-owner', address: ownerAddress, publicKey: '0x1', keyType: 'EXTERNAL',
    } });
    const sessionToken = randomUUID();
    await prisma.session.create({ data: {
      id: 'audience-owner-session', userId: 'audience-owner', token: sessionToken,
      expiresAt: new Date(Date.now() + 3_600_000),
    } });
    const context = await authModule.auth.$context;
    cookie = (await serializeSignedCookie(context.authCookies.sessionToken.name, sessionToken, context.secret)).split(';')[0]!;
  }, 90_000);

  afterAll(async () => {
    await prisma?.$disconnect();
    if (directory) await rm(directory, { recursive: true, force: true });
  });

  function call(path: string, init: RequestInit = {}, authenticated = false) {
    return app.fetch(new Request(`${issuer}${path}`, {
      ...init,
      headers: { ...(authenticated ? { cookie } : {}), ...init.headers },
    }));
  }

  async function register() {
    const response = await call('/oauth2/register', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: 'ChatGPT audience check', redirect_uris: [callback],
        token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
      }),
    });
    expect(response.status, await response.clone().text()).toBe(200);
    return stringField(await response.json(), 'client_id');
  }

  function stringField(body: unknown, key: string): string {
    const value: unknown = body && typeof body === 'object' ? Reflect.get(body, key) : undefined;
    if (typeof value !== 'string') throw new Error(`response has no string ${key}`);
    return value;
  }

  type Outcome =
    | { stage: 'authorize' | 'consent' | 'token'; error: string }
    | { stage: 'issued'; accessToken: string };

  // One public PKCE client, scope tinycloud:mcp, authorize + consent + token
  // for the given resource. Reports where (and with what error) it stops.
  async function issue(resource: string): Promise<Outcome> {
    const clientId = await register();
    const query = new URLSearchParams({
      client_id: clientId, response_type: 'code', redirect_uri: callback, scope: requestedScope, resource,
      state: 'audience-state', code_challenge: await generateCodeChallenge(verifier), code_challenge_method: 'S256',
    });
    const authorized = await call(`/oauth2/authorize?${query}`, {}, true);
    const location = new URL(authorized.headers.get('location') ?? issuer, issuer);
    if (authorized.status !== 302 || location.searchParams.has('error')) {
      return { stage: 'authorize', error: `${authorized.status} ${location.searchParams.get('error')} ${location.searchParams.get('error_description')}` };
    }
    const approve = await call('/oauth2/consent', {
      method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://openkey.test' },
      body: JSON.stringify({ accept: true, oauth_query: location.searchParams.toString() }),
    }, true);
    if (approve.status !== 200) return { stage: 'consent', error: `${approve.status} ${await approve.text()}` };
    const redirect = new URL(stringField(await approve.json(), 'url'));
    const code = redirect.searchParams.get('code');
    if (!code) return { stage: 'consent', error: `${redirect.searchParams.get('error')} ${redirect.searchParams.get('error_description')}` };
    const exchanged = await call('/oauth2/token', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId, grant_type: 'authorization_code', code,
        redirect_uri: callback, code_verifier: verifier, resource,
      }),
    });
    if (exchanged.status !== 200) return { stage: 'token', error: `${exchanged.status} ${await exchanged.text()}` };
    return { stage: 'issued', accessToken: stringField(await exchanged.json(), 'access_token') };
  }

  describe('ChatGPT MCP resource', () => {
    test('the exact resource gets a token whose audience is that resource', async () => {
      const outcome = await issue(CHATGPT_TINYCLOUD_MCP_AUDIENCE);
      if (outcome.stage !== 'issued') throw new Error(JSON.stringify(outcome));
      const jwks: JSONWebKeySet = await (await call('/jwks')).json();
      const { payload } = await jwtVerify(outcome.accessToken, createLocalJWKSet(jwks), {
        issuer, audience: CHATGPT_TINYCLOUD_MCP_AUDIENCE,
      });
      expect(payload.aud).toContain(CHATGPT_TINYCLOUD_MCP_AUDIENCE);
      expect(payload.aud).not.toContain(DEFAULT_TINYCLOUD_MCP_AUDIENCE);
      expect(payload.scope).toBe(requestedScope);
    });

    for (const near of [
      'https://mcp.tinycloud.xyz/chatgpt/mcp/x',
      'https://mcp.tinycloud.xyz/chatgpt',
      'https://mcp.tinycloud.xyz/chatgpt/mcp/',
      'http://mcp.tinycloud.xyz/chatgpt/mcp',
      'https://MCP.tinycloud.xyz.evil.test/chatgpt/mcp',
    ]) {
      test(`${near} is refused and no token is issued`, async () => {
        const outcome = await issue(near);
        expect(outcome).toMatchObject({ stage: 'token', error: expect.stringContaining('requested resource invalid') });
      });
    }
  });
}
