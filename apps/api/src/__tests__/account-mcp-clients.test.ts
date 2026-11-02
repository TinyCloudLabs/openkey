import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { readdir, readFile } from 'node:fs/promises';
import { createMiddleware } from 'hono/factory';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { mockModules, replaceModules } from './mock-module';

// The real migration chain on PGlite: the consent-withdrawal trigger is part of
// what these routes rely on.
let database: PGlite;
let prisma: PrismaClient;
let sessionUserId = 'user-a';
const savedEnv = { CORS_ORIGIN: process.env.CORS_ORIGIN, TEE_MODE: process.env.TEE_MODE };

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', { id: sessionUserId, email: `${sessionUserId}@example.test` });
      return next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({
    createPrismaClient: () => new Proxy({}, {
      get: (_target, name) => {
        const value = Reflect.get(prisma, name);
        return typeof value === 'function' ? value.bind(prisma) : value;
      },
    }),
  }),
});

beforeAll(async () => {
  process.env.CORS_ORIGIN = 'https://openkey.test';
  process.env.TEE_MODE = 'production';
  const root = new URL('../../../../packages/db/prisma/migrations/', import.meta.url);
  const names = (await readdir(root, { withFileTypes: true })).filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
  database = new PGlite();
  await database.waitReady;
  for (const name of names) await database.exec(await readFile(new URL(`${name}/migration.sql`, root), 'utf8'));
  prisma = new PrismaClient({ adapter: new PrismaPGlite(database) });
}, 120_000);

afterAll(async () => {
  await prisma.$disconnect();
  await database.close();
  for (const [name, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

const MCP = 'tinycloud:mcp';
const DELEGATION = 'tinycloud:delegation';
const MANAGE_KEY = 'tinycloud:manage-key';

async function call<T = unknown>(method: string, path: string, body?: unknown, headers: Record<string, string> = { origin: 'https://openkey.test' }) {
  const { accountRouter } = await import('../routes/account?account-mcp-clients-test' as string);
  const response = await accountRouter.request(path, {
    method,
    headers: { 'content-type': 'application/json', ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: response.status, body: await response.json() as T };
}
type McpApp = { kind: string; consentId: string; clientId: string; name: string; host: string | null; connectedAt: string; scopes: string[] };
type App = { clientId: string };
type ListBody = { apps: App[]; mcpApps: McpApp[]; activity: unknown[]; mode: string; policyEpoch: number };
const list = () => call<ListBody>('GET', '/tinycloud-apps');
const disconnectMcp = (consentId: string, body: unknown = { confirmation: 'DISCONNECT' }) => call('DELETE', `/tinycloud-apps/mcp/${consentId}`, body);

async function reset() {
  await database.exec(`TRUNCATE "oauth_access_token", "oauth_refresh_token", "tinycloud_native_grant", "tinycloud_native_request",
    "tinycloud_native_consent_generation", "oauth_consent", "oauth_client", "user" CASCADE`);
  for (const id of ['user-a', 'user-b']) await prisma.user.create({ data: { id, email: `${id}@example.test` } });
  for (const [clientId, name, uri] of [
    ['client-mcp', 'Research Assistant', 'https://mcp.example.test/app'],
    ['client-mcp-b', 'Other Assistant', null],
    ['client-plain', 'Plain App', 'https://plain.example.test'],
    ['client-delegation', 'Device App', 'https://device.example.test'],
    ['client-manage', 'Signing App', 'https://signing.example.test'],
  ] as const) {
    await prisma.oauthClient.create({ data: { id: `row-${clientId}`, clientId, name, uri, redirectUris: [], scopes: [] } });
  }
}
async function consent(id: string, userId: string, clientId: string, scopes: string[]) {
  await prisma.oauthConsent.create({ data: { id, userId, clientId, scopes } });
}
/** An active native grant plus its refresh and access token rows, as the provider stores them. */
async function nativeSession(userId: string, clientId: string, n: string, consentId: string) {
  await prisma.tinyCloudNativeGrant.create({ data: {
    id: `grant-${n}`, userId, clientId, consentId, consentGeneration: BigInt(0), keyId: `key-${n}`, address: '0x1111111111111111111111111111111111111111',
    sessionDid: 'did:key:z', sessionJwk: {}, sessionJkt: `jkt-${n}`, spaceId: 'space', approvedPermissions: {}, ttlSeconds: 60,
    tinycloudHost: 'https://node.example.test', refreshTokenHash: `refresh-${n}`, absoluteExpiresAt: new Date(Date.now() + 3_600_000),
  } });
  await prisma.oauthRefreshToken.create({ data: { id: `rt-${n}`, token: `refresh-${n}`, clientId, userId, scopes: [], expiresAt: new Date(Date.now() + 3_600_000) } });
  await prisma.oauthAccessToken.create({ data: { id: `at-${n}`, token: `access-${n}`, clientId, userId, refreshId: `rt-${n}`, scopes: [], expiresAt: new Date(Date.now() + 3_600_000) } });
}
/** A refresh token and an access token with no native grant, as the provider stores them for an MCP app. */
async function plainTokens(userId: string, clientId: string, n: string) {
  await prisma.oauthRefreshToken.create({ data: { id: `rt-${n}`, token: `refresh-${n}`, clientId, userId, scopes: [], expiresAt: new Date(Date.now() + 3_600_000) } });
  await prisma.oauthAccessToken.create({ data: { id: `at-${n}`, token: `access-${n}`, clientId, userId, refreshId: `rt-${n}`, scopes: [], expiresAt: new Date(Date.now() + 3_600_000) } });
}
async function tokenRows(userId: string, clientId: string) {
  return {
    refresh: await prisma.oauthRefreshToken.count({ where: { userId, clientId } }),
    access: await prisma.oauthAccessToken.count({ where: { userId, clientId } }),
  };
}
async function sessionState(clientId: string, n: string, userId = 'user-a') {
  const grant = await prisma.tinyCloudNativeGrant.findUnique({ where: { id: `grant-${n}` }, select: { status: true, revokedReason: true } });
  const generation = await prisma.tinyCloudNativeConsentGeneration.findUnique({ where: { userId_clientId: { userId, clientId } } });
  return {
    grant,
    generation: generation ? Number(generation.generation) : 0,
    refresh: await prisma.oauthRefreshToken.count({ where: { token: `refresh-${n}` } }),
    access: await prisma.oauthAccessToken.count({ where: { token: `access-${n}` } }),
  };
}

beforeEach(async () => {
  sessionUserId = 'user-a';
  await reset();
});

describe('account connected MCP apps', () => {
  test('lists the signed-in user\'s MCP consents with name, host, time and scopes, never another user\'s', async () => {
    await consent('c-a1', 'user-a', 'client-mcp', ['openid', MCP]);
    await consent('c-a2', 'user-a', 'client-mcp-b', [MCP]);
    await consent('c-b1', 'user-b', 'client-mcp', [MCP]);
    await consent('c-a3', 'user-a', 'client-plain', ['openid']);

    const mine = await list();
    expect(mine.status).toBe(200);
    expect(mine.body.mcpApps.map((app) => app.consentId).sort()).toEqual(['c-a1', 'c-a2']);
    const research = mine.body.mcpApps.find((app) => app.consentId === 'c-a1');
    expect(research).toMatchObject({
      kind: 'mcp', clientId: 'client-mcp', name: 'Research Assistant', host: 'mcp.example.test', scopes: ['openid', MCP],
    });
    expect(Number.isNaN(Date.parse(research!.connectedAt))).toBe(false);
    expect(mine.body.mcpApps.find((app) => app.consentId === 'c-a2')).toMatchObject({ name: 'Other Assistant', host: null });
    expect(JSON.stringify(mine.body)).not.toContain('c-b1');

    sessionUserId = 'user-b';
    expect((await list()).body.mcpApps.map((app) => app.consentId)).toEqual(['c-b1']);
  });

  test('another user\'s consent id is a 404 and the consent survives', async () => {
    await consent('c-b1', 'user-b', 'client-mcp', [MCP]);
    const refused = await disconnectMcp('c-b1');
    expect(refused.status).toBe(404);
    expect(await prisma.oauthConsent.count({ where: { id: 'c-b1' } })).toBe(1);
    expect(await prisma.tinyCloudNativeConsentGeneration.count()).toBe(0);
    expect((await disconnectMcp('no-such-consent')).status).toBe(404);
  });

  test('disconnect needs the typed confirmation and a same-site browser request', async () => {
    await consent('c-a1', 'user-a', 'client-mcp', [MCP]);
    expect((await disconnectMcp('c-a1', {})).status).toBe(400);
    expect((await disconnectMcp('c-a1', { confirmation: 'yes' })).status).toBe(400);
    expect((await call('DELETE', '/tinycloud-apps/mcp/c-a1', { confirmation: 'DISCONNECT' }, {})).status).toBe(403);
    expect((await call('DELETE', '/tinycloud-apps/mcp/c-a1', { confirmation: 'DISCONNECT' }, { origin: 'https://openkey.test', authorization: 'Bearer token' })).status).toBe(403);
    expect((await call('DELETE', '/tinycloud-apps/mcp/c-a1', { confirmation: 'DISCONNECT' }, { origin: 'https://evil.example' })).status).toBe(403);
    expect(await prisma.oauthConsent.count({ where: { id: 'c-a1' } })).toBe(1);
  });

  test('an MCP-only consent with plain provider tokens ends with no token rows; other clients and users keep theirs', async () => {
    // No native grant: these are the rows the provider writes for an MCP app.
    await consent('c-mcp', 'user-a', 'client-mcp', [MCP]);
    await consent('c-b-mcp', 'user-b', 'client-mcp', [MCP]);
    await consent('c-plain', 'user-a', 'client-plain', ['openid']);
    await plainTokens('user-a', 'client-mcp', 'a-mcp');
    await plainTokens('user-b', 'client-mcp', 'b-mcp');
    await plainTokens('user-a', 'client-plain', 'a-plain');

    expect((await disconnectMcp('c-mcp')).status).toBe(200);

    expect(await tokenRows('user-a', 'client-mcp')).toEqual({ refresh: 0, access: 0 });
    expect(await tokenRows('user-b', 'client-mcp')).toEqual({ refresh: 1, access: 1 });
    expect(await tokenRows('user-a', 'client-plain')).toEqual({ refresh: 1, access: 1 });
    expect(await prisma.oauthConsent.count({ where: { id: { in: ['c-b-mcp', 'c-plain'] } } })).toBe(2);
  });

  test('a refused disconnect leaves the tokens of a consent it does not own or that has no MCP scope', async () => {
    await consent('c-b-mcp', 'user-b', 'client-mcp', [MCP]);
    await plainTokens('user-b', 'client-mcp', 'b-mcp');
    await consent('c-plain', 'user-a', 'client-plain', ['openid']);
    await plainTokens('user-a', 'client-plain', 'a-plain');

    expect((await disconnectMcp('c-b-mcp')).status).toBe(404);
    expect((await disconnectMcp('c-plain')).status).toBe(404);
    expect(await tokenRows('user-b', 'client-mcp')).toEqual({ refresh: 1, access: 1 });
    expect(await tokenRows('user-a', 'client-plain')).toEqual({ refresh: 1, access: 1 });
  });

  test('disconnect removes the consent and has the same grant and token effect as the existing delete', async () => {
    // Same shape for both paths: consent, an active native grant, its refresh and access token.
    await consent('c-mcp', 'user-a', 'client-mcp', [MCP, DELEGATION]);
    await nativeSession('user-a', 'client-mcp', 'mcp', 'c-mcp');
    await consent('c-del', 'user-a', 'client-delegation', [DELEGATION]);
    await nativeSession('user-a', 'client-delegation', 'del', 'c-del');
    await consent('c-keep', 'user-a', 'client-manage', [MANAGE_KEY, DELEGATION]);
    await nativeSession('user-a', 'client-manage', 'keep', 'c-keep');

    const viaMcp = await disconnectMcp('c-mcp');
    expect(viaMcp).toEqual({ status: 200, body: { consentId: 'c-mcp', disconnected: true } });
    const viaExisting = await call('DELETE', '/tinycloud-apps/client-delegation', { confirmation: 'DISCONNECT' });
    expect(viaExisting.status).toBe(200);

    const mcp = await sessionState('client-mcp', 'mcp');
    const existing = await sessionState('client-delegation', 'del');
    expect(mcp).toEqual({ grant: { status: 'REVOKED', revokedReason: 'consent_withdrawn' }, generation: 1, refresh: 0, access: 0 });
    expect(mcp).toEqual(existing);
    expect(await prisma.oauthConsent.count({ where: { id: { in: ['c-mcp', 'c-del'] } } })).toBe(0);
    // A different client's consent, grant and tokens are untouched.
    expect(await sessionState('client-manage', 'keep')).toEqual({ grant: { status: 'ACTIVE', revokedReason: null }, generation: 0, refresh: 1, access: 1 });
    expect(await prisma.oauthConsent.count({ where: { id: 'c-keep' } })).toBe(1);

    const after = await list();
    expect(after.body.mcpApps).toEqual([]);
  });

  test('a consent without the MCP scope cannot be deleted through the MCP branch', async () => {
    await consent('c-del', 'user-a', 'client-delegation', [DELEGATION]);
    await nativeSession('user-a', 'client-delegation', 'del', 'c-del');
    await consent('c-man', 'user-a', 'client-manage', [MANAGE_KEY]);
    await consent('c-plain', 'user-a', 'client-plain', ['openid']);

    for (const id of ['c-del', 'c-man', 'c-plain']) expect((await disconnectMcp(id)).status).toBe(404);
    expect(await prisma.oauthConsent.count()).toBe(3);
    expect(await sessionState('client-delegation', 'del')).toEqual({ grant: { status: 'ACTIVE', revokedReason: null }, generation: 0, refresh: 1, access: 1 });
  });

  test('the existing delegation and manage-key entries are listed as before and the existing delete keeps its scope', async () => {
    await consent('c-del', 'user-a', 'client-delegation', [DELEGATION]);
    await consent('c-man', 'user-a', 'client-manage', [MANAGE_KEY]);
    await consent('c-mcp', 'user-a', 'client-mcp', [MCP]);

    const result = await list();
    const apps = result.body.apps;
    expect(apps.map((app) => app.clientId).sort()).toEqual(['client-delegation', 'client-manage']);
    expect(apps.find((app) => app.clientId === 'client-delegation')).toMatchObject({
      name: 'Device App', uri: 'https://device.example.test', nativeDelegation: true, activeNativeGrants: 0, enabled: true, status: 'ENABLED', disabled: false,
    });
    expect(apps.find((app) => app.clientId === 'client-manage')).toMatchObject({ nativeDelegation: false, status: 'PENDING_USER_APPROVAL', enabled: true });
    expect(result.body).toMatchObject({ activity: [], mode: 'APP_MANAGED', policyEpoch: 0 });

    // The existing delete does not reach MCP-only or manage-key-only consents.
    expect((await call('DELETE', '/tinycloud-apps/client-mcp', { confirmation: 'DISCONNECT' })).status).toBe(404);
    expect((await call('DELETE', '/tinycloud-apps/client-manage', { confirmation: 'DISCONNECT' })).status).toBe(404);
    expect(await prisma.oauthConsent.count()).toBe(3);
    expect((await call('DELETE', '/tinycloud-apps/client-delegation', { confirmation: 'DISCONNECT' })).status).toBe(200);
    expect(await prisma.oauthConsent.count()).toBe(2);
  });
});
