import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { readdir, readFile } from 'node:fs/promises';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { extendSession, mcpRefreshRefusal, type McpRefreshDatabase } from '../services/mcp-refresh-session';
import { storedRefreshToken } from '../services/native-delegation/provider-tokens';

// The extension is one UPDATE whose conditions guard against a change that lands
// between the checks made in code and the write. Here the code-side checks are out
// of the picture: the statement runs against the real schema with the row state
// changed in exactly one way, and must match nothing and leave the session as it was.

const DAY = 86_400_000;
const STORED = 'stored-refresh-token';
let database: PGlite;
let prisma: PrismaClient;
let now: Date;

beforeAll(async () => {
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
});

/** A session six days old with a day left, one refresh row, one consent and one enabled client: every condition holds. */
async function seed() {
  await database.exec(`TRUNCATE "oauth_refresh_token", "oauth_consent", "oauth_client", "session", "user" CASCADE`);
  now = new Date();
  await prisma.user.create({ data: { id: 'u', email: 'u@example.test' } });
  await prisma.user.create({ data: { id: 'other-user', email: 'o@example.test' } });
  await prisma.session.create({ data: { id: 's', userId: 'u', token: 'st', createdAt: new Date(now.getTime() - 6 * DAY), expiresAt: new Date(now.getTime() + DAY) } });
  await prisma.session.create({ data: { id: 's2', userId: 'u', token: 'st2', createdAt: new Date(now.getTime() - DAY), expiresAt: new Date(now.getTime() + 6 * DAY) } });
  await prisma.oauthClient.create({ data: { id: 'row-app', clientId: 'app', name: 'App', redirectUris: [], scopes: [], public: true } });
  await prisma.oauthClient.create({ data: { id: 'row-other-app', clientId: 'other-app', name: 'Other', redirectUris: [], scopes: [] } });
  await prisma.oauthConsent.create({ data: { id: 'c', userId: 'u', clientId: 'app', scopes: ['openid', 'tinycloud:mcp'] } });
  await prisma.oauthRefreshToken.create({ data: {
    id: 'r', token: STORED, clientId: 'app', userId: 'u', sessionId: 's', scopes: ['openid', 'tinycloud:mcp'],
    expiresAt: new Date(now.getTime() + 7 * DAY),
  } });
}
beforeEach(seed);

const run = () => extendSession(prisma as unknown as McpRefreshDatabase, { userId: 'u', clientId: 'app', sessionId: 's' }, STORED, now);
const expiry = async (id = 's') => (await prisma.session.findUniqueOrThrow({ where: { id } })).expiresAt.getTime();

describe('the extension statement', () => {
  test('with every condition holding it extends to six days from now', async () => {
    expect(await run()).toBe(true);
    expect(Math.abs((await expiry()) - (now.getTime() + 6 * DAY))).toBeLessThan(1000);
  });

  const blocked: [string, () => Promise<unknown>][] = [
    ['the session has expired', () => prisma.session.update({ where: { id: 's' }, data: { expiresAt: new Date(now.getTime() - 1000) } })],
    ['the refresh row was revoked (rotated by another request)', () => prisma.oauthRefreshToken.update({ where: { id: 'r' }, data: { revoked: new Date(now.getTime() - 1000) } })],
    ['the consent was deleted', () => prisma.oauthConsent.delete({ where: { id: 'c' } })],
    ['the client was disabled', () => prisma.oauthClient.update({ where: { clientId: 'app' }, data: { disabled: true } })],
    ['the refresh row belongs to another session of the user', () => prisma.oauthRefreshToken.update({ where: { id: 'r' }, data: { sessionId: 's2' } })],
    ['the refresh row has expired', () => prisma.oauthRefreshToken.update({ where: { id: 'r' }, data: { expiresAt: new Date(now.getTime() - 1000) } })],
    ['the refresh row lost the MCP scope', () => prisma.oauthRefreshToken.update({ where: { id: 'r' }, data: { scopes: ['openid'] } })],
    ['the refresh row belongs to another client', () => prisma.oauthRefreshToken.update({ where: { id: 'r' }, data: { clientId: 'other-app' } })],
    ['the refresh row belongs to another user', () => prisma.oauthRefreshToken.update({ where: { id: 'r' }, data: { userId: 'other-user' } })],
    ['the consent lost the MCP scope', () => prisma.oauthConsent.update({ where: { id: 'c' }, data: { scopes: ['openid'] } })],
    ['the sign-in is 30 days old', () => prisma.session.update({ where: { id: 's' }, data: { createdAt: new Date(now.getTime() - 30 * DAY - 1000), expiresAt: new Date(now.getTime() + 3_600_000) } })],
    ['the session row is gone (signed out)', () => prisma.session.delete({ where: { id: 's' } })],
  ];

  test.each(blocked)('matches no row when %s, and the session is unchanged', async (_name, change) => {
    await change();
    const before = await prisma.session.findMany({ orderBy: { id: 'asc' } });
    expect(await run()).toBe(false);
    expect(await prisma.session.findMany({ orderBy: { id: 'asc' } })).toEqual(before);
  });

  test('a session close to the cap extends to the cap and no further', async () => {
    await prisma.session.update({ where: { id: 's' }, data: { createdAt: new Date(now.getTime() - 29 * DAY), expiresAt: new Date(now.getTime() + 3_600_000) } });
    expect(await run()).toBe(true);
    const session = await prisma.session.findUniqueOrThrow({ where: { id: 's' } });
    expect(session.expiresAt.getTime()).toBe(session.createdAt.getTime() + 30 * DAY);
  });
});

describe('a change that lands between the checks and the write', () => {
  /** The real database, except that something happens just before the extension statement runs. */
  function racing(beforeUpdate: () => Promise<unknown>): McpRefreshDatabase {
    const queryRaw = async (strings: TemplateStringsArray, ...values: unknown[]) => {
      await beforeUpdate();
      return prisma.$queryRaw(strings, ...values);
    };
    return {
      oauthRefreshToken: prisma.oauthRefreshToken,
      oauthClient: prisma.oauthClient,
      oauthConsent: prisma.oauthConsent,
      session: prisma.session,
      $queryRaw: queryRaw as McpRefreshDatabase['$queryRaw'],
    };
  }
  const refresh = (db: McpRefreshDatabase) =>
    mcpRefreshRefusal(db, {}, 'refresh-token', 'app', null, now, { presentedSecret: null });

  test('the token was rotated meanwhile: invalid_grant that says it was already used, and the session is untouched', async () => {
    const stored = await storedRefreshToken({}, 'refresh-token');
    await prisma.oauthRefreshToken.update({ where: { id: 'r' }, data: { token: stored! } });
    const before = await expiry();
    const refusal = await refresh(racing(() => prisma.oauthRefreshToken.update({ where: { id: 'r' }, data: { revoked: new Date(now.getTime() - 1000) } })));
    expect(refusal).toEqual({ status: 400, error: 'invalid_grant', description: 'this refresh token was already used' });
    expect(await expiry()).toBe(before);
  });

  test('the session was signed out meanwhile: invalid_grant for an ended connection, and the row is not recreated', async () => {
    const stored = await storedRefreshToken({}, 'refresh-token');
    await prisma.oauthRefreshToken.update({ where: { id: 'r' }, data: { token: stored! } });
    const refusal = await refresh(racing(() => prisma.session.delete({ where: { id: 's' } })));
    expect(refusal?.status).toBe(400);
    expect(refusal?.description).toContain('has ended');
    expect(await prisma.session.count({ where: { id: 's' } })).toBe(0);
  });

  test('the session reached 30 days meanwhile: invalid_grant for an ended connection, not "already used"', async () => {
    const stored = await storedRefreshToken({}, 'refresh-token');
    await prisma.oauthRefreshToken.update({ where: { id: 'r' }, data: { token: stored! } });
    const refusal = await refresh(racing(() => prisma.session.update({ where: { id: 's' }, data: { createdAt: new Date(now.getTime() - 31 * DAY) } })));
    expect(refusal?.status).toBe(400);
    expect(refusal?.description).toContain('has ended');
  });
});
