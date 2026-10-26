import { describe, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { createProviderInterceptors, type ProviderInterceptorDatabase } from '../services/native-delegation/interceptors';
import { mcpRefreshSessionRefusal, type McpRefreshDatabase } from '../services/mcp-refresh-session';
import { storedRefreshToken } from '../services/native-delegation/provider-tokens';

type Row = { clientId: string; userId: string; sessionId: string | null; scopes: string[] };
const mcpRow: Row = { clientId: 'app', userId: 'u', sessionId: 's', scopes: ['openid', 'tinycloud:mcp'] };

function database(options: { row?: Row | null; session?: { id: string } | null; failRow?: boolean; failSession?: boolean }) {
  const sessionQueries: unknown[] = [];
  const db = {
    oauthRefreshToken: { findUnique: async () => { if (options.failRow) throw new Error('db down'); return options.row ?? null; } },
    session: { findFirst: async (query: unknown) => { sessionQueries.push(query); if (options.failSession) throw new Error('db down'); return options.session ?? null; } },
  } as unknown as McpRefreshDatabase;
  return { db, sessionQueries };
}
const check = (db: McpRefreshDatabase, client: string | null = 'app', now = new Date('2026-10-27T12:00:00.000Z')) =>
  mcpRefreshSessionRefusal(db, {}, 'refresh-token', client, now);

describe('mcpRefreshSessionRefusal', () => {
  test('a live session lets the provider rotate; the lookup is bound to the row\'s own user and the clock', async () => {
    const { db, sessionQueries } = database({ row: mcpRow, session: { id: 's' } });
    expect(await check(db)).toBeNull();
    expect(sessionQueries).toEqual([{ where: { id: 's', userId: 'u', expiresAt: { gt: new Date('2026-10-27T12:00:00.000Z') } }, select: { id: true } }]);
  });

  test('a missing or expired session and a row with no session are invalid_grant', async () => {
    expect(await check(database({ row: mcpRow, session: null }).db)).toMatchObject({ status: 400, error: 'invalid_grant' });
    expect(await check(database({ row: { ...mcpRow, sessionId: null } }).db)).toMatchObject({ status: 400, error: 'invalid_grant' });
  });

  test('tokens without the MCP scope, unknown tokens and another client\'s token are left to the provider without a session lookup', async () => {
    for (const options of [{ row: { ...mcpRow, scopes: ['openid', 'offline_access'] } }, { row: null }]) {
      const { db, sessionQueries } = database(options);
      expect(await check(db)).toBeNull();
      expect(sessionQueries).toEqual([]);
    }
    const mismatch = database({ row: mcpRow });
    expect(await check(mismatch.db, 'other-app')).toBeNull();
    expect(await check(mismatch.db, null)).toBeNull();
    expect(mismatch.sessionQueries).toEqual([]);
  });

  test('a token the provider cannot normalize is left to the provider', async () => {
    const { db } = database({ row: mcpRow });
    expect(await mcpRefreshSessionRefusal(db, { prefix: { refreshToken: 'rt_' } }, 'no-prefix', 'app')).toBeNull();
  });

  test('a failed lookup is temporarily_unavailable (503), never invalid_grant', async () => {
    expect(await check(database({ failRow: true }).db)).toMatchObject({ status: 503, error: 'temporarily_unavailable' });
    expect(await check(database({ row: mcpRow, failSession: true }).db)).toMatchObject({ status: 503, error: 'temporarily_unavailable' });
  });
});

describe('token endpoint interception', () => {
  const stored = storedRefreshToken({}, 'refresh-token');
  function tokenRequest(db: McpRefreshDatabase, provider: () => Response) {
    const seen: string[] = [];
    const full = {
      oauthClient: { findMany: async () => [], findUnique: async () => null },
      oauthAccessToken: { findUnique: async () => null },
      tinyCloudNativeGrant: { findFirst: async () => null },
      ...db,
    } as unknown as ProviderInterceptorDatabase;
    const app = new Hono();
    app.use('/api/auth/*', createProviderInterceptors({
      database: full,
      tokens: {},
      authorizationCodes: { find: async () => null, delete: async () => {} },
      provider: async (request) => { seen.push(await request.text()); return provider(); },
      getSessionUserId: async () => null,
    }));
    app.post('/api/auth/*', () => Response.json({ access_token: 'issued' }));
    return {
      seen,
      response: app.fetch(new Request('https://api.openkey.test/api/auth/oauth2/token', {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=refresh_token&client_id=app&refresh_token=refresh-token',
      })),
    };
  }

  test('an ended session answers 400 invalid_grant before the provider runs; a live one reaches the handler', async () => {
    await stored;
    const ended = tokenRequest(database({ row: mcpRow, session: null }).db, () => Response.json({}));
    const refused = await ended.response;
    expect(refused.status).toBe(400);
    expect(await refused.json()).toMatchObject({ error: 'invalid_grant' });
    expect(refused.headers.get('cache-control')).toBe('no-store');

    const live = await tokenRequest(database({ row: mcpRow, session: { id: 's' } }).db, () => Response.json({})).response;
    expect(await live.json()).toEqual({ access_token: 'issued' });
  });

  test('a database failure is a 503 from the guard, not a 500', async () => {
    const failed = await tokenRequest(database({ row: mcpRow, failSession: true }).db, () => Response.json({})).response;
    expect(failed.status).toBe(503);
    expect(await failed.json()).toMatchObject({ error: 'temporarily_unavailable' });
  });
});
