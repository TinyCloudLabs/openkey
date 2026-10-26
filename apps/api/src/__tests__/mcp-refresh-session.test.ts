import { describe, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { createProviderInterceptors, type ProviderInterceptorDatabase } from '../services/native-delegation/interceptors';
import { mcpRefreshRefusal, type McpRefreshDatabase } from '../services/mcp-refresh-session';
import { mcpTokenStatus, type McpTokenStatusDatabase } from '../services/mcp-token-status';

// The interceptor reads the clock itself, so fixtures are relative to the real time.
const NOW = new Date();
const SECOND = 1000;

type Row = {
  clientId: string; userId: string; sessionId: string | null; scopes: string[];
  revoked: Date | null; expiresAt: Date; createdAt: Date;
};
const mcpRow: Row = {
  clientId: 'app', userId: 'u', sessionId: 's', scopes: ['openid', 'tinycloud:mcp'],
  revoked: null, expiresAt: new Date(NOW.getTime() + 86_400_000), createdAt: new Date(NOW.getTime() - 3_600_000),
};
type World = {
  row?: Row | null;
  client?: { disabled: boolean } | null;
  consent?: { scopes: string[]; createdAt: Date } | null;
  session?: { id: string } | null;
  fail?: 'row' | 'client' | 'consent' | 'session';
};
const live: World = {
  row: mcpRow,
  client: { disabled: false },
  consent: { scopes: ['openid', 'email', 'tinycloud:mcp'], createdAt: new Date(NOW.getTime() - 7_200_000) },
  session: { id: 's' },
};

function world(w: World) {
  const queries: { session: unknown[]; others: string[] } = { session: [], others: [] };
  const maybeFail = (what: NonNullable<World['fail']>) => { queries.others.push(what); if (w.fail === what) throw new Error('db down'); };
  const db = {
    oauthRefreshToken: { findUnique: async () => { maybeFail('row'); return w.row ?? null; } },
    oauthClient: { findUnique: async () => { maybeFail('client'); return w.client ?? null; } },
    oauthConsent: { findUnique: async () => { maybeFail('consent'); return w.consent ?? null; } },
    session: { findFirst: async (query: unknown) => { queries.session.push(query); if (w.fail === 'session') throw new Error('db down'); return w.session ?? null; } },
  } as unknown as McpRefreshDatabase;
  return { db, queries };
}
const guard = (w: World, client: string | null = 'app', scope: string | null = null) =>
  mcpRefreshRefusal(world({ ...live, ...w }).db, {}, 'refresh-token', client, scope, NOW);
const ended = { status: 400, error: 'invalid_grant' };

describe('mcpRefreshRefusal: a found, unrevoked, unexpired MCP row of the requesting client', () => {
  test('a standing connection goes on to the provider; the session lookup is bound to the row\'s user and the clock', async () => {
    const { db, queries } = world(live);
    expect(await mcpRefreshRefusal(db, {}, 'refresh-token', 'app', null, NOW)).toBeNull();
    expect(queries.session).toEqual([{ where: { id: 's', userId: 'u', expiresAt: { gt: NOW } }, select: { id: true } }]);
  });

  test.each([
    ['a missing or expired session', { session: null }],
    ['no session id on the row', { row: { ...mcpRow, sessionId: null } }],
    ['a missing client', { client: null }],
    ['a disabled client', { client: { disabled: true } }],
    ['a missing consent', { consent: null }],
    ['a consent narrowed below the token\'s scopes', { consent: { scopes: ['openid'], createdAt: new Date(NOW.getTime() - 7_200_000) } }],
    ['a consent created after the token, in a later second', { consent: { scopes: live.consent!.scopes, createdAt: new Date(mcpRow.createdAt.getTime() + 2 * SECOND) } }],
  ] as [string, World][])('%s is invalid_grant', async (_name, change) => {
    expect(await guard(change)).toMatchObject(ended);
  });

  test('a consent created in the same second as the token still stands', async () => {
    const created = new Date(Math.floor(mcpRow.createdAt.getTime() / 1000) * 1000 + 400);
    expect(await guard({ row: { ...mcpRow, createdAt: new Date(created.getTime() - 400) }, consent: { scopes: live.consent!.scopes, createdAt: created } })).toBeNull();
  });

  test('the requested scope, not the row\'s, is checked against the consent when the request names one', async () => {
    expect(await guard({}, 'app', 'tinycloud:mcp')).toBeNull();
    expect(await guard({}, 'app', 'tinycloud:mcp tinycloud:manage-key')).toMatchObject(ended);
    expect(await guard({ consent: { scopes: ['openid'], createdAt: live.consent!.createdAt } }, 'app', 'openid')).toBeNull();
  });
});

describe('mcpRefreshRefusal: everything else is the provider\'s call, with no connection lookup', () => {
  test.each([
    ['an unknown token', { row: null }],
    ['a revoked token (reuse detection must still run)', { row: { ...mcpRow, revoked: new Date(NOW.getTime() - 1000) } }],
    ['an expired token', { row: { ...mcpRow, expiresAt: new Date(NOW.getTime() - 1000) } }],
    ['a token without the MCP scope', { row: { ...mcpRow, scopes: ['openid', 'offline_access'] } }],
  ] as [string, World][])('%s', async (_name, change) => {
    const w = { ...live, ...change, session: null, consent: null, client: null };
    const { db, queries } = world(w);
    expect(await mcpRefreshRefusal(db, {}, 'refresh-token', 'app', null, NOW)).toBeNull();
    expect(queries.session).toEqual([]);
    expect(queries.others).toEqual(['row']);
  });

  test('another client\'s token, whether the request names none or a different one', async () => {
    const { db, queries } = world({ ...live, session: null });
    expect(await mcpRefreshRefusal(db, {}, 'refresh-token', 'other-app', null, NOW)).toBeNull();
    expect(await mcpRefreshRefusal(db, {}, 'refresh-token', null, null, NOW)).toBeNull();
    expect(queries.session).toEqual([]);
  });

  test('a token the provider would reject before any lookup (prefix mismatch)', async () => {
    const { db } = world({ ...live, session: null });
    expect(await mcpRefreshRefusal(db, { prefix: { refreshToken: 'rt_' } }, 'no-prefix', 'app', null, NOW)).toBeNull();
  });
});

describe('mcpRefreshRefusal: an error', () => {
  test.each(['row', 'client', 'consent', 'session'] as const)('a failed %s lookup is 503 temporarily_unavailable with a retry hint, never invalid_grant', async (fail) => {
    expect(await guard({ fail })).toEqual({
      status: 503, error: 'temporarily_unavailable', description: expect.any(String), retryAfter: 5,
    });
  });
});

describe('mcpTokenStatus, shared with the token status check', () => {
  const status = (w: World, scopes: string[] = ['tinycloud:mcp'], issuedAtSeconds = Math.floor(mcpRow.createdAt.getTime() / 1000)) =>
    mcpTokenStatus(world({ ...live, ...w }).db as McpTokenStatusDatabase, { userId: 'u', clientId: 'app', sessionId: 's', scopes, issuedAtSeconds }, NOW);

  test('gives the reason a connection ended', async () => {
    expect(await status({})).toEqual({ active: true });
    expect(await status({ client: { disabled: true } })).toEqual({ active: false, reason: 'client' });
    expect(await status({ consent: null })).toEqual({ active: false, reason: 'consent' });
    expect(await status({ session: null })).toEqual({ active: false, reason: 'session' });
    expect(await status({}, ['tinycloud:manage-key'])).toEqual({ active: false, reason: 'scope' });
    expect(await status({}, ['tinycloud:mcp'], 1)).toEqual({ active: false, reason: 'older_than_consent' });
    expect(await mcpTokenStatus(world(live).db as McpTokenStatusDatabase, { userId: 'u', clientId: 'app', sessionId: null, scopes: [], issuedAtSeconds: 0 }, NOW))
      .toEqual({ active: false, reason: 'session' });
  });
});

describe('token endpoint interception', () => {
  function tokenRequest(w: World, provider: () => Response) {
    const { db } = world({ ...live, ...w });
    const full = {
      oauthAccessToken: { findUnique: async () => null },
      tinyCloudNativeGrant: { findFirst: async () => null },
      ...db,
      oauthClient: { findMany: async () => [], findUnique: async () => (w.client === undefined ? live.client : w.client) },
    } as unknown as ProviderInterceptorDatabase;
    const reached: string[] = [];
    const app = new Hono();
    app.use('/api/auth/*', createProviderInterceptors({
      database: full,
      tokens: {},
      authorizationCodes: { find: async () => null, delete: async () => {} },
      provider: async (request) => { reached.push(await request.text()); return provider(); },
      getSessionUserId: async () => null,
    }));
    app.post('/api/auth/*', () => { reached.push('handler'); return Response.json({ access_token: 'issued' }); });
    return {
      reached,
      response: app.fetch(new Request('https://api.openkey.test/api/auth/oauth2/token', {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=refresh_token&client_id=app&refresh_token=refresh-token',
      })),
    };
  }

  test('an ended connection is answered before the provider runs; a standing one reaches it', async () => {
    const refused = tokenRequest({ session: null }, () => Response.json({}));
    const response = await refused.response;
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: 'invalid_grant' });
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(refused.reached).toEqual([]);

    const ok = tokenRequest({}, () => Response.json({}));
    expect(await (await ok.response).json()).toEqual({ access_token: 'issued' });
    expect(ok.reached).toEqual(['handler']);
  });

  test('a guard error is a 503 with Retry-After and never reaches the provider', async () => {
    const failed = tokenRequest({ fail: 'session' }, () => Response.json({}));
    const response = await failed.response;
    expect(response.status).toBe(503);
    expect(response.headers.get('retry-after')).toBe('5');
    expect(await response.json()).toMatchObject({ error: 'temporarily_unavailable' });
    expect(failed.reached).toEqual([]);
  });
});
