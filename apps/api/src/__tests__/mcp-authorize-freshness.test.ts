import { describe, expect, test } from 'bun:test';
import { Hono } from 'hono';
import { mcpAuthorizeNeedsFreshSignIn, withLoginPrompt } from '../services/mcp-authorize-freshness';
import { MCP_AUTHORIZE_MAX_SESSION_AGE_SECONDS } from '../services/session-lifetime';
import { createProviderInterceptors, type ProviderInterceptorDatabase } from '../services/native-delegation/interceptors';

const DAY_MS = 86_400_000;
const NOW = new Date('2026-10-27T12:00:00.000Z');

describe('the age limit for a new MCP connection', () => {
  test('is 23 days: the 30-day cap minus a 7-day margin', () => {
    expect(MCP_AUTHORIZE_MAX_SESSION_AGE_SECONDS).toBe(23 * 86_400);
  });

  test('is inclusive: exactly 23 days old needs a fresh sign-in, one millisecond younger does not', () => {
    expect(mcpAuthorizeNeedsFreshSignIn(new Date(NOW.getTime() - 23 * DAY_MS), NOW)).toBe(true);
    expect(mcpAuthorizeNeedsFreshSignIn(new Date(NOW.getTime() - 23 * DAY_MS + 1), NOW)).toBe(false);
    expect(mcpAuthorizeNeedsFreshSignIn(new Date(NOW.getTime() - 22 * DAY_MS), NOW)).toBe(false);
    expect(mcpAuthorizeNeedsFreshSignIn(new Date(NOW.getTime() - 24 * DAY_MS), NOW)).toBe(true);
    expect(mcpAuthorizeNeedsFreshSignIn(NOW, NOW)).toBe(false);
  });
});

describe('adding the login prompt', () => {
  test.each([
    [null, 'login'],
    ['', 'login'],
    ['consent', 'login consent'],
    ['login', 'login'],
    ['login consent', 'login consent'],
    ['none', null],
    ['create', 'login'],
    ['create consent', null],
    ['select_account', null],
    ['select_account consent', null],
  ] as [string | null, string | null][])('prompt %j becomes %j', (prompt, expected) => {
    expect(withLoginPrompt(prompt)).toBe(expected);
  });
});

describe('the authorize request through the interceptor', () => {
  const MCP = 'tinycloud:mcp';
  function run(options: { query: string; clientScopes?: string[] | null; createdAt?: Date | null; withReader?: boolean }) {
    const lookups: string[] = [];
    const database = {
      oauthClient: {
        findMany: async () => [],
        findUnique: async () => { lookups.push('client'); return options.clientScopes === null ? null : { scopes: options.clientScopes ?? ['openid', MCP] }; },
      },
      oauthRefreshToken: { findUnique: async () => null },
      tinyCloudNativeGrant: { findFirst: async () => null },
    } as unknown as ProviderInterceptorDatabase;
    const reached: (string | null)[] = [];
    const app = new Hono();
    app.use('/api/auth/*', createProviderInterceptors({
      database,
      tokens: {},
      authorizationCodes: { find: async () => null, delete: async () => {} },
      provider: async (request) => { reached.push(new URL(request.url).searchParams.get('prompt')); return new Response(null, { status: 302 }); },
      getSessionUserId: async () => null,
      ...(options.withReader === false ? {} : { getSessionCreatedAt: async () => (options.createdAt === undefined ? new Date(Date.now() - 24 * DAY_MS) : options.createdAt) }),
    }));
    app.get('/api/auth/oauth2/authorize', () => { reached.push('handler'); return new Response(null, { status: 302 }); });
    const response = app.fetch(new Request(`https://api.openkey.test/api/auth/oauth2/authorize?client_id=app&response_type=code&${options.query}`));
    return { reached, response, lookups };
  }

  test('an MCP request on an old sign-in is sent to the provider with login added', async () => {
    const result = run({ query: `scope=openid+${encodeURIComponent(MCP)}` });
    await result.response;
    expect(result.reached).toEqual(['login']);
  });

  test('a request without a scope is judged by the client\'s own scopes', async () => {
    const mcpClient = run({ query: '' });
    await mcpClient.response;
    expect(mcpClient.reached).toEqual(['login']);
    const plainClient = run({ query: '', clientScopes: ['openid', 'email'] });
    await plainClient.response;
    expect(plainClient.reached).toEqual(['handler']);
    const unknownClient = run({ query: '', clientScopes: null });
    await unknownClient.response;
    expect(unknownClient.reached).toEqual(['handler']);
  });

  test.each([
    ['a young sign-in', { query: `scope=${encodeURIComponent(MCP)}`, createdAt: new Date(Date.now() - 22 * DAY_MS) }],
    ['no sign-in', { query: `scope=${encodeURIComponent(MCP)}`, createdAt: null }],
    ['a request without the MCP scope', { query: 'scope=openid+email' }],
    ['a pushed request', { query: `request_uri=urn%3Aexample&scope=${encodeURIComponent(MCP)}` }],
    ['prompt=select_account', { query: `scope=${encodeURIComponent(MCP)}&prompt=select_account` }],
    ['no session reader configured', { query: `scope=${encodeURIComponent(MCP)}`, withReader: false }],
  ] as [string, Parameters<typeof run>[0]][])('%s goes to the handler untouched', async (_name, options) => {
    const result = run(options);
    await result.response;
    expect(result.reached).toEqual(['handler']);
  });

  test('a prompt of consent becomes login consent; a request that already asks for login is not rewritten', async () => {
    const consent = run({ query: `scope=${encodeURIComponent(MCP)}&prompt=consent` });
    await consent.response;
    expect(consent.reached).toEqual(['login consent']);
    const login = run({ query: `scope=${encodeURIComponent(MCP)}&prompt=login` });
    await login.response;
    expect(login.reached).toEqual(['handler']);
  });

  test('prompt=create on an old sign-in becomes login, so the create step cannot resume the request on that sign-in', async () => {
    const result = run({ query: `scope=${encodeURIComponent(MCP)}&prompt=create` });
    await result.response;
    expect(result.reached).toEqual(['login']);
    const young = run({ query: `scope=${encodeURIComponent(MCP)}&prompt=create`, createdAt: new Date(Date.now() - 22 * DAY_MS) });
    await young.response;
    expect(young.reached).toEqual(['handler']);
  });

  describe('prompt=none', () => {
    /** What the provider is handed: the prompt, and whether the request still carries the sign-in's credentials. */
    function runNone(options: { query: string; createdAt?: Date | null; clientScopes?: string[] | null }) {
      const handed: { prompt: string | null; credentials: boolean }[] = [];
      const database = {
        oauthClient: { findMany: async () => [], findUnique: async () => (options.clientScopes === null ? null : { scopes: options.clientScopes ?? ['openid', MCP] }) },
        oauthRefreshToken: { findUnique: async () => null },
        tinyCloudNativeGrant: { findFirst: async () => null },
      } as unknown as ProviderInterceptorDatabase;
      const app = new Hono();
      app.use('/api/auth/*', createProviderInterceptors({
        database,
        tokens: {},
        authorizationCodes: { find: async () => null, delete: async () => {} },
        provider: async (request) => {
          handed.push({ prompt: new URL(request.url).searchParams.get('prompt'), credentials: request.headers.has('cookie') || request.headers.has('authorization') });
          return new Response(null, { status: 302 });
        },
        getSessionUserId: async () => null,
        getSessionCreatedAt: async () => (options.createdAt === undefined ? new Date(Date.now() - 24 * DAY_MS) : options.createdAt),
      }));
      app.get('/api/auth/oauth2/authorize', (c) => {
        handed.push({ prompt: new URL(c.req.url).searchParams.get('prompt'), credentials: c.req.raw.headers.has('cookie') });
        return new Response(null, { status: 302 });
      });
      const response = app.fetch(new Request(`https://api.openkey.test/api/auth/oauth2/authorize?client_id=app&response_type=code&prompt=none&${options.query}`, {
        headers: { cookie: 'session=old', authorization: 'Bearer old-session-token' },
      }));
      return { handed, response };
    }

    test('an old sign-in with the MCP scope reaches the provider as a request from nobody signed in, still prompt=none', async () => {
      const result = runNone({ query: `scope=${encodeURIComponent(MCP)}` });
      await result.response;
      expect(result.handed).toEqual([{ prompt: 'none', credentials: false }]);
    });

    test('so does a request that names no scope on an MCP client', async () => {
      const result = runNone({ query: '' });
      await result.response;
      expect(result.handed).toEqual([{ prompt: 'none', credentials: false }]);
    });

    test.each([
      ['a young sign-in', { query: `scope=${encodeURIComponent(MCP)}`, createdAt: new Date(Date.now() - 22 * DAY_MS) }],
      ['no sign-in', { query: `scope=${encodeURIComponent(MCP)}`, createdAt: null }],
      ['a request without the MCP scope', { query: 'scope=openid+email' }],
      ['a pushed request', { query: `request_uri=urn%3Aexample&scope=${encodeURIComponent(MCP)}` }],
    ] as [string, Parameters<typeof runNone>[0]][])('%s keeps its credentials and goes to the handler as it is', async (_name, options) => {
      const result = runNone(options);
      await result.response;
      expect(result.handed).toEqual([{ prompt: 'none', credentials: true }]);
    });
  });
});

describe('the authorization code exchange (the age limit once more, when the code is used)', () => {
  const MCP = 'tinycloud:mcp';
  const ISSUED = new Date('2026-10-27T12:00:00.000Z');
  const DAY = 86_400_000;

  /** An exchange of the code `abc`, stored with the given sign-in time, issue time, scope and client. */
  function exchange(stored: { authTime?: number | string; createdAt?: Date | string; scope?: string; clientId?: string; raw?: string } | null, options: { failFind?: boolean } = {}) {
    const deleted: string[] = [];
    const database = {
      oauthClient: { findMany: async () => [], findUnique: async () => null },
      oauthRefreshToken: { findUnique: async () => null },
      tinyCloudNativeGrant: { findFirst: async () => null },
    } as unknown as ProviderInterceptorDatabase;
    const app = new Hono();
    app.use('/api/auth/*', createProviderInterceptors({
      database,
      tokens: {},
      authorizationCodes: {
        find: async () => {
          if (options.failFind) throw new Error('database unavailable');
          if (!stored) return null;
          return {
            value: stored.raw ?? JSON.stringify({
              type: 'authorization_code',
              query: { client_id: stored.clientId ?? 'app', scope: stored.scope ?? `openid ${MCP}` },
              authTime: stored.authTime,
            }),
            createdAt: stored.createdAt ?? ISSUED,
          };
        },
        delete: async (identifier) => { deleted.push(identifier); },
      },
      provider: async () => new Response(null, { status: 200 }),
      getSessionUserId: async () => null,
    }));
    app.post('/api/auth/oauth2/token', () => new Response('provider', { status: 200 }));
    const response = app.fetch(new Request('https://api.openkey.test/api/auth/oauth2/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: 'abc', client_id: 'app', redirect_uri: 'https://app.example/cb', code_verifier: 'v' }),
    }));
    return { response, deleted };
  }

  test('a code issued on a sign-in exactly 23 days old is refused and spent; one millisecond younger is the provider\'s', async () => {
    const old = exchange({ authTime: ISSUED.getTime() - 23 * DAY });
    const refused = await old.response;
    expect(refused.status).toBe(400);
    expect(await refused.json()).toMatchObject({ error: 'invalid_grant' });
    expect(old.deleted).toHaveLength(1);

    const justYoung = exchange({ authTime: ISSUED.getTime() - 23 * DAY + 1 });
    expect(await (await justYoung.response).text()).toBe('provider');
    expect(justYoung.deleted).toEqual([]);
  });

  test('a code for a young sign-in, or for other scopes, or another client\'s, is the provider\'s and is not spent', async () => {
    for (const stored of [
      { authTime: ISSUED.getTime() - 2 * DAY },
      { authTime: ISSUED.getTime() - 40 * DAY, scope: 'openid email' },
      { authTime: ISSUED.getTime() - 40 * DAY, clientId: 'other' },
      { authTime: ISSUED.getTime() - 40 * DAY, raw: 'not json' },
    ]) {
      const result = exchange(stored);
      expect(await (await result.response).text()).toBe('provider');
      expect(result.deleted).toEqual([]);
    }
    const unknown = exchange(null);
    expect(await (await unknown.response).text()).toBe('provider');
  });

  test('a code of this client that does not say when the sign-in began, or when it was issued, is refused and spent', async () => {
    for (const stored of [{ authTime: undefined }, { authTime: 'not a time' }, { authTime: ISSUED.getTime() - DAY, createdAt: 'not a time' }]) {
      const result = exchange(stored);
      const response = await result.response;
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: 'invalid_grant' });
      expect(result.deleted).toHaveLength(1);
    }
  });

  test('a failed lookup answers 503 and does not fall through to the provider', async () => {
    const result = exchange({ authTime: ISSUED.getTime() }, { failFind: true });
    const response = await result.response;
    expect(response.status).toBe(503);
    expect(response.headers.get('retry-after')).toBe('5');
    expect(result.deleted).toEqual([]);
  });
});
