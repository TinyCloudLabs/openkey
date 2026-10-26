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
    ['create', null],
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
    ['a prompt the provider cannot combine with login', { query: `scope=${encodeURIComponent(MCP)}&prompt=none` }],
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
});
