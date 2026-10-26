import { describe, expect, test } from 'bun:test';
import { mcpRefreshRefusal, type McpRefreshDatabase } from '../services/mcp-refresh-session';
import { hashClientSecret } from '../services/resource-server';
import { storedRefreshToken } from '../services/native-delegation/provider-tokens';

// The statement itself is exercised against the real schema in the provider test;
// these cover the decisions around it, with stubbed lookups.
const NOW = new Date();
const SECRET = 'a-client-secret';

type Client = { public: boolean; clientSecret: string | null };
const publicClient: Client = { public: true, clientSecret: null };
const confidential: Client = { public: false, clientSecret: hashClientSecret(SECRET) };

function setup(options: { client?: Client | null; updated?: number | 'throws' } = {}) {
  const updates: unknown[][] = [];
  const row = {
    clientId: 'app', userId: 'u', sessionId: 's', scopes: ['openid', 'tinycloud:mcp'],
    revoked: null, expiresAt: new Date(NOW.getTime() + 86_400_000), createdAt: new Date(NOW.getTime() - 3_600_000),
  };
  const db = {
    oauthRefreshToken: { findUnique: async () => row },
    oauthClient: { findUnique: async (query: { select: Record<string, boolean> }) => (query.select.disabled ? { disabled: false } : options.client === undefined ? publicClient : options.client) },
    oauthConsent: { findUnique: async () => ({ scopes: ['openid', 'tinycloud:mcp'], createdAt: new Date(NOW.getTime() - 7_200_000) }) },
    session: { findFirst: async () => ({ id: 's' }) },
    $queryRaw: async (...args: unknown[]) => {
      updates.push(args);
      if (options.updated === 'throws') throw new Error('db down');
      return Array.from({ length: options.updated ?? 1 }, () => ({ id: 's' }));
    },
  } as unknown as McpRefreshDatabase;
  return { db, updates };
}
const run = (db: McpRefreshDatabase, presentedSecret: string | null, extension = true) =>
  mcpRefreshRefusal(db, {}, 'refresh-token', 'app', null, NOW, extension ? { presentedSecret } : undefined);

describe('extending the session on an MCP refresh', () => {
  test('a public client that presents no secret extends once, with the time bound from the caller in UTC and the 6-day and 30-day limits', async () => {
    const { db, updates } = setup();
    expect(await run(db, null)).toBeNull();
    expect(updates).toHaveLength(1);
    const values = updates[0]!.slice(1);
    expect(values).toContain(NOW.toISOString());
    expect(values).toContain(6 * 86_400);
    expect(values).toContain(30 * 86_400);
    expect(values).toContain('s');
    expect(values).toContain('u');
    expect(values).toContain('app');
    expect(values).toContain(await storedRefreshToken({}, 'refresh-token'));
  });

  test('a confidential client extends only when its secret matches', async () => {
    for (const [presented, extends_] of [[SECRET, true], ['wrong-secret', false], [null, false], ['', false]] as const) {
      const { db, updates } = setup({ client: confidential });
      expect(await run(db, presented), String(presented)).toBeNull();
      expect(updates.length, String(presented)).toBe(extends_ ? 1 : 0);
    }
  });

  test('a public client that presents a secret is the provider\'s to refuse: nothing is extended', async () => {
    const { db, updates } = setup({ client: publicClient });
    expect(await run(db, SECRET)).toBeNull();
    expect(updates).toHaveLength(0);
  });

  test('an unknown client row extends nothing', async () => {
    const { db, updates } = setup({ client: null });
    expect(await run(db, null)).toBeNull();
    expect(updates).toHaveLength(0);
  });

  test('a session the update does not match (gone, expired, at the cap, token or consent just ended) is invalid_grant', async () => {
    const { db } = setup({ updated: 0 });
    expect(await run(db, null)).toMatchObject({ status: 400, error: 'invalid_grant' });
  });

  test('a failed update is a 503 with a retry hint, never invalid_grant', async () => {
    const { db } = setup({ updated: 'throws' });
    expect(await run(db, null)).toMatchObject({ status: 503, error: 'temporarily_unavailable', retryAfter: 5 });
  });

  test('without the extension option the guard only checks, as before', async () => {
    const { db, updates } = setup();
    expect(await run(db, null, false)).toBeNull();
    expect(updates).toHaveLength(0);
  });
});

describe('a refresh that matched nothing although the checks held a moment ago', () => {
  // The token is unrevoked when the guard reads it; by the time the update runs it may not be.
  function raced(afterwards: { revoked: Date | null } | null): McpRefreshDatabase {
    const row = {
      clientId: 'app', userId: 'u', sessionId: 's', scopes: ['openid', 'tinycloud:mcp'],
      revoked: null, expiresAt: new Date(NOW.getTime() + 86_400_000), createdAt: new Date(NOW.getTime() - 3_600_000),
    };
    let reads = 0;
    return {
      oauthRefreshToken: { findUnique: async () => (++reads === 1 ? row : afterwards) },
      oauthClient: { findUnique: async (query: { select: Record<string, boolean> }) => (query.select.disabled ? { disabled: false } : publicClient) },
      oauthConsent: { findUnique: async () => ({ scopes: ['openid', 'tinycloud:mcp'], createdAt: new Date(NOW.getTime() - 7_200_000) }) },
      session: { findFirst: async () => ({ id: 's' }) },
      $queryRaw: async () => [],
    } as unknown as McpRefreshDatabase;
  }

  test('a token rotated in the meantime goes on to the provider, whose reuse detection decides', async () => {
    expect(await run(raced({ revoked: new Date() }), null)).toBeNull();
  });

  test('a token that is still unrevoked, or gone, means the connection or the session ended', async () => {
    for (const afterwards of [{ revoked: null }, null]) {
      // Plain reads: a matcher object inside toMatchObject would be written into the shared refusal constant.
      const refusal = await run(raced(afterwards), null);
      expect(refusal?.status).toBe(400);
      expect(refusal?.error).toBe('invalid_grant');
      expect(refusal?.description).toContain('has ended');
    }
  });
});
