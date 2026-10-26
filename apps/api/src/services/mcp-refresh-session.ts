import type { PrismaClient } from '@openkey/db';
import { TINYCLOUD_MCP_SCOPE } from '../oauth-config';
import { mcpTokenStatus, type McpTokenStatusDatabase } from './mcp-token-status';
import { storedRefreshToken, type ProviderTokenOptions } from './native-delegation/provider-tokens';

/**
 * An MCP access token is active only while the connection it belongs to stands
 * (see `mcpTokenStatus`). The provider's refresh grant looks at none of that, so
 * a refresh returned tokens that were inactive on arrival and the client kept
 * retrying. This runs before the provider: a refusal leaves the refresh token
 * unrotated.
 */

export type McpRefreshDatabase = Pick<PrismaClient, 'oauthRefreshToken'> & McpTokenStatusDatabase;

export type McpRefreshRefusal = {
  status: 400 | 503;
  error: 'invalid_grant' | 'temporarily_unavailable';
  description: string;
  retryAfter?: number;
};

const CONNECTION_ENDED: McpRefreshRefusal = {
  status: 400,
  error: 'invalid_grant',
  description: 'the connection that authorized this token has ended; connect again',
};

const UNAVAILABLE: McpRefreshRefusal = {
  status: 503,
  error: 'temporarily_unavailable',
  description: 'the connection could not be checked; try again',
  retryAfter: 5,
};

/**
 * Null lets the request through to the provider. Only a refresh token that is
 * found, unrevoked and unexpired, carries `tinycloud:mcp` in its own scopes and
 * belongs to the requesting client (`requestingClientId`: the Basic header when
 * present, else the body) is judged here. Unknown, revoked and expired tokens
 * and another client's token stay the provider's call, so its reuse detection
 * still removes the token family. An error answers 503 with a retry hint: it
 * never reaches the provider and is never `invalid_grant` (the client would
 * discard a good connection).
 */
export async function mcpRefreshRefusal(
  database: McpRefreshDatabase,
  tokens: ProviderTokenOptions,
  refreshToken: string,
  requestingClientId: string | null,
  requestedScope: string | null,
  now: Date = new Date(),
): Promise<McpRefreshRefusal | null> {
  try {
    const stored = await storedRefreshToken(tokens, refreshToken);
    if (stored === null) return null;
    const row = await database.oauthRefreshToken.findUnique({
      where: { token: stored },
      select: { clientId: true, userId: true, sessionId: true, scopes: true, revoked: true, expiresAt: true, createdAt: true },
    });
    if (!row || row.revoked || row.expiresAt <= now) return null;
    if (!row.scopes.includes(TINYCLOUD_MCP_SCOPE) || row.clientId !== requestingClientId) return null;
    const asked = requestedScope === null ? row.scopes : requestedScope.split(' ').filter(Boolean);
    const state = await mcpTokenStatus(database, {
      userId: row.userId,
      clientId: row.clientId,
      sessionId: row.sessionId,
      scopes: asked,
      issuedAtSeconds: Math.floor(row.createdAt.getTime() / 1000),
    }, now);
    return state.active ? null : CONNECTION_ENDED;
  } catch {
    return UNAVAILABLE;
  }
}
