import type { PrismaClient } from '@openkey/db';
import { TINYCLOUD_MCP_SCOPE } from '../oauth-config';
import { storedRefreshToken, type ProviderTokenOptions } from './native-delegation/provider-tokens';

/**
 * An MCP access token is active only while the web session it was issued under
 * (`sid`) lives. The provider's refresh grant never looks at that session, so a
 * refresh keeps returning tokens that are inactive on arrival. This check runs
 * before the provider: a refusal leaves the refresh token unrotated.
 */

export type McpRefreshDatabase = Pick<PrismaClient, 'oauthRefreshToken' | 'session'>;

export type McpRefreshRefusal = {
  status: 400 | 503;
  error: 'invalid_grant' | 'temporarily_unavailable';
  description: string;
};

const SESSION_ENDED: McpRefreshRefusal = {
  status: 400,
  error: 'invalid_grant',
  description: 'the session that authorized this connection has ended; connect again',
};

const UNAVAILABLE: McpRefreshRefusal = {
  status: 503,
  error: 'temporarily_unavailable',
  description: 'the session could not be checked; try again',
};

/**
 * Null lets the request through to the provider. Only a refresh token that
 * carries `tinycloud:mcp` and belongs to the requesting client is judged here;
 * every other token, unknown token or client mismatch is the provider's call.
 * A failed lookup answers 503, never `invalid_grant` (the client would discard
 * a good connection) and never an unhandled 500.
 */
export async function mcpRefreshSessionRefusal(
  database: McpRefreshDatabase,
  tokens: ProviderTokenOptions,
  refreshToken: string,
  requestingClientId: string | null,
  now: Date = new Date(),
): Promise<McpRefreshRefusal | null> {
  let stored: string | null;
  try {
    stored = await storedRefreshToken(tokens, refreshToken);
  } catch {
    // The provider rejects a token it cannot normalize with its own error.
    return null;
  }
  if (stored === null) return null;
  try {
    const row = await database.oauthRefreshToken.findUnique({
      where: { token: stored },
      select: { clientId: true, userId: true, sessionId: true, scopes: true },
    });
    if (!row || !row.scopes.includes(TINYCLOUD_MCP_SCOPE) || row.clientId !== requestingClientId) return null;
    if (!row.sessionId) return SESSION_ENDED;
    const session = await database.session.findFirst({
      where: { id: row.sessionId, userId: row.userId, expiresAt: { gt: now } },
      select: { id: true },
    });
    return session ? null : SESSION_ENDED;
  } catch {
    return UNAVAILABLE;
  }
}
