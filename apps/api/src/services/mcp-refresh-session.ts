import type { PrismaClient } from '@openkey/db';
import { TINYCLOUD_MCP_SCOPE } from '../oauth-config';
import { mcpTokenStatus, type McpTokenStatusDatabase } from './mcp-token-status';
import { storedRefreshToken, type ProviderTokenOptions } from './native-delegation/provider-tokens';
import { clientSecretMatches } from './resource-server';
import { WEB_SESSION_ABSOLUTE_CAP_SECONDS } from './session-cap';
import { SESSION_EXPIRES_IN_SECONDS, SESSION_UPDATE_AGE_SECONDS } from './session-lifetime';

/**
 * An MCP access token is active only while the connection it belongs to stands
 * (see `mcpTokenStatus`). The provider's refresh grant looks at none of that, so
 * a refresh returned tokens that were inactive on arrival and the client kept
 * retrying. This runs before the provider: a refusal leaves the refresh token
 * unrotated.
 *
 * When the request authenticates as the token's client, a refresh that gets
 * through also extends the session that authorized it, up to the absolute cap
 * after sign-in. Only this path extends it on behalf of an MCP client; it
 * writes the row directly and never goes through Better Auth's session update.
 */

export type McpRefreshDatabase = Pick<PrismaClient, 'oauthRefreshToken' | '$queryRaw'> & McpTokenStatusDatabase;

export type McpRefreshRefusal = {
  status: 400 | 503;
  error: 'invalid_grant' | 'temporarily_unavailable';
  description: string;
  retryAfter?: number;
};

/** What the request presented, when the caller wants the session extended. */
export type McpRefreshExtension = {
  /** The client secret as the provider reads it: the Basic header's, else the body's. */
  presentedSecret: string | null;
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
 * Whether the provider will accept the request's client credentials. This
 * mirrors its client check (`validateClientCredentials`): a confidential
 * client must present its secret and it must match; a public client must
 * present none. When the provider would refuse, nothing is extended and the
 * refusal is left to it.
 */
function clientAuthenticates(client: { public: boolean | null; clientSecret: string | null }, presented: string | null): boolean {
  const secret = presented || null;
  if (!client.public && !secret) return false;
  if (secret && !client.clientSecret) return false;
  if (secret && !clientSecretMatches(secret, client.clientSecret)) return false;
  return true;
}

/**
 * One statement checks and extends. The refresh row, the consent, the client and
 * the session are all conditions of the update itself, so a sign-out, a
 * Disconnect or a revocation that lands first matches no row and one that lands
 * after ends the session as usual. The new expiry is the web renewal point
 * (`expiresIn - updateAge` from now, so a web use still renews it and re-sends the
 * cookie), capped at the absolute limit after sign-in, and never earlier than the
 * current expiry. Time is bound from the caller in UTC: the columns are
 * `timestamp(3)` without a time zone, so the database session's own time zone and
 * clock play no part.
 */
export async function extendSession(
  database: McpRefreshDatabase,
  row: { userId: string; clientId: string; sessionId: string },
  stored: string,
  now: Date,
): Promise<boolean> {
  const nowIso = now.toISOString();
  const renewSeconds = SESSION_EXPIRES_IN_SECONDS - SESSION_UPDATE_AGE_SECONDS;
  const capSeconds = WEB_SESSION_ABSOLUTE_CAP_SECONDS;
  const extended = await database.$queryRaw<{ id: string }[]>`
    WITH t AS (SELECT (${nowIso}::timestamptz AT TIME ZONE 'UTC') AS moment)
    UPDATE session s
    SET "expiresAt" = GREATEST(
          s."expiresAt",
          LEAST(t.moment + make_interval(secs => ${renewSeconds}::double precision),
                s."createdAt" + make_interval(secs => ${capSeconds}::double precision))
        ),
        "updatedAt" = t.moment
    FROM t
    WHERE s.id = ${row.sessionId}
      AND s."userId" = ${row.userId}
      AND s."expiresAt" > t.moment
      AND s."createdAt" + make_interval(secs => ${capSeconds}::double precision) > t.moment
      AND EXISTS (
        SELECT 1 FROM oauth_refresh_token r
        WHERE r.token = ${stored} AND r."userId" = s."userId" AND r."sessionId" = s.id
          AND r."clientId" = ${row.clientId} AND r.revoked IS NULL AND r."expiresAt" > t.moment
          AND ${TINYCLOUD_MCP_SCOPE} = ANY(r.scopes))
      AND EXISTS (
        SELECT 1 FROM oauth_consent c
        WHERE c."userId" = s."userId" AND c."clientId" = ${row.clientId} AND ${TINYCLOUD_MCP_SCOPE} = ANY(c.scopes))
      AND EXISTS (
        SELECT 1 FROM oauth_client o WHERE o."clientId" = ${row.clientId} AND o.disabled = false)
    RETURNING s.id`;
  return extended.length === 1;
}

/**
 * Null lets the request through to the provider. Only a refresh token that is
 * found, unrevoked and unexpired, carries `tinycloud:mcp` in its own scopes and
 * belongs to the requesting client (`requestingClientId`: the Basic header when
 * present, else the body) is judged here. Unknown, revoked and expired tokens
 * and another client's token stay the provider's call, so its reuse detection
 * still removes the token family. An error answers 503 with a retry hint: it
 * never reaches the provider and is never `invalid_grant` (the client would
 * discard a good connection).
 *
 * With `extension`, a token that passes also extends its session (see
 * `extendSession`), after the client has authenticated; a session at or past the
 * cap matches no row and the answer is `invalid_grant`.
 */
export async function mcpRefreshRefusal(
  database: McpRefreshDatabase,
  tokens: ProviderTokenOptions,
  refreshToken: string,
  requestingClientId: string | null,
  requestedScope: string | null,
  now: Date = new Date(),
  extension?: McpRefreshExtension,
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
    if (!state.active) return CONNECTION_ENDED;
    if (!extension || !row.sessionId) return null;

    const client = await database.oauthClient.findUnique({
      where: { clientId: row.clientId },
      select: { public: true, clientSecret: true },
    });
    if (!client || !clientAuthenticates(client, extension.presentedSecret)) return null;
    const extended = await extendSession(database, { userId: row.userId, clientId: row.clientId, sessionId: row.sessionId }, stored, now);
    if (extended) return null;
    // Nothing matched although the checks above held a moment ago. If the token has
    // been rotated since (a parallel refresh of the same token got there first), the
    // provider decides: its reuse detection removes the whole token family, so a
    // replay of a token that was taken ends the chain of whoever holds the newer
    // token. Otherwise the connection or the session ended, or the session reached
    // its cap.
    const current = await database.oauthRefreshToken.findUnique({ where: { token: stored }, select: { revoked: true } });
    return current?.revoked ? null : CONNECTION_ENDED;
  } catch {
    return UNAVAILABLE;
  }
}
