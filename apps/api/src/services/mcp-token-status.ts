import type { PrismaClient } from '@openkey/db';

/**
 * Whether the user's connection that a token belongs to still stands. One
 * predicate for both sides of an MCP token's life: the token status check for
 * resource servers asks it about an access token, and the refresh guard asks it
 * about a refresh token before the provider rotates it, so a refresh that is
 * answered 200 always yields an access token the status check calls active.
 */

export type McpTokenStatusDatabase = Pick<PrismaClient, 'oauthClient' | 'oauthConsent' | 'session'>;

export interface McpTokenSubject {
  userId: string;
  clientId: string;
  /** The web session the token was issued under (`sid`); a token without one is inactive. */
  sessionId: string | null;
  /** The scopes the token carries (or, for a refresh, asks for). */
  scopes: readonly string[];
  /** When the token was issued, in whole seconds. */
  issuedAtSeconds: number;
}

export type McpTokenInactiveReason = 'client' | 'consent' | 'scope' | 'older_than_consent' | 'session';
export type McpTokenStatus = { active: true } | { active: false; reason: McpTokenInactiveReason };

export async function mcpTokenStatus(database: McpTokenStatusDatabase, subject: McpTokenSubject, now: Date): Promise<McpTokenStatus> {
  const { userId, clientId, sessionId, scopes, issuedAtSeconds } = subject;
  if (!sessionId) return { active: false, reason: 'session' };
  const [client, consent, session] = await Promise.all([
    database.oauthClient.findUnique({ where: { clientId }, select: { disabled: true } }),
    database.oauthConsent.findUnique({ where: { userId_clientId: { userId, clientId } }, select: { scopes: true, createdAt: true } }),
    database.session.findFirst({ where: { id: sessionId, userId, expiresAt: { gt: now } }, select: { id: true } }),
  ]);
  if (!client || client.disabled) return { active: false, reason: 'client' };
  if (!consent) return { active: false, reason: 'consent' };
  if (!session) return { active: false, reason: 'session' };
  // Every scope must still be in the user's consent.
  const consented = new Set(consent.scopes);
  if (!scopes.every((granted) => consented.has(granted))) return { active: false, reason: 'scope' };
  // The consent must not be newer than the token: disconnecting deletes the row and
  // reconnecting creates a new one, and a token issued before that must not come back.
  // Consent times are whole seconds, so compare in whole seconds. A token issued in the
  // same second the consent row was created stays active (`>=` the consent's second),
  // which is the token of the very sign-in that created it. A consent time that cannot
  // be read ends the token.
  const consentSecond = Math.floor(new Date(consent.createdAt).getTime() / 1000);
  if (!Number.isFinite(consentSecond) || issuedAtSeconds < consentSecond) return { active: false, reason: 'older_than_consent' };
  return { active: true };
}
