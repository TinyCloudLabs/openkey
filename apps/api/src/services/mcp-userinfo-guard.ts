// /oauth2/userinfo for an MCP access token (TC-1366).
//
// The provider answers /oauth2/userinfo for a JWT access token after checking only its signature, audience, issuer,
// expiry and that the client is not disabled: not the owner's consent, the sign-in it was issued under, or the revoke
// list. With a 5-minute token that gap was small; an MCP token now lasts 12 hours, so this ends it. A JWT whose
// audience is one of the hosted MCP resources must pass the same checks the resource server's status check makes
// (routes/oauth-resource-introspect.ts). Any other token is passed on to the provider untouched.

import type { Context, MiddlewareHandler } from 'hono';
import { logError } from '../log';
import { JWT_SHAPE, MAX_TOKEN_LENGTH, type AccessTokenVerifier } from './access-token-verifier';
import { mcpTokenStatus, type McpTokenStatusDatabase } from './mcp-token-status';
import { isAccessTokenRevoked, type RevokedAccessTokenDatabase } from './revoked-access-token';

export interface McpUserinfoGuardOptions {
  database: McpTokenStatusDatabase & RevokedAccessTokenDatabase;
  verify: AccessTokenVerifier;
  /** The hosted MCP resources whose tokens are checked here. */
  mcpAudiences: readonly string[];
  now?: () => number;
}

const NO_STORE = { 'Cache-Control': 'no-store', Pragma: 'no-cache' } as const;

const invalid = (c: Context) => c.json({ error: 'invalid_token', error_description: 'The access token is not active' }, 401, {
  ...NO_STORE, 'WWW-Authenticate': 'Bearer error="invalid_token"',
});

export function createMcpUserinfoGuard(options: McpUserinfoGuardOptions): MiddlewareHandler {
  return async (c, next) => {
    // Read the header as the provider does: it strips a "Bearer " prefix when there is one and otherwise takes the
    // whole value as the token, so a JWT sent with no scheme at all must be checked too.
    const header = c.req.header('authorization')?.trim();
    const token = header ? header.replace(/^bearer\s+/i, '').trim() : null;
    if (!token) return next();
    if (token.length > MAX_TOKEN_LENGTH || !JWT_SHAPE.test(token)) {
      // The provider's JWS decoder tolerates a signature with `=` padding or spaces in it, and the signature is not
      // part of what it signs, so a spelling this guard cannot read as a canonical JWT could still be accepted by the
      // provider as a withdrawn MCP token. Anything with a dot is a JWS candidate and is refused; provider opaque tokens
      // have no dots and pass through.
      return token.includes('.') ? invalid(c) : next();
    }
    try {
      const payload = await options.verify(token, [...options.mcpAudiences]);
      if (!payload) return next();
      const { sub, azp, sid, scope, iat } = payload as Record<string, unknown>;
      const [revoked, state] = await Promise.all([
        isAccessTokenRevoked(options.database, token),
        typeof sub === 'string' && typeof azp === 'string' && typeof sid === 'string' && typeof scope === 'string' && typeof iat === 'number'
          ? mcpTokenStatus(
            options.database,
            { userId: sub, clientId: azp, sessionId: sid, scopes: scope.split(' ').filter(Boolean), issuedAtSeconds: iat },
            new Date(options.now?.() ?? Date.now()),
          )
          : { active: false as const },
      ]);
      if (revoked || !state.active) return invalid(c);
    } catch (error) {
      // A lookup that fails is never an answer for a token that may have been withdrawn.
      logError('error', 'mcp_userinfo_guard_failed', error);
      return c.json({ error: 'temporarily_unavailable' }, 503, { ...NO_STORE, 'Retry-After': '5' });
    }
    return next();
  };
}
