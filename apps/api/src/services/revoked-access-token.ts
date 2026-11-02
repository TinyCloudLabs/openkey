// Revocation of JWT access tokens at the provider's /oauth2/revoke (TC-2104).
//
// A JWT access token has no stored row, so the provider's revoke of one changes nothing and the
// token stays valid until its own `exp`. This keeps the revoked tokens' keys until then, and the
// token status check (routes/oauth-resource-introspect.ts) reads them.
//
// The key is the SHA-256 of the token's signing input (`header.payload`), not of the whole string:
// the last character of the signature has spare bits, and an ES256 signature has a second valid
// form (s and n - s), so a changed signature still verifies. The signing input is the same for
// every such variant. The token itself is never stored.

import { createHash } from 'node:crypto';
import type { Context, MiddlewareHandler } from 'hono';
import type { PrismaClient } from '@openkey/db';
import { logError } from '../log';
import { JWT_SHAPE, MAX_TOKEN_LENGTH, type AccessTokenVerifier } from './access-token-verifier';
import { parseProviderForm, providerPath, requestClients } from './native-delegation/interceptors';

export type RevokedAccessTokenDatabase = Pick<PrismaClient, 'revokedAccessToken'>;

/** The key a revoked token is stored under, or null if the string is not a JWT of the allowed size. */
export function accessTokenKey(token: string): string | null {
  if (token.length > MAX_TOKEN_LENGTH || !JWT_SHAPE.test(token)) return null;
  return createHash('sha256').update(token.slice(0, token.lastIndexOf('.'))).digest('base64url');
}

/**
 * Whether the token (already verified) was revoked. A token that cannot be keyed counts as revoked,
 * and a failed lookup is thrown: neither ever reads as an active token.
 */
export async function isAccessTokenRevoked(database: RevokedAccessTokenDatabase, token: string): Promise<boolean> {
  const key = accessTokenKey(token);
  if (key === null) return true;
  return (await database.revokedAccessToken.findUnique({ where: { tokenHash: key }, select: { tokenHash: true } })) !== null;
}

const DEFAULT_SWEEP_INTERVAL_MS = 60_000;

export interface RevokeDenylistOptions {
  database: RevokedAccessTokenDatabase;
  /** The verifier the token status check uses. */
  verify: AccessTokenVerifier;
  /** Audiences this server issues tokens for (`oauthValidAudiences`). */
  validAudiences: readonly string[];
  /** Clock, in milliseconds; tests only. */
  now?: () => number;
  /** Least time between deletes of expired rows. */
  sweepIntervalMs?: number;
}

/** What a revoke request names: the token as sent, and the client the provider resolves from it. */
async function revocation(request: Request): Promise<{ token: string; clientId: string } | null> {
  const parsed = await parseProviderForm(request);
  if (!('params' in parsed)) return null;
  const token = parsed.params.get('token');
  if (!token || accessTokenKey(token) === null) return null;
  const clients = requestClients(request, parsed.params);
  if ('status' in clients || !clients.effective) return null;
  return { token, clientId: clients.effective };
}

const UNAVAILABLE = JSON.stringify({
  error: 'temporarily_unavailable',
  error_description: 'the revocation could not be recorded; try again',
});

/**
 * Runs around the provider's revoke (mounted before the provider interceptors, so their refusals
 * and the provider's own answer come first). The request always goes to the provider unchanged and
 * its response is the answer. Only when that answer is 200 is a row written, and only for a token
 * that verifies and was issued to the client that sent the request, as the provider resolved it
 * (Basic header first). A failure to write, or to read the signing keys, replaces the response with
 * 503: a revoke that was not recorded must not look like one that was.
 */
export function createRevokeDenylist(options: RevokeDenylistOptions): MiddlewareHandler {
  const now = () => options.now?.() ?? Date.now();
  const sweepIntervalMs = options.sweepIntervalMs ?? DEFAULT_SWEEP_INTERVAL_MS;
  const audiences = [...options.validAudiences];
  let lastSweep = 0;

  async function sweep(): Promise<void> {
    const at = now();
    if (at - lastSweep < sweepIntervalMs) return;
    lastSweep = at;
    try {
      await options.database.revokedAccessToken.deleteMany({ where: { expiresAt: { lt: new Date(at) } } });
    } catch (error) {
      logError('warn', 'revoked_token_sweep_failed', error);
    }
  }

  async function record({ token, clientId }: { token: string; clientId: string }): Promise<void> {
    const payload = await options.verify(token, audiences);
    if (!payload || payload.azp !== clientId || typeof payload.exp !== 'number') return;
    await options.database.revokedAccessToken.createMany({
      data: [{ tokenHash: accessTokenKey(token)!, clientId, expiresAt: new Date(payload.exp * 1000) }],
      skipDuplicates: true,
    });
    await sweep();
  }

  async function run(c: Context, next: () => Promise<void>): Promise<void> {
    const pending = await revocation(c.req.raw);
    await next();
    if (!pending || c.res.status !== 200) return;
    try {
      await record(pending);
    } catch (error) {
      logError('error', 'revoked_token_record_failed', error);
      (c as { res: Response | undefined }).res = undefined;
      c.res = new Response(UNAVAILABLE, {
        status: 503,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'Retry-After': '5' },
      });
    }
  }

  // Other auth routes go straight to the next handler without an async hop.
  return (c, next) => (c.req.method === 'POST' && providerPath(c.req.url) === '/oauth2/revoke' ? run(c, next) : next());
}
