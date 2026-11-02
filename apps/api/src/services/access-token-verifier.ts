// Verifies OpenKey's own JWT access tokens: signature against the issuer's key set, issuer,
// audience and expiry. Shared by the token status check and the revoke denylist.

import { createLocalJWKSet, errors as joseErrors, jwtVerify, type JSONWebKeySet, type JWTPayload } from 'jose';

/** A token is a JWT of three base64url segments; anything longer than this is not one of ours. */
export const MAX_TOKEN_LENGTH = 8 * 1024;
export const JWT_SHAPE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

const JWKS_TTL_MS = 60_000;
const JWKS_MIN_REFETCH_MS = 10_000;
const SIGNING_ALGORITHMS = ['EdDSA', 'ES256', 'RS256'];

export interface AccessTokenVerifierOptions {
  /** The token issuer (`iss`), e.g. https://api.openkey.so/api/auth. */
  issuer: string;
  /** The issuer's public signing keys. A failure to read them is thrown, never read as an invalid token. */
  getJwks: () => Promise<JSONWebKeySet>;
  /** Clock, in milliseconds; tests only. */
  now?: () => number;
}

export type AccessTokenVerifier = (token: string, audience: string[]) => Promise<JWTPayload | null>;

/**
 * The payload of a token whose signature, issuer, audience and expiry all hold, else null. The key
 * set is cached for a minute and read again, at most every few seconds, for a key it has not seen.
 */
export function createAccessTokenVerifier(options: AccessTokenVerifierOptions): AccessTokenVerifier {
  const now = () => options.now?.() ?? Date.now();

  type SigningKeys = { resolver: ReturnType<typeof createLocalJWKSet>; fetchedAt: number };
  let cachedKeys: SigningKeys | null = null;
  async function signingKeys(refresh = false): Promise<SigningKeys> {
    const at = now();
    if (cachedKeys && (!refresh ? at - cachedKeys.fetchedAt < JWKS_TTL_MS : at - cachedKeys.fetchedAt < JWKS_MIN_REFETCH_MS)) return cachedKeys;
    cachedKeys = { resolver: createLocalJWKSet(await options.getJwks()), fetchedAt: at };
    return cachedKeys;
  }

  return async function verify(token, audience) {
    const attempt = async (keys: SigningKeys) =>
      (await jwtVerify(token, keys.resolver, {
        issuer: options.issuer, audience, algorithms: SIGNING_ALGORITHMS, currentDate: new Date(now()),
      })).payload;
    const first = await signingKeys();
    try {
      return await attempt(first);
    } catch (error) {
      // A key the cache has not seen yet: look once more, at most every few seconds.
      if (!(error instanceof joseErrors.JWKSNoMatchingKey)) return null;
    }
    const fresh = await signingKeys(true);
    if (fresh === first) return null;
    try { return await attempt(fresh); } catch { return null; }
  };
}
