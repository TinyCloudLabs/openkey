import { Hono } from 'hono';
import { calculateJwkThumbprint, type JWK } from 'jose';
import type { TeeClient } from '@openkey/tee';
import { log, logError } from '../log';

/**
 * TC-3842: OpenKey's public attestation, modelled on tinycloud-node's `GET /attestation`
 * (tinycloud-node-server/src/routes/attestation.rs). No session: anyone can ask this instance
 * for a fresh TDX quote over a binding of its public identity and the caller's nonce.
 *
 * key_binding = `so.openkey/tee-key/v1\0:<identity>:<nonce>`, where `\0` is the two characters
 * backslash and zero (as in the node's preimage), and
 * identity = `<issuer>#<thumbprints>`: the OIDC issuer, then the RFC 7638 SHA-256 JWK
 * thumbprints (base64url) of every key its JWKS serves, sorted and joined with ','.
 * Those are the keys OpenKey signs ID and access tokens with.
 *
 * The quote's REPORTDATA is SHA-256 of the UTF-8 key_binding followed by 32 zero bytes;
 * `@openkey/tee` checks that before this answers 200. This route does not verify the quote.
 */
export const KEY_BINDING_DOMAIN = 'so.openkey/tee-key/v1\\0';

const MAX_NONCE_LENGTH = 64;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const NONCE_ERROR = `nonce must be 1-${MAX_NONCE_LENGTH} characters of A-Z, a-z, 0-9, '-' or '_'`;

/** Each call takes a quote from the guest agent; the cap is per process, since no client address is trustworthy here. */
export const ATTESTATION_LIMIT_PER_MINUTE = 60;
const RATE_WINDOW_MS = 60_000;

export interface AttestationRouterOptions {
  tee: Pick<TeeClient, 'getQuote' | 'appInfo' | 'isInTee'>;
  /** OIDC issuer, `${BETTER_AUTH_URL}/api/auth`. */
  issuer: string;
  /** The key set `${issuer}/jwks` serves. */
  readSigningKeys: () => Promise<{ keys: JWK[] }>;
  limitPerMinute?: number;
  now?: () => number;
}

/** `<issuer>#<sorted JWK thumbprints>`; throws when the key set is empty. */
export async function attestationIdentity(issuer: string, keys: JWK[]): Promise<string> {
  if (keys.length === 0) throw new Error('the issuer serves no signing keys');
  const thumbprints = await Promise.all(keys.map((key) => calculateJwkThumbprint(key, 'sha256')));
  return `${issuer}#${[...new Set(thumbprints)].sort().join(',')}`;
}

export function keyBinding(identity: string, nonce: string): string {
  return `${KEY_BINDING_DOMAIN}:${identity}:${nonce}`;
}

export function createAttestationRouter(options: AttestationRouterOptions): Hono {
  const limit = options.limitPerMinute ?? ATTESTATION_LIMIT_PER_MINUTE;
  const now = options.now ?? Date.now;
  let windowStart = 0;
  let windowCalls = 0;
  const takeSlot = (): boolean => {
    const at = now();
    if (at - windowStart >= RATE_WINDOW_MS) {
      windowStart = at;
      windowCalls = 0;
    }
    windowCalls += 1;
    return windowCalls <= limit;
  };

  const router = new Hono();
  router.get('/', async (c) => {
    c.header('Cache-Control', 'no-store');
    if (!takeSlot()) {
      log('warn', 'public_attestation_rate_limited');
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }
    // A verifier always sends a fresh nonce; without one the quote proves no freshness.
    const nonce = c.req.query('nonce');
    if (nonce === undefined || !NONCE_PATTERN.test(nonce)) {
      return c.json({ error: NONCE_ERROR }, 400);
    }
    if (!options.tee.isInTee()) {
      return c.json({ mode: 'classic', message: 'This instance is not running in a TEE' });
    }
    try {
      const identity = await attestationIdentity(options.issuer, (await options.readSigningKeys()).keys);
      const binding = keyBinding(identity, nonce);
      const [app, quote] = await Promise.all([options.tee.appInfo(), options.tee.getQuote(binding)]);
      return c.json({
        mode: 'dstack',
        quote: quote.quote,
        event_log: quote.eventLog,
        compose_hash: app.composeHash,
        app_id: app.appId,
        identity,
        key_binding: binding,
        key_binding_sha256: quote.reportDataSha256,
        timestamp: new Date(now()).toISOString(),
      });
    } catch (error) {
      logError('error', 'public_attestation_failed', error);
      return c.json({ error: 'quote_unavailable' }, 503);
    }
  });
  return router;
}
