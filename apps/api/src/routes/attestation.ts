import { randomBytes } from 'node:crypto';
import { symmetricDecrypt } from 'better-auth/crypto';
import { Hono } from 'hono';
import { CompactSign, calculateJwkThumbprint, compactVerify, importJWK, type JWK } from 'jose';
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
 * thumbprints (base64url) of the keys this measured code holds and signs with, sorted and joined
 * with ','. A key the issuer's JWKS serves counts only when this process can load its private key
 * (the database row, decrypted with the auth secret) and that private key signs a fresh challenge
 * the served public key verifies. The rest are left out of the identity and counted in
 * `excluded_keys`, so a public key written into the table without its private key is never quoted.
 *
 * The quote's REPORTDATA is SHA-256 of the UTF-8 key_binding followed by 32 zero bytes;
 * `@openkey/tee` checks that before this answers 200. This route does not verify the quote.
 *
 * Limit: these are keys this measured code holds and signs with; the keys are stored in the
 * database. Anyone with database read plus BETTER_AUTH_SECRET can sign with them too, so a 200
 * proves possession, not exclusivity. A TEE-derived signing key is a one-way step (new
 * identity), outside this route.
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
  /**
   * The private JWK behind a served key id, or null when this process has none it can open.
   * Throws only when the lookup itself fails, which answers 503.
   */
  loadPrivateKey: (kid: string) => Promise<JWK | null>;
  limitPerMinute?: number;
  now?: () => number;
}

/** True when `privateJwk` signs a fresh challenge that `publicJwk` verifies. */
export async function holdsPrivateKey(publicJwk: JWK, privateJwk: JWK): Promise<boolean> {
  const alg = publicJwk.alg ?? 'EdDSA';
  try {
    const signed = await new CompactSign(randomBytes(32)).setProtectedHeader({ alg }).sign(await importJWK(privateJwk, alg));
    await compactVerify(signed, await importJWK(publicJwk, alg));
    return true;
  } catch {
    return false;
  }
}

/**
 * A private OKP or EC JWK (kty, d, crv, x, y) from its JSON text, or null. Better Auth's jwt plugin as
 * OpenKey configures it makes Ed25519 keys; any other key type is not read and so not quoted.
 */
export function parsePrivateJwk(text: string): JWK | null {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof value !== 'object' || value === null) return null;
  if (!('kty' in value) || typeof value.kty !== 'string' || !('d' in value) || typeof value.d !== 'string') return null;
  if (!('crv' in value) || typeof value.crv !== 'string' || !('x' in value) || typeof value.x !== 'string') return null;
  const jwk: JWK = { kty: value.kty, crv: value.crv, x: value.x, d: value.d };
  if ('y' in value && typeof value.y === 'string') jwk.y = value.y;
  return jwk;
}

/**
 * Loads the private JWK behind a served key id as Better Auth's signer does: the jwks row's privateKey is a
 * JSON string of the ciphertext, decrypted with the auth secret. Returns null for no row, or for a row this
 * process cannot open, such as a public key written into the table without a private key encrypted under
 * this process's secret. A failed row read throws.
 */
export function jwksPrivateKeyLoader(source: {
  readEncryptedPrivateKey: (kid: string) => Promise<string | null>;
  secret: () => Promise<Parameters<typeof symmetricDecrypt>[0]['key']>;
}): (kid: string) => Promise<JWK | null> {
  return async (kid) => {
    const stored = await source.readEncryptedPrivateKey(kid);
    if (stored === null) return null;
    let encrypted: unknown;
    try {
      encrypted = JSON.parse(stored);
    } catch {
      return null;
    }
    if (typeof encrypted !== 'string') return null;
    const opened = await symmetricDecrypt({ key: await source.secret(), data: encrypted }).catch(() => null);
    return opened === null ? null : parsePrivateJwk(opened);
  };
}

/** The served keys whose private key this process holds. */
export async function heldSigningKeys(keys: JWK[], loadPrivateKey: (kid: string) => Promise<JWK | null>): Promise<JWK[]> {
  const held = await Promise.all(keys.map(async (key) => {
    if (typeof key.kid !== 'string') return false;
    const privateJwk = await loadPrivateKey(key.kid);
    return privateJwk !== null && await holdsPrivateKey(key, privateJwk);
  }));
  return keys.filter((_, index) => held[index]);
}

/** `<issuer>#<sorted JWK thumbprints>`; throws when the key set is empty. */
export async function attestationIdentity(issuer: string, keys: JWK[]): Promise<string> {
  if (keys.length === 0) throw new Error('this process holds none of the served signing keys');
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
    // A verifier always sends a fresh nonce; without one the quote proves no freshness.
    // Validated before the rate limit, so a malformed request does not spend a slot.
    const nonce = c.req.query('nonce');
    if (nonce === undefined || !NONCE_PATTERN.test(nonce)) {
      return c.json({ error: NONCE_ERROR }, 400);
    }
    if (!takeSlot()) {
      log('warn', 'public_attestation_rate_limited');
      return c.json({ error: 'Rate limit exceeded' }, 429);
    }
    if (!options.tee.isInTee()) {
      return c.json({ mode: 'classic', message: 'This instance is not running in a TEE' });
    }
    try {
      const { keys } = await options.readSigningKeys();
      const held = await heldSigningKeys(keys, options.loadPrivateKey);
      const identity = await attestationIdentity(options.issuer, held);
      const binding = keyBinding(identity, nonce);
      const [app, quote] = await Promise.all([options.tee.appInfo(), options.tee.getQuote(binding)]);
      return c.json({
        mode: 'dstack',
        quote: quote.quote,
        event_log: quote.eventLog,
        compose_hash: app.composeHash,
        app_id: app.appId,
        identity,
        excluded_keys: keys.length - held.length,
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
