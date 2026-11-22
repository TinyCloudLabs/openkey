// TC-3800: a grant on secret keys made outside a signed approval request lasts 7 days at most. A sign-in popup or
// frame, a pasted link and `/authorize-sign` are clamped to it before anything is signed; signed bytes that ask for
// more (`/complete`, raw `/sign`) are refused, because they cannot be shortened. "Secret keys" are `decrypt` or
// `key.create` on a key or prefix under `default/secrets/`, or on an encryption resource that cannot be read; a whole
// network's `decrypt` joins them only while `OPENKEY_NETWORK_DECRYPT_CAP=enabled` (Sam's D3). A signed approval
// request (`/a/`) is held by its own window check (`approvalLifetimeCapSeconds`), network included.
import { SECRET_GRANT_MAX_SECONDS, secretLifetimeCapApplies } from '@openkey/capability-review';
import { signedSiweExpirationTime } from '../routes/delegate-validation';
import { recapResources } from './app-key-refusal';
import { decodeHexUtf8 } from './siwe-origin';

export const SECRET_GRANT_MAX_MS = SECRET_GRANT_MAX_SECONDS * 1000;
/** Signed bytes may end this much past the cap, for the time between the server's clock and the signer's. */
const CLOCK_SKEW_MS = 5_000;

export const SECRET_LIFETIME_CODE = 'secret_lifetime_exceeded';
export const SECRET_LIFETIME_MESSAGE = 'Access to your secrets can last up to 7 days. Ask again with an expiry of 7 days or less.';

/** `OPENKEY_NETWORK_DECRYPT_CAP=enabled` also holds a whole network's `decrypt` to 7 days. Off by default. */
export function networkDecryptCapEnabled(): boolean {
  return process.env.OPENKEY_NETWORK_DECRYPT_CAP === 'enabled';
}

/** A delegation permission as a request body lists it. */
export interface PermissionLike {
  service: string;
  space?: string;
  path: string;
  actions: readonly string[];
}

/** Are these delegation permissions held to 7 days? */
export function permissionsHeldToSecretCap(permissions: readonly PermissionLike[]): boolean {
  return secretLifetimeCapApplies(
    permissions.map(({ service, space, path, actions }) => ({ service, space: space ?? '', path, actions })),
    { networkDecrypt: networkDecryptCapEnabled() },
  );
}

/** Is this SIWE message held to 7 days? A ReCap that cannot be read is (the other refusals report it). */
export function siweHeldToSecretCap(siwe: string): boolean {
  const resources = recapResources(siwe);
  if (resources === null) return true;
  return secretLifetimeCapApplies(
    resources.map(([resource, actions]) => ({ service: 'tinycloud.encryption', space: 'encryption', path: resource, actions })),
    { networkDecrypt: networkDecryptCapEnabled() },
  );
}

/** A lifetime for these permissions: `expiryMs`, or 7 days when they are held to 7 days and it is longer. */
export function clampSecretExpiryMs(expiryMs: number, permissions: readonly PermissionLike[] | undefined): number {
  return permissions !== undefined && permissionsHeldToSecretCap(permissions) ? Math.min(expiryMs, SECRET_GRANT_MAX_MS) : expiryMs;
}

/** The latest Expiration Time this SIWE message may carry, as an ISO time, or null when it is not held to 7 days. */
export function secretCapExpirationTime(siwe: string, now: number): string | null {
  return siweHeldToSecretCap(siwe) ? new Date(now + SECRET_GRANT_MAX_MS).toISOString() : null;
}

/**
 * Do these signed (or about to be signed) bytes ask for more than 7 days on secret keys? True when the message is held
 * to 7 days and its Expiration Time is missing or more than 7 days (and the skew) from `now`.
 */
export function exceedsSecretLifetime(siwe: string, now: number): boolean {
  if (!siweHeldToSecretCap(siwe)) return false;
  const expirationTime = signedSiweExpirationTime(siwe);
  return expirationTime === undefined || Date.parse(expirationTime) > now + SECRET_GRANT_MAX_MS + CLOCK_SKEW_MS;
}

/** Same check for a message as the signer will cover it: as written, and as UTF-8 when it is `0x` hex. */
export function messageExceedsSecretLifetime(message: string, now: number): boolean {
  if (exceedsSecretLifetime(message, now)) return true;
  const decoded = decodeHexUtf8(message);
  return decoded !== null && exceedsSecretLifetime(decoded, now);
}

export function secretLifetimeBody(): { error: string; code: string } {
  return { error: SECRET_LIFETIME_MESSAGE, code: SECRET_LIFETIME_CODE };
}
