// A grant on secret keys made outside a signed approval request lasts 7 days at most. A sign-in popup or
// frame, a pasted link and `/authorize-sign` are clamped to it before anything is signed; signed bytes that ask for
// more (`/complete`, raw `/sign`) are refused, because they cannot be shortened. "Secret keys" are `decrypt` or
// `key.create` on a key or prefix under `default/secrets/`, or on an encryption resource that cannot be read, a KV
// read of the secrets vault (`get`, `list`, `metadata` or `sync` on `vault/secrets` or a path under it), and any action
// of the `secrets` service; a whole network's `decrypt` joins them only while `OPENKEY_NETWORK_DECRYPT_CAP=enabled`.
// A signed approval request (`/a/`) is held by its own window check (`approvalLifetimeCapSeconds`), network included.
import { SECRET_GRANT_MAX_SECONDS, secretLifetimeCapApplies, siweExpirationTime } from '@openkey/capability-review';
import { recapResources } from './app-key-refusal';
import { decodeHexUtf8 } from './siwe-origin';

export const SECRET_GRANT_MAX_MS = SECRET_GRANT_MAX_SECONDS * 1000;
/** Signed bytes may end this much past the cap, for the time between the server's clock and the signer's. */
const CLOCK_SKEW_MS = 5_000;

export const SECRET_LIFETIME_CODE = 'secret_lifetime_exceeded';
/** The refusal for a grant on secret keys. */
export const SECRET_LIFETIME_MESSAGE =
  'This request asks for secret access longer than 7 days. Secret access lasts at most 7 days, so ask again with an expiry of 7 days or less.';
/** The refusal for a whole network's `decrypt`, held only while `OPENKEY_NETWORK_DECRYPT_CAP=enabled`. */
export const NETWORK_LIFETIME_MESSAGE =
  'This request asks for access to secrets or encrypted data longer than 7 days. Access to secrets or encrypted data lasts at most 7 days, so ask again with an expiry of 7 days or less.';

/** What holds a grant to 7 days: secret keys, or (with the flag) a whole network's `decrypt`, which says more. */
export type SecretLifetimeReach = 'secrets' | 'network';

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

interface ReachEntry {
  service: string;
  space: string;
  path: string;
  actions: readonly string[];
}

/** `network` when the flag is on and some entry is a whole network's `decrypt`; else `secrets` when held at all. */
function reachOf(entries: readonly ReachEntry[]): SecretLifetimeReach | null {
  const networkDecrypt = networkDecryptCapEnabled();
  if (!secretLifetimeCapApplies(entries, { networkDecrypt })) return null;
  const network = networkDecrypt && entries.some((entry) =>
    !secretLifetimeCapApplies([entry], { networkDecrypt: false }) && secretLifetimeCapApplies([entry], { networkDecrypt: true }));
  return network ? 'network' : 'secrets';
}

/** Are these delegation permissions held to 7 days? */
export function permissionsHeldToSecretCap(permissions: readonly PermissionLike[]): boolean {
  return reachOf(permissions.map(({ service, space, path, actions }) => ({ service, space: space ?? '', path, actions }))) !== null;
}

/**
 * The entries a ReCap resource stands for: its encryption reading (a key URN, or a resource that cannot be read),
 * for `kv` abilities a KV entry on the path after the `kv` segment of `<space>/kv` or `<space>/kv/<path>` (an empty
 * path, the whole space, when there is none; a KV resource with no `kv` segment counts as the secrets vault), and
 * for `secrets` abilities a `secrets` service entry (fail closed, whatever the path).
 */
function reachEntriesOf([resource, actions]: [string, string[]]): ReachEntry[] {
  const entries: ReachEntry[] = [{ service: 'tinycloud.encryption', space: 'encryption', path: resource, actions }];
  const kvActions = actions.filter((action) => /^(?:tinycloud\.)?kv\//i.test(action));
  if (kvActions.length > 0) {
    const match = /^[^/]*\/kv(?:\/(.*))?$/s.exec(resource);
    const path = match === null ? 'vault/secrets/' : match[1] ?? '';
    entries.push({ service: 'tinycloud.kv', space: '', path, actions: kvActions });
  }
  const secretsActions = actions.filter((action) => /^(?:tinycloud\.)?secrets\//i.test(action));
  if (secretsActions.length > 0) entries.push({ service: 'tinycloud.secrets', space: '', path: resource, actions: secretsActions });
  return entries;
}

/** What holds this SIWE message to 7 days, or null. A ReCap that cannot be read is held (the other refusals report it). */
function siweSecretReach(siwe: string): SecretLifetimeReach | null {
  const resources = recapResources(siwe);
  if (resources === null) return 'secrets';
  return reachOf(resources.flatMap(reachEntriesOf));
}

/** A lifetime for these permissions: `expiryMs`, or 7 days when they are held to 7 days and it is longer. */
export function clampSecretExpiryMs(expiryMs: number, permissions: readonly PermissionLike[] | undefined): number {
  return permissions !== undefined && permissionsHeldToSecretCap(permissions) ? Math.min(expiryMs, SECRET_GRANT_MAX_MS) : expiryMs;
}

/** The latest Expiration Time this SIWE message may carry, as an ISO time, or null when it is not held to 7 days. */
export function secretCapExpirationTime(siwe: string, now: number): string | null {
  return siweSecretReach(siwe) !== null ? new Date(now + SECRET_GRANT_MAX_MS).toISOString() : null;
}

/**
 * Do these signed (or about to be signed) bytes ask for more than 7 days on secret keys? What holds them, when the
 * message is held to 7 days and its Expiration Time is missing or more than 7 days (and the skew) from `now`; else null.
 */
export function exceedsSecretLifetime(siwe: string, now: number): SecretLifetimeReach | null {
  const reach = siweSecretReach(siwe);
  if (reach === null) return null;
  const expirationTime = siweExpirationTime(siwe);
  return expirationTime === null || !(Date.parse(expirationTime) <= now + SECRET_GRANT_MAX_MS + CLOCK_SKEW_MS) ? reach : null;
}

/** Same check for a message as the signer will cover it: as written, and as UTF-8 when it is `0x` hex. */
export function messageExceedsSecretLifetime(message: string, now: number): SecretLifetimeReach | null {
  const asWritten = exceedsSecretLifetime(message, now);
  if (asWritten !== null) return asWritten;
  const decoded = decodeHexUtf8(message);
  return decoded === null ? null : exceedsSecretLifetime(decoded, now);
}

export function secretLifetimeMessage(reach: SecretLifetimeReach): string {
  return reach === 'network' ? NETWORK_LIFETIME_MESSAGE : SECRET_LIFETIME_MESSAGE;
}

export function secretLifetimeBody(reach: SecretLifetimeReach): { error: string; code: string } {
  return { error: secretLifetimeMessage(reach), code: SECRET_LIFETIME_CODE };
}
