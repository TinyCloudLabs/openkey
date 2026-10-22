/**
 * Decrypt lifetime cap for non-device OpenKey transports (TC-1781).
 *
 * A delegation or recap that contains `tinycloud.encryption/decrypt` must be
 * the only entry, must carry only that action, and must have an explicit
 * lifetime of at most one hour measured from signing time. Device flow has its
 * own equivalent rule in `device-authorization.ts` and is not routed through
 * this module.
 *
 * The enforcement flag is read on every call so tests can toggle it. Only the
 * exact strings `true` and `1` turn enforcement on; any other value is off.
 */

export const DECRYPT_LIFETIME_FLAG = 'DECRYPT_LIFETIME_ENFORCE_NON_DEVICE';
export const DECRYPT_ENTRY_MAX_LIFETIME_SECONDS = 60 * 60;
export const DECRYPT_LIFETIME_REFUSAL = 'a decrypt approval lasts at most one hour';

const ENCRYPTION_SERVICE = 'tinycloud.encryption';
const DECRYPT_ACTION = 'tinycloud.encryption/decrypt';

export interface DecryptPolicyEntry {
  service: string;
  actions: readonly string[];
  space?: string;
  path?: string;
}

export interface DecryptLifetimeInput {
  entries: readonly DecryptPolicyEntry[];
  /** Explicit lifetime in seconds, measured from signing time. */
  requestedTtlSeconds?: number | null;
  /** Explicit absolute expiry, measured from signing time. */
  expiresAt?: Date | string | number | null;
  /** Signing time in epoch milliseconds. Defaults to Date.now(). */
  now?: number;
}

export class DecryptLifetimeError extends Error {
  readonly code = 'invalid_request';
  readonly status = 400;

  constructor() {
    super(DECRYPT_LIFETIME_REFUSAL);
    this.name = 'DecryptLifetimeError';
  }
}

export function decryptLifetimeEnforcementEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const value = env[DECRYPT_LIFETIME_FLAG];
  return value === 'true' || value === '1';
}

let flagStateLogged = false;

/** Logs the flag state once per process. Logs the state only, never any other value. */
export function logDecryptLifetimeFlagOnce(
  log: (line: string) => void = (line) => console.log(line),
  env: NodeJS.ProcessEnv = process.env,
): void {
  if (flagStateLogged) return;
  flagStateLogged = true;
  log(`${DECRYPT_LIFETIME_FLAG}=${decryptLifetimeEnforcementEnabled(env) ? 'on' : 'off'}`);
}

function isDecryptAction(entry: DecryptPolicyEntry, action: string): boolean {
  if (action === DECRYPT_ACTION) return true;
  const isEncryption = entry.service === ENCRYPTION_SERVICE || entry.service === 'encryption';
  return isEncryption && (action === 'decrypt' || action.endsWith('/decrypt'));
}

export function hasDecryptEntry(entries: readonly DecryptPolicyEntry[]): boolean {
  return entries.some((entry) => entry.actions.some((action) => isDecryptAction(entry, action)));
}

/**
 * Throws `DecryptLifetimeError` when the request carries a decrypt entry that
 * is not alone or has no explicit lifetime of at most one hour. Requests with
 * no decrypt entry are not affected.
 */
export function assertDecryptLifetime(input: DecryptLifetimeInput): void {
  if (!hasDecryptEntry(input.entries)) return;

  if (input.entries.length !== 1) throw new DecryptLifetimeError();
  const [entry] = input.entries;
  if (entry.actions.length !== 1 || !isDecryptAction(entry, entry.actions[0])) {
    throw new DecryptLifetimeError();
  }

  const hasTtl = input.requestedTtlSeconds !== undefined && input.requestedTtlSeconds !== null;
  const hasExpiry = input.expiresAt !== undefined && input.expiresAt !== null;
  if (!hasTtl && !hasExpiry) throw new DecryptLifetimeError();

  if (hasTtl) {
    const ttl = input.requestedTtlSeconds as number;
    if (!Number.isFinite(ttl) || ttl <= 0 || ttl > DECRYPT_ENTRY_MAX_LIFETIME_SECONDS) {
      throw new DecryptLifetimeError();
    }
  }

  if (hasExpiry) {
    const expiryMs = input.expiresAt instanceof Date
      ? input.expiresAt.getTime()
      : typeof input.expiresAt === 'number'
        ? input.expiresAt
        : Date.parse(input.expiresAt as string);
    const nowMs = input.now ?? Date.now();
    const remainingSeconds = (expiryMs - nowMs) / 1000;
    if (!Number.isFinite(remainingSeconds) || remainingSeconds <= 0 || remainingSeconds > DECRYPT_ENTRY_MAX_LIFETIME_SECONDS) {
      throw new DecryptLifetimeError();
    }
  }
}

/** Runs `assertDecryptLifetime` only when the flag is on. Flag off is a no-op. */
export function assertDecryptLifetimeIfEnforced(
  input: DecryptLifetimeInput,
  env: NodeJS.ProcessEnv = process.env,
): void {
  if (!decryptLifetimeEnforcementEnabled(env)) return;
  assertDecryptLifetime(input);
}
