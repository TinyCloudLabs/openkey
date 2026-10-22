/**
 * Decrypt lifetime cap for non-device OpenKey transports (TC-1781).
 *
 * A delegation or recap that contains `tinycloud.encryption/decrypt` must be
 * the only entry, must carry only that action, and must have an explicit
 * lifetime of at most one hour measured from signing time. Device flow has its
 * own equivalent rule in `device-authorization.ts` and is not routed through
 * this module.
 *
 * Both flags are read on every call. Only the exact strings `true` and `1`
 * turn a flag on; any other value leaves it off.
 *
 * `DECRYPT_STEPUP_ADMIT` admits a lone raw decrypt on the approver's own
 * `default` network with an explicit lifetime of at most one hour. It only
 * turns a refused request into a successful one.
 * `DECRYPT_LIFETIME_ENFORCE_NON_DEVICE` applies the cap described above.
 */

export const DECRYPT_LIFETIME_FLAG = 'DECRYPT_LIFETIME_ENFORCE_NON_DEVICE';
export const DECRYPT_STEPUP_ADMIT_FLAG = 'DECRYPT_STEPUP_ADMIT';
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

export interface DecryptLifetimeRefusal {
  error: string;
  code: 'invalid_request';
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

export function decryptStepupAdmitEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const value = env[DECRYPT_STEPUP_ADMIT_FLAG];
  return value === 'true' || value === '1';
}

let flagStateLogged = false;

/**
 * Lines describing both flag states, with a warning when enforcement is on
 * without admission: lone own-network decrypt requests are then refused.
 */
export function decryptLifetimeFlagLines(env: NodeJS.ProcessEnv = process.env): string[] {
  const enforce = decryptLifetimeEnforcementEnabled(env);
  const admit = decryptStepupAdmitEnabled(env);
  const lines = [
    `${DECRYPT_STEPUP_ADMIT_FLAG}=${admit ? 'on' : 'off'}`,
    `${DECRYPT_LIFETIME_FLAG}=${enforce ? 'on' : 'off'}`,
  ];
  if (enforce && !admit) {
    lines.push(
      `WARNING: ${DECRYPT_LIFETIME_FLAG}=on without ${DECRYPT_STEPUP_ADMIT_FLAG}=on; lone own-network decrypt requests are refused`,
    );
  }
  return lines;
}

/** Logs the flag lines once per process; states only, never any other value. */
export function logDecryptLifetimeFlagOnce(
  log: (line: string) => void = (line) => console.log(line),
  env: NodeJS.ProcessEnv = process.env,
): void {
  if (flagStateLogged) return;
  flagStateLogged = true;
  for (const line of decryptLifetimeFlagLines(env)) log(line);
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
  const [action] = entry?.actions ?? [];
  if (!entry || entry.actions.length !== 1 || action === undefined || !isDecryptAction(entry, action)) {
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

/**
 * Route-facing form: returns the fixed refusal body when enforcement is on and
 * the request is refused, otherwise null. Routes return it as a 400 before any
 * build, sign, response, activation, or persistence step.
 */
export function decryptLifetimeRefusal(
  input: DecryptLifetimeInput,
  env: NodeJS.ProcessEnv = process.env,
): DecryptLifetimeRefusal | null {
  if (!decryptLifetimeEnforcementEnabled(env)) return null;
  try {
    assertDecryptLifetime(input);
    return null;
  } catch (error) {
    if (error instanceof DecryptLifetimeError) return { error: error.message, code: 'invalid_request' };
    throw error;
  }
}
