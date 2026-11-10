// TC-2272: the user may change when an approval expires. The new time replaces
// the `Expiration Time:` line of the SIWE the server is about to preview or
// sign; no other byte changes. The app's own time is only the default.

export type ExpirationOverride = { ok: true; value: string } | { ok: false; reason?: 'invalid' | 'too_long' };

/** The shortest approval the server previews: the one-minute floor the clients enforce, less 10 s for clock skew and network delay. */
export const MIN_EXPIRATION_LEAD_MS = 50_000;

/** Maximum lifetime for any TinyCloud delegation SIWE signed or approved by OpenKey. */
export const MAX_DELEGATION_CEILING_YEARS = 10;

/** Calendar-year ceiling, preserving UTC month/day/time across leap years. */
export function delegationCeilingMs(now: number = Date.now()): number {
  const ceiling = new Date(now);
  ceiling.setUTCFullYear(ceiling.getUTCFullYear() + MAX_DELEGATION_CEILING_YEARS);
  return ceiling.getTime();
}

export type DelegationCeilingResult = 'ok' | 'too_long' | 'missing';

/** TinyCloud delegations are SIWEs containing at least one ReCap resource. */
export function assertWithinDelegationCeiling(siwe: string, now: number = Date.now()): DelegationCeilingResult {
  if (!/^[^\r\n]+ wants you to sign in with your Ethereum account:\r?\n/.test(siwe) ||
      !/^Resources:\r?\n(?:[^\r\n]*\r?\n)*- urn:recap:/m.test(siwe)) return 'ok';
  const line = siwe.match(/^Expiration Time: (.+)$/m)?.[1]?.trim();
  if (!line) return 'missing';
  const time = Date.parse(line);
  return Number.isFinite(time) && time <= delegationCeilingMs(now) ? 'ok' : 'too_long';
}

/** The last second a SIWE timestamp (four-digit year) can name. */
export const LATEST_SIWE_TIME_MS = Date.UTC(9999, 11, 31, 23, 59, 59);

/**
 * A chosen expiry must be an exact ISO-8601 UTC time, satisfy its lower
 * bounds, and not exceed the ten-calendar-year ceiling evaluated at now.
 */
export function validateExpirationOverride(
  value: unknown,
  siwe: { issuedAt: string; notBefore?: string },
  minLeadMs: number,
  now: number = Date.now(),
): ExpirationOverride {
  if (typeof value !== 'string') return { ok: false, reason: 'invalid' };
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) return { ok: false, reason: 'invalid' };
  if (time > delegationCeilingMs(now)) return { ok: false, reason: 'too_long' };
  if (time <= now + minLeadMs) return { ok: false, reason: 'invalid' };
  for (const bound of [siwe.issuedAt, siwe.notBefore]) {
    const boundTime = bound ? Date.parse(bound) : Number.NaN;
    if (Number.isFinite(boundTime) && time <= boundTime) return { ok: false, reason: 'invalid' };
  }
  return { ok: true, value };
}

const EXPIRATION_LINE = /^Expiration Time: .+$/gm;

/** The SIWE with its one `Expiration Time:` line replaced; null when it does not have exactly one. */
export function withExpirationTime(siwe: string, expirationTime: string): string | null {
  if ((siwe.match(EXPIRATION_LINE) ?? []).length !== 1) return null;
  return siwe.replace(/^Expiration Time: .+$/m, `Expiration Time: ${expirationTime}`);
}

export function expirationTimeOf(siwe: string): string | undefined {
  return siwe.match(/^Expiration Time: (.+)$/m)?.[1]?.trim();
}
