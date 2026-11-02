// TC-2272: the user may change when an approval expires. The new time replaces
// the `Expiration Time:` line of the SIWE the server is about to preview or
// sign; no other byte changes. The app's own time is only the default.

export type ExpirationOverride = { ok: true; value: string } | { ok: false };

/** The shortest approval the server previews: the one-minute floor the clients enforce, less 10 s for clock skew and network delay. */
export const MIN_EXPIRATION_LEAD_MS = 50_000;

/** The last second a SIWE timestamp (four-digit year) can name. */
const LATEST_SIWE_TIME_MS = Date.UTC(9999, 11, 31, 23, 59, 59);

/**
 * A chosen expiry must be an exact ISO-8601 UTC time (what `toISOString()`
 * writes), at least `minLeadMs` after now, after the message's Issued At and
 * after its Not Before when it has one. There is no upper limit beyond what a
 * four-digit year can hold. At sign time `minLeadMs` is 0: the preview already
 * met the floor, and the time must only still be in the future.
 */
export function validateExpirationOverride(
  value: unknown,
  siwe: { issuedAt: string; notBefore?: string },
  minLeadMs: number,
  now: number = Date.now(),
): ExpirationOverride {
  if (typeof value !== 'string') return { ok: false };
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) return { ok: false };
  if (time > LATEST_SIWE_TIME_MS || time <= now + minLeadMs) return { ok: false };
  for (const bound of [siwe.issuedAt, siwe.notBefore]) {
    const boundTime = bound ? Date.parse(bound) : Number.NaN;
    if (Number.isFinite(boundTime) && time <= boundTime) return { ok: false };
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
