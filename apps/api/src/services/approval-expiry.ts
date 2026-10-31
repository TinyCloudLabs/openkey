// TC-2272: the user may change when an approval expires. The new time replaces
// the `Expiration Time:` line of the SIWE the server is about to preview or
// sign; no other byte changes. The app's own time is only the default.

export type ExpirationOverride = { ok: true; value: string } | { ok: false };

/**
 * A chosen expiry must be an exact ISO-8601 UTC time (what `toISOString()`
 * writes), after both now and the message's Issued At. There is no upper limit
 * beyond what a four-digit year can hold.
 */
export function validateExpirationOverride(value: unknown, issuedAt: string, now: number = Date.now()): ExpirationOverride {
  if (typeof value !== 'string') return { ok: false };
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) return { ok: false };
  const issued = Date.parse(issuedAt);
  if (time <= now || (Number.isFinite(issued) && time <= issued)) return { ok: false };
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
