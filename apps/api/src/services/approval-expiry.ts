// TC-2272: the user may change when an approval expires. The new time replaces
// the `Expiration Time:` line of the SIWE the server is about to preview or
// sign; no other byte changes. The app's own time is only the default.

export type ExpirationOverride = { ok: true; value: string } | { ok: false; reason?: 'invalid' | 'too_long' };

/** The shortest approval the server previews: the one-minute floor the clients enforce, less 10 s for clock skew and network delay. */
export const MIN_EXPIRATION_LEAD_MS = 50_000;

/** Maximum lifetime for any TinyCloud delegation SIWE signed or approved by OpenKey. */
export const MAX_DELEGATION_CEILING_YEARS = 10;

/** Calendar-year ceiling; leap-day starts clamp to the last day of February. */
export function delegationCeilingMs(now: number = Date.now()): number {
  const ceiling = new Date(now);
  const day = ceiling.getUTCDate();
  const targetYear = ceiling.getUTCFullYear() + MAX_DELEGATION_CEILING_YEARS;
  ceiling.setUTCDate(1);
  ceiling.setUTCFullYear(targetYear);
  const lastTargetDay = new Date(Date.UTC(targetYear, ceiling.getUTCMonth() + 1, 0)).getUTCDate();
  ceiling.setUTCDate(Math.min(day, lastTargetDay));
  return ceiling.getTime();
}

export type DelegationCeilingResult = 'ok' | 'too_long' | 'missing' | 'malformed';

const UNSUPPORTED_SIWE_LINE_SEPARATORS = /[\r\u0085\u2028\u2029]/;

interface DelegationSiweLayout {
  issuedAtIndex: number;
  expirationIndex?: number;
  resourcesIndex: number;
}

/** Mirrors the node parser's fixed fields and optional Expiration/Not Before/Request ID order. */
function delegationSiweLayout(siwe: string): DelegationSiweLayout | null {
  const lines = siwe.split('\n');
  if (!lines[0]?.includes(' wants you to sign in with your Ethereum account:')) return null;
  const uriIndex = lines[3] === '' ? 4 : 5;
  if (!lines[uriIndex]?.startsWith('URI: ') ||
      !lines[uriIndex + 1]?.startsWith('Version: ') ||
      !lines[uriIndex + 2]?.startsWith('Chain ID: ') ||
      !lines[uriIndex + 3]?.startsWith('Nonce: ') ||
      !lines[uriIndex + 4]?.startsWith('Issued At: ')) return null;
  const issuedAtIndex = uriIndex + 4;
  let index = issuedAtIndex + 1;
  let expirationIndex: number | undefined;
  if (lines[index]?.startsWith('Expiration Time: ')) expirationIndex = index++;
  if (lines[index]?.startsWith('Not Before: ')) index++;
  if (lines[index]?.startsWith('Request ID: ')) index++;
  if (lines[index] !== 'Resources:' || !lines.slice(index + 1).some((line) => line.startsWith('- urn:recap:'))) return null;
  return { issuedAtIndex, expirationIndex, resourcesIndex: index };
}

/** TinyCloud delegations are SIWEs whose parsed Resources section contains ReCap. */
export function assertWithinDelegationCeiling(siwe: string, now: number = Date.now()): DelegationCeilingResult {
  const layout = delegationSiweLayout(siwe);
  if (!layout) {
    const lines = siwe.split('\n');
    const hasRecapShape = lines[0]?.includes(' wants you to sign in with your Ethereum account:') &&
      lines.some((line) => line.startsWith('Resources:') && lines.slice(lines.indexOf(line) + 1).some((resource) => resource.startsWith('- urn:recap:')));
    return hasRecapShape ? 'malformed' : 'ok';
  }
  const lines = siwe.split('\n');
  const expiryLine = layout.expirationIndex === undefined ? undefined : lines[layout.expirationIndex];
  const expiration = expiryLine?.slice('Expiration Time: '.length).trim();
  if (!expiration) return 'missing';
  const time = Date.parse(expiration);
  if (!Number.isFinite(time)) return 'malformed';
  if (time > delegationCeilingMs(now)) return 'too_long';
  return UNSUPPORTED_SIWE_LINE_SEPARATORS.test(siwe) ? 'malformed' : 'ok';
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

/** Set the positional Expiration Time header; null means the SIWE is malformed or ambiguous. */
export function withExpirationTime(siwe: string, expirationTime: string): string | null {
  if (UNSUPPORTED_SIWE_LINE_SEPARATORS.test(siwe)) return null;
  const layout = delegationSiweLayout(siwe);
  if (!layout) return null;
  const lines = siwe.split('\n');
  if (layout.expirationIndex !== undefined) lines[layout.expirationIndex] = `Expiration Time: ${expirationTime}`;
  else lines.splice(layout.issuedAtIndex + 1, 0, `Expiration Time: ${expirationTime}`);
  return lines.join('\n');
}

/** Return only the positional Expiration Time header, never statement/resource text. */
export function expirationTimeOf(siwe: string): string | undefined {
  if (UNSUPPORTED_SIWE_LINE_SEPARATORS.test(siwe)) return undefined;
  const layout = delegationSiweLayout(siwe);
  if (!layout || layout.expirationIndex === undefined) return undefined;
  return siwe.split('\n')[layout.expirationIndex]!.slice('Expiration Time: '.length).trim();
}

