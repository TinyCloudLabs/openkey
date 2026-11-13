// The expiry and renewal line on the approval screen (TC-2272, TC-2933):
// parsing and showing a duration, turning the chosen one into the instant the
// server writes into the signed message, and the renewal lease choices.

const S = 1000;
const M = 60 * S;
const H = 60 * M;
const D = 24 * H;

const UNIT_MS: Record<string, number> = { s: S, m: M, h: H, d: D, w: 7 * D, y: 365 * D };

/** The shortest approval the server will sign (matches the server's one-minute floor). */
export const MIN_EXPIRY_MS = M;

/** The last second a SIWE timestamp (four-digit year) can name. */
const LATEST_EXPIRY_MS = Date.UTC(9999, 11, 31, 23, 59, 59);

export const EXPIRY_PRESETS: ReadonlyArray<{ label: string; ms: number }> = [
  { label: '1 hour', ms: H },
  { label: '24 hours', ms: 24 * H },
  { label: '7 days', ms: 7 * D },
  { label: '30 days', ms: 30 * D },
];

/** Renewal lease lengths (spec D4): 90 days by default, 6 months or 1 year, never more than a year. */
export const LEASE_PRESETS: ReadonlyArray<{ label: string; ms: number }> = [
  { label: '90 days', ms: 90 * D },
  { label: '6 months', ms: 182 * D },
  { label: '1 year', ms: 365 * D },
];
export const DEFAULT_LEASE_MS = 90 * D;
export const MAX_LEASE_MS = 365 * D;

/** Spec D6 rule 3: renewing access to secrets or decrypt uses a 7-day window. */
export const SENSITIVE_RENEWAL_WINDOW_MS = 7 * D;

/** The lease shown when the box is first ticked: the default, or less when the requester asked for less. */
export function defaultLeaseMs(maxLeaseMs: number): number {
  return Math.min(DEFAULT_LEASE_MS, maxLeaseMs);
}

/** Longer than this shows the warning. There is no upper limit. */
export const LONG_EXPIRY_MS = 365 * D;
export const LONG_EXPIRY_WARNING = "That's a long time. OpenKey can't cancel it early once you approve.";

export type ParsedExpiry = { ok: true; ms: number } | { ok: false; message: string };

/**
 * Read a duration such as `5600s`, `90m`, `40d` or `1y`: a whole number and one
 * unit (s, m, h, d, w, y), in either case. A year is 365 days. `now` only
 * bounds the result to a date a SIWE message can hold.
 */
export function parseExpiry(text: string, now: number = Date.now()): ParsedExpiry {
  const value = text.trim();
  if (/^-\s*\d/.test(value)) return { ok: false, message: 'Enter a time longer than zero.' };
  const match = /^([0-9]+)\s*([smhdwy])$/i.exec(value);
  if (!match) return { ok: false, message: 'Use a number and a unit, like 5600s, 90m, 40d or 1y.' };
  const count = Number(match[1]);
  if (count === 0) return { ok: false, message: 'Enter a time longer than zero.' };
  const ms = count * UNIT_MS[match[2]!.toLowerCase()]!;
  if (!Number.isFinite(ms) || now + ms > LATEST_EXPIRY_MS) {
    return { ok: false, message: 'That is too far in the future.' };
  }
  if (ms < MIN_EXPIRY_MS) return { ok: false, message: 'Use at least 1m.' };
  return { ok: true, ms };
}

/** A duration in the short form the line shows: the largest unit that fits it exactly. */
export function formatExpiry(ms: number): string {
  if (ms % (365 * D) === 0) return `${ms / (365 * D)}y`;
  if (ms % D === 0) return `${ms / D}d`;
  if (ms % H === 0) return `${ms / H}h`;
  if (ms % M === 0) return `${ms / M}m`;
  return `${Math.round(ms / S)}s`;
}

function count(value: number, unit: string): string {
  return `${value} ${unit}${value === 1 ? '' : 's'}`;
}

/** A duration in words, as the line reads it: "30 days", "6 months", "1 year", "90 minutes". */
export function formatDuration(ms: number): string {
  const preset = LEASE_PRESETS.find((item) => item.ms === ms);
  if (preset) return preset.label;
  if (ms % (365 * D) === 0) return count(ms / (365 * D), 'year');
  if (ms % D === 0) return count(ms / D, 'day');
  if (ms % H === 0) return count(ms / H, 'hour');
  if (ms % M === 0) return count(ms / M, 'minute');
  return count(Math.round(ms / S), 'second');
}

/**
 * How long the app asked the approval to last: its Expiration Time minus its
 * Issued At, to the second. A few seconds either way snap to the whole day, hour or
 * minute, so a "7 day" request shows as 7d. Null when it cannot be worked out.
 */
export function requestedExpiryMs(issuedAt: string | undefined, expirationTime: string | undefined): number | null {
  const start = Date.parse(issuedAt ?? '');
  const end = Date.parse(expirationTime ?? '');
  if (!Number.isFinite(start) || !Number.isFinite(end)) return null;
  const span = Math.round((end - start) / S) * S;
  if (span <= 0) return null;
  for (const unit of [D, H, M]) {
    const whole = Math.round(span / unit) * unit;
    if (whole > 0 && Math.abs(span - whole) <= 5 * S) return whole;
  }
  return span;
}

/** The ISO time `ms` from `now`: what the signed message's Expiration Time becomes. */
export function expiryAt(ms: number, now: number = Date.now()): string {
  return new Date(now + ms).toISOString();
}

/** The `Expiration Time:` of a SIWE message, or null. */
export function siweExpiration(message: string): string | null {
  return /^Expiration Time: (.+)$/m.exec(message)?.[1]?.trim() ?? null;
}

/** Shown where the requester signed the longest time it accepts (signed CLI and device requests). */
export function expiryLimitNote(maxMs: number): string {
  return `This app asked for up to ${formatDuration(maxMs)}. To allow longer, start the request again with a longer expiry.`;
}

/** Shown when a typed renewal time is longer than the requester or the one-year limit allows. */
export function leaseLimitNote(maxMs: number): string {
  return `Renewal can last up to ${formatDuration(maxMs)}.`;
}

/** Like `expiryAt`, but never later than `ceiling` (the time a requester asked for), when that is a valid time. */
export function expiryAtCapped(ms: number, ceiling: string | null, now: number = Date.now()): string {
  const cap = ceiling === null ? Number.NaN : Date.parse(ceiling);
  return new Date(Number.isFinite(cap) ? Math.min(now + ms, cap) : now + ms).toISOString();
}
