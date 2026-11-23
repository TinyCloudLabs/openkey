// The expiry and renewal line on the approval screen (TC-2272, TC-2933):
// parsing and showing a duration, turning the chosen one into the instant the
// server writes into the signed message, and the renewal lease choices.

import { parseSiweFields } from '@openkey/capability-review';

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

/**
 * Where a signed approval request starts: the requester's suggestion up to its signed maximum,
 * otherwise the maximum.
 */
export function approvalRequestStartSeconds(maxSeconds: number, suggestedSeconds?: number): number {
  return typeof suggestedSeconds === 'number' && Number.isFinite(suggestedSeconds) && suggestedSeconds >= 1 && suggestedSeconds <= maxSeconds
    ? suggestedSeconds
    : maxSeconds;
}

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

/**
 * The Expiration Time for a window chosen with a confirmed sensitive renewal (TC-3821): `ms` from the message's own
 * Not Before, else its Issued At, read the way the node reads them (`parseSiweFields`). The node renews each window
 * from that start, and the server refuses a sensitive lease whose window is over 7 days, so counting from now (seconds
 * after the app signed) would land just over. Counts from now when the message does not parse.
 */
export function renewalWindowExpiryAt(ms: number, message: string, now: number = Date.now()): string {
  const parsed = parseSiweFields(message);
  const start = parsed.ok ? Date.parse(parsed.fields.notBefore ?? parsed.fields.issuedAt) : NaN;
  return new Date((Number.isFinite(start) ? Math.min(start, now) : now) + ms).toISOString();
}

/** One-time approvals (the Once tier: access to all secrets or all encrypted data) start at one hour (spec D6). */
export const ONCE_DEFAULT_EXPIRY_MS = H;

/**
 * The window a one-time approval starts at: one hour when the app asked for longer, otherwise null (the app asked
 * for an hour or less, or the request is not one-time, so what it asked for stands).
 */
export function onceDefaultExpiryMs(onceTier: boolean, requestedMs: number | null): number | null {
  return onceTier && requestedMs !== null && requestedMs > ONCE_DEFAULT_EXPIRY_MS ? ONCE_DEFAULT_EXPIRY_MS : null;
}

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

/**
 * The whole days a duration over 48 hours reads as, rounded UP ("30 days" for 29 days 4 hours, never "700 hours"):
 * a consent screen never shows less than what is granted. Null for 48 hours or less, which read in hours, minutes or
 * seconds. Every duration shown to the owner uses this one rule.
 */
export function daysOverTwoDays(ms: number): number | null {
  return ms > 2 * D ? Math.ceil(ms / D) : null;
}

/**
 * The day a window of `ms` starting at `now` ends, month first like every other date on the page: "Dec 17", or
 * "Jan 17, 2027" in another year. It is the owner's own day (the browser's time zone, or `timeZone` when given),
 * because a UTC day can be a day off for them.
 */
export function formatEndDay(ms: number, now: number = Date.now(), timeZone?: string): string {
  const yearOf = (at: number) => new Intl.DateTimeFormat('en-US', { year: 'numeric', timeZone }).format(at);
  const end = now + ms;
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    ...(yearOf(end) === yearOf(now) ? {} : { year: 'numeric' as const }),
    timeZone,
  }).format(end);
}

/** A duration in words, as the line reads it: "30 days", "6 months", "1 year", "90 minutes". */
export function formatDuration(ms: number): string {
  const preset = LEASE_PRESETS.find((item) => item.ms === ms);
  if (preset) return preset.label;
  if (ms % (365 * D) === 0) return count(ms / (365 * D), 'year');
  const days = daysOverTwoDays(ms);
  if (days !== null) return count(days, 'day');
  if (ms % D === 0) return count(ms / D, 'day');
  if (ms % H === 0) return count(ms / H, 'hour');
  if (ms % M === 0) return count(ms / M, 'minute');
  return count(Math.round(ms / S), 'second');
}

/** The window as the access line says it: over two days the day it ends too ("29 days, until Dec 17"); otherwise just the length ("45 minutes"). */
export function formatDurationWithEnd(ms: number, now: number = Date.now(), timeZone?: string): string {
  return daysOverTwoDays(ms) === null ? formatDuration(ms) : `${formatDuration(ms)}, until ${formatEndDay(ms, now, timeZone)}`;
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

/**
 * How long access signed as written lasts from `now`: up to the message's own Expiration Time. A few seconds either
 * way snap to the whole day, hour or minute; otherwise it rounds up to the minute, so the line never shows less than
 * what is granted. Null when there is no end or it has passed.
 */
export function remainingAccessMs(expirationTime: string | null | undefined, now: number = Date.now()): number | null {
  const span = requestedExpiryMs(new Date(now).toISOString(), expirationTime ?? undefined);
  return span === null ? null : Math.ceil(span / M) * M;
}

/**
 * When a window of access starts: the message's Issued At (the signed length is counted from it), else `now`. The end
 * day and end time on the face are `windowStart + length`, which is what the signed Expiration Time will be.
 */
export function windowStartMs(issuedAt: string | null | undefined, now: number = Date.now()): number {
  const start = Date.parse(issuedAt ?? '');
  return Number.isFinite(start) ? start : now;
}

/** The line every approval screen shows for how long the access lasts; `start` is when the window starts (`windowStartMs`). */
export function accessLastsLine(holder: 'app' | 'device', ms: number, start: number = Date.now()): string {
  return `This ${holder}'s access to your data lasts ${formatDurationWithEnd(ms, start)}.`;
}

/** The ISO time `ms` from `now` (or from the window start): what the signed message's Expiration Time becomes. */
export function expiryAt(ms: number, now: number = Date.now()): string {
  return new Date(now + ms).toISOString();
}

/** Shown where the requester signed the longest time it accepts (signed CLI and device requests). */
export function expiryLimitNote(maxMs: number): string {
  return `This app asked for up to ${formatDuration(maxMs)}. To allow longer, the app has to ask again.`;
}

/** Shown when a typed renewal time is longer than the requester or the one-year limit allows. */
export function leaseLimitNote(maxMs: number): string {
  return `Renewal can last up to ${formatDuration(maxMs)}. Choose that or less.`;
}

/** Like `expiryAt`, but never later than `ceiling` (the time a requester asked for), when that is a valid time. */
export function expiryAtCapped(ms: number, ceiling: string | null, now: number = Date.now()): string {
  const cap = ceiling === null ? Number.NaN : Date.parse(ceiling);
  return new Date(Number.isFinite(cap) ? Math.min(now + ms, cap) : now + ms).toISOString();
}
