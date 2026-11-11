/**
 * The share invitation a signed approval request names (TC-2234). The API checks it strictly when it loads the
 * request and keeps it with the request; the approval can only issue one new share key for it.
 */
export interface ShareInvitationContext {
  kind: 'share-invitation';
  version: 1;
  invitationId: string;
  recipientEmail: string;
  subjectKind: 'session' | 'file';
  subjectName: string;
  acceptanceExpiresAt: string;
  /** When the recipient's access ends: the acceptance deadline for a session, that or later for a file. */
  accessExpiresAt: string;
}

/** An invitation date as a local date and time with its time zone, e.g. "Nov 12, 2026, 3:04 PM UTC". */
export function invitationDateText(instant: string, locale?: string, timeZone?: string): string {
  return new Intl.DateTimeFormat(locale, {
    year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZoneName: 'short', timeZone,
  }).format(new Date(instant));
}

const HOUR_MS = 60 * 60 * 1000;

/**
 * The time from `nowMs` to `instant` in plain words, rounded down: whole hours from one hour to under 48 hours,
 * whole days from 48 hours on. Under an hour it reads `underAnHour` ("the next hour" after "Accept within",
 * "less than an hour" after "for"), so a deadline is never overstated.
 */
export function invitationDurationText(instant: string, nowMs: number, underAnHour: string): string {
  const remainingMs = Math.max(0, Date.parse(instant) - nowMs);
  if (remainingMs < HOUR_MS) return underAnHour;
  if (remainingMs < 48 * HOUR_MS) {
    const hours = Math.floor(remainingMs / HOUR_MS);
    return hours === 1 ? '1 hour' : `${hours} hours`;
  }
  const days = Math.floor(remainingMs / (24 * HOUR_MS));
  return `${days} days`;
}
