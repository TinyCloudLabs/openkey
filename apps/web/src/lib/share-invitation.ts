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
  accessExpiresAt: string;
}

/** The acceptance deadline as a local date and time with its time zone, e.g. "Nov 12, 2026, 3:04 PM UTC". */
export function acceptByText(acceptanceExpiresAt: string, locale?: string, timeZone?: string): string {
  return new Intl.DateTimeFormat(locale, {
    year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZoneName: 'short', timeZone,
  }).format(new Date(acceptanceExpiresAt));
}
