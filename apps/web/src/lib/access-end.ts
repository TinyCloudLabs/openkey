/**
 * The end of an access as a date and time of day in UTC, e.g.
 * `Oct 27, 2026, 2:34 PM UTC`. The zone is written out, so the text reads the
 * same wherever it is shown. A value that is not a date is shown as it is.
 */
export function formatAccessEnd(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  const text = new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }).format(date);
  // Newer ICU data puts a narrow no-break space before AM/PM.
  return `${text.replace(/\s/g, ' ')} UTC`;
}

/**
 * The same end in the viewer's own time zone, with its abbreviation, e.g. `Oct 7, 2026, 1:00 AM EDT`. For the
 * consent screens, whose other dates ("expires in 30 days, on Dec 17") are the owner's own day. `timeZone` is for tests.
 */
export function formatLocalAccessEnd(iso: string, timeZone?: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  const text = new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    timeZoneName: 'short',
    timeZone,
  }).format(date);
  return text.replace(/\s/g, ' ');
}
