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
