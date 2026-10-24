/**
 * The end of an access as a readable date and time in the viewer's locale and
 * time zone: day, short month, year and the time of day, e.g. `24 Nov 2026,
 * 14:00`. A value that is not a date is shown as it is.
 */
export function formatAccessEnd(iso: string, locale?: string, timeZone?: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short', timeZone }).format(date);
}
