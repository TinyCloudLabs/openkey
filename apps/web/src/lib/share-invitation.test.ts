// TC-2234: how long an invitation's deadlines are, in the words the approval page shows.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { expect, test } from 'bun:test';
import { invitationDurationText } from './share-invitation';

const now = Date.UTC(2026, 10, 11, 12, 0, 0);
const HOUR = 3600_000;
const at = (ms: number) => new Date(now + ms).toISOString();

test.each([
  ['one hour', HOUR, '1 hour'],
  ['an hour and 59 minutes', 2 * HOUR - 60_000, '1 hour'],
  ['just under a day', 24 * HOUR - 1000, '23 hours'],
  ['one day', 24 * HOUR, '24 hours'],
  ['just under 48 hours', 48 * HOUR - 1000, '47 hours'],
  ['48 hours', 48 * HOUR, '2 days'],
  ['seven days', 7 * 24 * HOUR, '7 days'],
  ['just under 30 days', 30 * 24 * HOUR - 1000, '29 days'],
  ['30 days', 30 * 24 * HOUR, '30 days'],
  ['90 days and 23 hours', (90 * 24 + 23) * HOUR, '90 days'],
] as const)('%s ahead is written rounded down', (_name: string, ms: number, words: string) => {
  expect(invitationDurationText(at(ms), now, 'unused')).toBe(words);
});

test('thirty minutes ahead reads as the words each line gives for under an hour, never "1 hour"', () => {
  expect(`Accept within ${invitationDurationText(at(HOUR / 2), now, 'the next hour')}`).toBe('Accept within the next hour');
  expect(`can open it for ${invitationDurationText(at(HOUR / 2), now, 'less than an hour')}`).toBe('can open it for less than an hour');
  expect(invitationDurationText(at(HOUR - 1000), now, 'less than an hour')).toBe('less than an hour');
});
