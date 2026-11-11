// TC-2234: how long an invitation's deadlines are, in the words the approval page shows.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { expect, test } from 'bun:test';
import { invitationDurationText } from './share-invitation';

const now = Date.UTC(2026, 10, 11, 12, 0, 0);
const HOUR = 3600_000;
const at = (ms: number) => new Date(now + ms).toISOString();

test.each([
  ['half an hour', HOUR / 2, '1 hour'],
  ['one hour', HOUR, '1 hour'],
  ['just under a day', 24 * HOUR - 1000, '23 hours'],
  ['one day', 24 * HOUR, '24 hours'],
  ['just under 48 hours', 48 * HOUR - 1000, '47 hours'],
  ['48 hours', 48 * HOUR, '2 days'],
  ['seven days', 7 * 24 * HOUR, '7 days'],
  ['just under 30 days', 30 * 24 * HOUR - 1000, '29 days'],
  ['30 days', 30 * 24 * HOUR, '30 days'],
  ['90 days and 23 hours', (90 * 24 + 23) * HOUR, '90 days'],
] as const)('%s ahead is written rounded down', (_name: string, ms: number, words: string) => {
  expect(invitationDurationText(at(ms), now)).toBe(words);
});
