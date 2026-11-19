import { expect, test } from 'bun:test';
import { resolveScoreboardExclusions } from '../services/scoreboard-exclusions';

// Replaces the env-parsing coverage of the removed `exclusionsFromEnv` test (TC-1480):
// SCOREBOARD_EXCLUDE_CLIENT_IDS stays the env-driven way to drop an OAuth client (for example the
// smoke client) from the app-user counts; the legacy user-id env is deliberately ignored.
// With no SCOREBOARD_EXCLUSIONS rule the resolver never touches the database.
const noDatabase = {} as Parameters<typeof resolveScoreboardExclusions>[0];

test('SCOREBOARD_EXCLUDE_CLIENT_IDS is split on commas and trimmed; empty items are dropped', async () => {
  const { clientIds } = await resolveScoreboardExclusions(noDatabase, { SCOREBOARD_EXCLUDE_CLIENT_IDS: ' a, b ,,' });
  expect([...clientIds]).toEqual(['a', 'b']);
});

test('unset or empty SCOREBOARD_EXCLUDE_CLIENT_IDS excludes no client', async () => {
  expect((await resolveScoreboardExclusions(noDatabase, {})).clientIds.size).toBe(0);
  expect((await resolveScoreboardExclusions(noDatabase, { SCOREBOARD_EXCLUDE_CLIENT_IDS: '' })).clientIds.size).toBe(0);
});

test('the legacy SCOREBOARD_EXCLUDE_USER_IDS env is ignored by the resolver', async () => {
  const result = await resolveScoreboardExclusions(noDatabase, { SCOREBOARD_EXCLUDE_USER_IDS: 'a,b', SCOREBOARD_EXCLUDE_CLIENT_IDS: 'c' });
  expect(result.userIds.size).toBe(0);
  expect([...result.clientIds]).toEqual(['c']);
});
