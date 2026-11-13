import { test, expect } from 'bun:test';
import { reviewResolution, REVIEW_DEADLINE_MS } from './account-deletion-review-policy';
import type { DeletionPreflight } from './account-deletion-preflight';
const requested = new Date('2026-11-01T00:00:00Z');
const held: DeletionPreflight = { state: 'pending_review', resources: {}, dependencies: { host: { count: 1, hashes: ['a'.repeat(64)] } }, unavailableHosts: [] };

test('wait never resets the original seven-day deadline', () => {
  const wait = { actor: 'Naomi', at: new Date(requested.getTime() + 6 * 86_400_000), reason: 'Waiting', disposition: 'wait_for_re-encryption' as const };
  expect(reviewResolution(requested, new Date(requested.getTime() + REVIEW_DEADLINE_MS - 1), held, wait)).toBe('pending');
  expect(reviewResolution(requested, new Date(requested.getTime() + REVIEW_DEADLINE_MS), held, wait)).toBe('deadline');
  expect(reviewResolution(requested, new Date(requested.getTime() + REVIEW_DEADLINE_MS), { ...held, state: 'pending', unavailableHosts: ['host'] }, wait)).toBe('pending');
});

test('fresh zero needs no new decision; expired operator authority cannot cut dependencies', () => {
  const now = new Date(requested.getTime() + 86_400_000);
  expect(reviewResolution(requested, now, { ...held, state: 'ready', dependencies: { host: { count: 0, hashes: [] } } })).toBe('zero');
  expect(reviewResolution(requested, now, held, { actor: 'Naomi', at: now, reason: 'Reviewed', disposition: 'proceed' })).toBe('operator');
  expect(reviewResolution(requested, now, held, { actor: 'Naomi', at: new Date(now.getTime() - 172800_000), reason: 'Reviewed', disposition: 'proceed' })).toBe('pending');
});
