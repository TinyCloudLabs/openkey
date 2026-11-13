import { test, expect } from 'bun:test';
import { assessDeletionPreflight, mayProceedAfterReview } from './account-deletion-preflight';
const snapshot = { configured: [{ hostId: 'a', url: 'https://a.test' }, { hostId: 'b', url: 'https://b.test' }], recorded: ['https://a.test'], uncertain: false };

test('every host inventory and dependency check must complete before commit', async () => {
  const result = await assessDeletionPreflight(snapshot, { inventory: async () => ['network', 'named-key', 'network'], dependencies: async () => ({ count: 0, hashes: [] }) });
  expect(result.state).toBe('ready');
  expect(Object.keys(result.resources)).toHaveLength(2);
  expect(result.resources['https://a.test']).toEqual(['network', 'named-key']);
  const unavailable = await assessDeletionPreflight(snapshot, { inventory: async host => { if (host === 'https://b.test') throw Error(); return []; }, dependencies: async () => ({ count: 0, hashes: [] }) });
  expect(unavailable.state).toBe('pending');
  expect(unavailable.unavailableHosts).toEqual(['https://b.test']);
});

test('dependencies require a recorded decision and fresh zero all-host checks', async () => {
  let count = 1;
  const adapter = { inventory: async () => [], dependencies: async () => ({ count, hashes: count ? ['a'.repeat(64)] : [] }) };
  const held = await assessDeletionPreflight(snapshot, adapter);
  expect(held.state).toBe('pending_review');
  const decision = { actor: 'Naomi', at: new Date(), reason: 'Review recorded', disposition: 'proceed' as const };
  expect(mayProceedAfterReview(decision, held)).toBe(false);
  count = 0;
  const clear = await assessDeletionPreflight(snapshot, adapter);
  expect(mayProceedAfterReview(undefined, clear)).toBe(false);
  expect(mayProceedAfterReview({ ...decision, disposition: 'wait_for_re-encryption' }, clear)).toBe(true);
  expect(mayProceedAfterReview(decision, clear)).toBe(true);
  // The same check is repeated immediately before key destruction.
  count = 1;
  expect(mayProceedAfterReview(decision, await assessDeletionPreflight(snapshot, adapter))).toBe(false);
});
