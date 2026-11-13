import { test, expect } from 'bun:test';
import { pruneCompletedReviewTargets, type DurableResourceCompletion } from './account-deletion-review-completions';
const hosts = { configured: [{ hostId: 'node-test', url: 'https://node.test' }], recorded: ['https://node.test'], uncertain: false };
const targets = { 'https://node.test': ['first', 'second'] };
const complete: DurableResourceCompletion = { jobId: 'job', hostId: 'node-test', resourceId: 'first', purgeId: crypto.randomUUID(), state: 'complete' };
test('only matching durable complete records prune targets; retries are idempotent', () => {
  expect(pruneCompletedReviewTargets('job', hosts, targets, [], []).targets).toEqual(targets);
  const pruned = pruneCompletedReviewTargets('job', hosts, targets, [], [complete]);
  expect(pruned.targets['https://node.test']).toEqual(['second']);
  expect(pruneCompletedReviewTargets('job', hosts, pruned.targets, pruned.records, [complete])).toEqual(pruned);
  expect(() => pruneCompletedReviewTargets('job', hosts, targets, [], [{ ...complete, jobId: 'other' }])).toThrow();
  expect(() => pruneCompletedReviewTargets('job', hosts, targets, [], [{ ...complete, resourceId: 'unknown' }])).toThrow();
  expect(() => pruneCompletedReviewTargets('job', hosts, targets, [], [{ ...complete, state: 'purging' } as unknown as DurableResourceCompletion])).toThrow();
});
