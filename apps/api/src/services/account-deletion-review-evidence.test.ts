import { test, expect } from 'bun:test';
import { buildReviewSnapshot, type ResourceDependencyObservation } from './account-deletion-decision';
import { validateReviewEvidence, type ReviewEvidence } from './account-deletion-review-evidence';
import { mayProceedAfterReview } from './account-deletion-preflight';
const a = 'https://a.test';
const b = 'https://b.test';
const resource = 'urn:tinycloud:encryption:did:pkh:eip155:1:0x1111111111111111111111111111111111111111:default';
const hosts = { configured: [{ hostId: 'node-a', url: a }, { hostId: 'node-b', url: b }], recorded: [a], uncertain: false };
const ledger = { [a]: [resource], [b]: [] };
function evidence(): ReviewEvidence {
  const observations: ResourceDependencyObservation[] = [
    { hostId: 'node-a', ownerHmac: 'a'.repeat(64), dependentResourceCount: 0, resourceHmacs: [], targets: [{ resourceId: resource, targetResourceHmac: 'b'.repeat(64), dependentCount: 0, dependencyFingerprint: 'c'.repeat(64), fingerprintKeyId: 'fp-1' }] },
    { hostId: 'node-b', ownerHmac: 'd'.repeat(64), dependentResourceCount: 0, resourceHmacs: [], targets: [] },
  ];
  return { fresh: { state: 'ready', resources: { [a]: [resource], [b]: [] }, inventoryComplete: { [a]: true, [b]: true }, dependencies: { [a]: { count: 0, hashes: [] }, [b]: { count: 0, hashes: [] } }, unavailableHosts: [] }, observations, snapshot: buildReviewSnapshot(hosts, observations) };
}

test('zero requires every host, explicit complete inventories and every ledger target count', () => {
  expect(() => validateReviewEvidence(hosts, ledger, evidence())).not.toThrow();
  const empty = evidence();
  empty.fresh.resources = {}; empty.fresh.dependencies = {}; empty.fresh.inventoryComplete = {};
  expect(mayProceedAfterReview(undefined, empty.fresh)).toBe(false);
  expect(() => validateReviewEvidence(hosts, ledger, empty)).toThrow();
  const partial = evidence(); delete partial.fresh.dependencies[b];
  expect(() => validateReviewEvidence(hosts, ledger, partial)).toThrow();
  const incomplete = evidence(); incomplete.fresh.inventoryComplete[a] = false;
  expect(() => validateReviewEvidence(hosts, ledger, incomplete)).toThrow();
  const missing = evidence(); missing.observations[0]!.targets = [];
  expect(() => validateReviewEvidence(hosts, ledger, missing)).toThrow();
  expect(() => validateReviewEvidence(hosts, { ...ledger, [a]: [resource, `${resource}/apps/other/key`] }, evidence())).toThrow();
  expect(() => validateReviewEvidence(hosts, undefined, evidence())).toThrow();
});

test('host IDs alone cannot mask inconsistent fresh summaries or snapshot rows', () => {
  const changed = evidence(); changed.fresh.dependencies[a] = { count: 1, hashes: ['b'.repeat(64)] };
  expect(() => validateReviewEvidence(hosts, ledger, changed)).toThrow();
  const snapshotMismatch = evidence(); snapshotMismatch.snapshot[0]![4][0]![1] = 1;
  expect(() => validateReviewEvidence(hosts, ledger, snapshotMismatch)).toThrow();
  const placeholder = evidence(); placeholder.observations = [];
  expect(() => validateReviewEvidence(hosts, ledger, placeholder)).toThrow();
});
