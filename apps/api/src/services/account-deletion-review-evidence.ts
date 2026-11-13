import { buildReviewSnapshot, reviewJcs, validateDependencyObservation, type HostRow, type ResourceDependencyObservation } from './account-deletion-decision';
import type { DeletionHostSnapshot } from './account-deletion-request';
import type { DeletionPreflight } from './account-deletion-preflight';

export type ReviewEvidence = { fresh: DeletionPreflight; observations: ResourceDependencyObservation[]; snapshot: HostRow[] };

/** Validate complete evidence against the frozen hosts and pending target ledger. */
export function validateReviewEvidence(hosts: DeletionHostSnapshot, targets: Record<string, string[]> | undefined, check: ReviewEvidence): void {
  const urls = hosts.configured.map(host => host.url).sort();
  const ids = hosts.configured.map(host => host.hostId);
  const covers = (value: object | undefined) => !!value && reviewJcs(Object.keys(value).sort()) === reviewJcs(urls);
  if (hosts.uncertain || !urls.length || new Set(urls).size !== urls.length || new Set(ids).size !== ids.length || hosts.recorded.some(host => !urls.includes(host)) || !covers(targets) || !covers(check.fresh.resources) || !covers(check.fresh.dependencies) || !covers(check.fresh.inventoryComplete) || check.fresh.unavailableHosts.length || check.observations.length !== urls.length || new Set(check.observations.map(row => row.hostId)).size !== urls.length) throw new Error('Incomplete all-host review evidence');
  let hasDependencies = false;
  for (const host of hosts.configured) {
    const inventory = check.fresh.resources[host.url];
    const required = targets![host.url];
    const summary = check.fresh.dependencies[host.url];
    const observation = check.observations.find(row => row.hostId === host.hostId);
    if (check.fresh.inventoryComplete[host.url] !== true || !Array.isArray(inventory) || inventory.some(item => typeof item !== 'string' || !item) || new Set(inventory).size !== inventory.length || !Array.isArray(required) || required.some(item => !inventory.includes(item)) || !summary || !observation) throw new Error('Missing required review target evidence');
    validateDependencyObservation(observation, inventory);
    if (summary.count !== observation.dependentResourceCount || reviewJcs(summary.hashes) !== reviewJcs(observation.resourceHmacs)) throw new Error('Inconsistent dependency evidence');
    const targetDependencies = observation.targets.some(target => target.dependentCount > 0);
    if ((summary.count > 0) !== targetDependencies) throw new Error('Inconsistent target dependency counts');
    hasDependencies ||= targetDependencies;
  }
  if (check.fresh.state !== (hasDependencies ? 'pending_review' : 'ready') || reviewJcs(buildReviewSnapshot(hosts, check.observations)) !== reviewJcs(check.snapshot)) throw new Error('Inconsistent review snapshot');
}
