import type { DeletionHostSnapshot } from './account-deletion-request';

// Internal adapter contract only: no resource HTTP wire is implied here.
export interface DeletionPreflightAdapter {
  // Resolves only after complete, host/owner-bound pagination.
  inventory(host: string): Promise<string[]>;
  dependencies(host: string): Promise<{ count: number; hashes: string[] }>;
}
export type DeletionPreflight = {
  state: 'ready' | 'pending' | 'pending_review';
  resources: Record<string, string[]>;
  dependencies: Record<string, { count: number; hashes: string[] }>;
  unavailableHosts: string[];
};

/** Run before irreversible commit, and again before network-key destruction. */
export async function assessDeletionPreflight(snapshot: DeletionHostSnapshot, adapter: DeletionPreflightAdapter): Promise<DeletionPreflight> {
  const result: DeletionPreflight = { state: 'pending', resources: {}, dependencies: {}, unavailableHosts: [] };
  const hosts = snapshot.configured.map(host => host.url);
  result.unavailableHosts = snapshot.recorded.filter(host => !hosts.includes(host));
  if (snapshot.uncertain || !hosts.length || result.unavailableHosts.length) return result;
  for (const host of hosts) {
    try {
      const resources = await adapter.inventory(host);
      if (!Array.isArray(resources) || resources.some(resource => typeof resource !== 'string' || !resource)) throw new Error('Invalid resource inventory');
      result.resources[host] = [...new Set(resources)];
      const summary = await adapter.dependencies(host);
      if (!Number.isSafeInteger(summary.count) || summary.count < 0 || !Array.isArray(summary.hashes) || summary.hashes.some(hash => typeof hash !== 'string' || !/^[0-9a-f]{64}$/i.test(hash))) throw new Error('Invalid dependency summary');
      result.dependencies[host] = summary;
    } catch { result.unavailableHosts.push(host); }
  }
  // A known dependency requires review even if another host is unavailable;
  // that host must still pass a fresh check before proceeding.
  result.state = Object.values(result.dependencies).some(summary => summary.count > 0)
    ? 'pending_review' : result.unavailableHosts.length ? 'pending' : 'ready';
  return result;
}

export type DeletionReviewDecision = {
  actor: string;
  at: Date;
  reason: string;
  disposition: 'proceed' | 'wait_for_re-encryption';
};

export function mayProceedAfterReview(decision: DeletionReviewDecision | undefined, fresh: DeletionPreflight): boolean {
  return !!decision && !!decision.actor.trim() && !!decision.reason.trim() && Number.isFinite(decision.at.getTime()) && ['proceed', 'wait_for_re-encryption'].includes(decision.disposition) && fresh.state === 'ready';
}
