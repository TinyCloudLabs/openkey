import type { DeletionHostSnapshot } from './account-deletion-request';

// Runtime obtains these only from authenticated node status/protected purge
// records, never from a missing inventory entry or an accepted-only response.
export type DurableResourceCompletion = { jobId: string; hostId: string; resourceId: string; purgeId: string; state: 'complete' };
export function pruneCompletedReviewTargets(jobId: string, hosts: DeletionHostSnapshot, targets: Record<string, string[]>, recorded: DurableResourceCompletion[], incoming: DurableResourceCompletion[]) {
  const records = new Map<string, DurableResourceCompletion>();
  const key = (record: DurableResourceCompletion) => JSON.stringify([record.hostId, record.resourceId]);
  for (const record of recorded) records.set(key(record), record);
  for (const record of incoming) {
    const host = hosts.configured.find(entry => entry.hostId === record.hostId);
    const existing = records.get(key(record));
    if (record.jobId !== jobId || record.state !== 'complete' || !host || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(record.purgeId) || (!targets[host.url]?.includes(record.resourceId) && !existing) || (existing && existing.purgeId !== record.purgeId)) throw new Error('Invalid durable resource completion');
    records.set(key(record), record);
  }
  const remaining = Object.fromEntries(Object.entries(targets).map(([url, values]) => {
    const host = hosts.configured.find(entry => entry.url === url);
    if (!host) throw new Error('Unregistered review target host');
    return [url, values.filter(resourceId => !records.has(JSON.stringify([host.hostId, resourceId])))];
  }));
  return { targets: remaining, records: [...records.values()] };
}
