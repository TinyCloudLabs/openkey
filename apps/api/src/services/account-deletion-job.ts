import { randomUUID } from 'node:crypto';

export type DeletionHost = { retired: boolean; spaces?: Record<string, { key: string; purgeId?: string; complete: boolean }>; retirementKey: string };
export type DeletionJob = {
  state: 'deletion_requested' | 'complete';
  hosts: Record<string, DeletionHost>;
  unreachableHosts: string[];
};
export interface DeletionAdapter {
  hosts(): Promise<string[]>;
  recordedHosts(): Promise<string[]>;
  retire(host: string, key: string): Promise<void>;
  list(host: string): Promise<string[]>;
  purge(host: string, space: string, key: string): Promise<{ purgeId: string; complete: boolean }>;
  status(host: string, space: string, purgeId: string): Promise<boolean>;
}
export interface DeletionStore {
  save(job: DeletionJob): Promise<void>;
  // Atomically remove retained keys and mark the durable job complete.
  complete(job: DeletionJob): Promise<void>;
}

/** One resumable pass. The caller serializes passes with a database job lock. */
export async function advanceDeletion(job: DeletionJob, node: DeletionAdapter, store: DeletionStore): Promise<void> {
  if (job.state === 'complete') return;
  const configured = await node.hosts();
  const recorded = await node.recordedHosts();
  const missing = recorded.filter(host => !configured.includes(host));
  if (!configured.length || missing.length) {
    job.unreachableHosts = missing;
    await store.save(job);
    return;
  }
  // Never remove previously captured hosts when configuration changes.
  for (const host of configured) job.hosts[host] ??= { retired: false, retirementKey: randomUUID() };
  job.unreachableHosts = [];
  await store.save(job);
  for (const [host, progress] of Object.entries(job.hosts)) {
    if (progress.retired) continue;
    try {
      await node.retire(host, progress.retirementKey);
      progress.retired = true;
    } catch { job.unreachableHosts.push(host); }
    await store.save(job);
  }
  if (Object.values(job.hosts).some(host => !host.retired)) return;
  for (const [host, progress] of Object.entries(job.hosts)) {
    try {
      if (!progress.spaces) {
        progress.spaces = Object.fromEntries((await node.list(host)).map(space => [space, { key: randomUUID(), complete: false }]));
        await store.save(job);
      }
      for (const [space, purge] of Object.entries(progress.spaces)) {
        if (purge.complete) continue;
        if (!purge.purgeId) {
          const result = await node.purge(host, space, purge.key);
          purge.purgeId = result.purgeId;
          purge.complete = result.complete;
          await store.save(job);
        }
        if (!purge.complete) purge.complete = await node.status(host, space, purge.purgeId!);
        await store.save(job);
      }
    } catch { job.unreachableHosts.push(host); await store.save(job); }
  }
  if (job.unreachableHosts.length || Object.values(job.hosts).some(host => !host.spaces || Object.values(host.spaces).some(space => !space.complete))) return;
  await store.complete({ ...job, state: 'complete' });
}
