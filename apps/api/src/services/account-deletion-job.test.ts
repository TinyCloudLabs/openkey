import { expect, test } from 'bun:test';
import { advanceDeletion, type DeletionJob, type DeletionAdapter } from './account-deletion-job';

test('retirement barrier survives restart and keys remain until every purge completes', async () => {
  let durable: DeletionJob = { state: 'deletion_requested', hosts: {}, unreachableHosts: [] };
  let keysRetained = true;
  let offline = true;
  let purged = false;
  const calls: string[] = [];
  const node: DeletionAdapter = {
    hosts: async () => ['a', 'b'], recordedHosts: async () => ['a'],
    retire: async (host) => { calls.push(`retire:${host}`); if (host === 'b' && offline) throw Error(); },
    list: async host => { calls.push(`list:${host}`); return ['openkey', 'secrets', 'other-app']; },
    purge: async (_host, space, key) => ({ purgeId: key, complete: false }),
    status: async () => purged,
  };
  const store = {
    save: async (job: DeletionJob) => { durable = structuredClone(job); },
    complete: async (job: DeletionJob) => { keysRetained = false; durable = structuredClone(job); },
  };
  await advanceDeletion(structuredClone(durable), node, store);
  expect(calls.some(call => call.startsWith('list:'))).toBe(false);
  expect(durable.unreachableHosts).toEqual(['b']);
  offline = false;
  await advanceDeletion(structuredClone(durable), node, store);
  expect(keysRetained).toBe(true);
  expect(Object.keys(durable.hosts.a!.spaces!)).toHaveLength(3);
  purged = true;
  await advanceDeletion(structuredClone(durable), node, store);
  expect(keysRetained).toBe(false);
  expect(durable.state).toBe('complete');
});

test('an owner-recorded host absent from configuration prevents deletion', async () => {
  const job: DeletionJob = { state: 'deletion_requested', hosts: {}, unreachableHosts: [] };
  const unexpected = async (): Promise<never> => { throw Error('must not run'); };
  await advanceDeletion(job, { hosts: async () => ['a'], recordedHosts: async () => ['b'], retire: unexpected, list: unexpected, purge: unexpected, status: unexpected }, { save: async () => {}, complete: unexpected });
  expect(job.unreachableHosts).toEqual(['b']);
  expect(job.state).toBe('deletion_requested');
});
