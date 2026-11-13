import { test, expect } from 'bun:test';
import { Wallet } from 'ethers';
import { createDeletionAdapter } from './account-deletion-adapter';
import { advanceDeletion, type DeletionJob } from './account-deletion-job';

test('job reaches complete through signed HTTP adapter after status completes', async () => {
  const wallet = Wallet.createRandom();
  const owner = `did:pkh:eip155:1:${wallet.address}`;
  const space = `tinycloud:${owner.slice(4)}:other-app`;
  const purgeId = crypto.randomUUID();
  const paths: string[] = [];
  const adapter = createDeletionAdapter(wallet.privateKey, [{ hostId: 'node-test', url: 'https://node.example.test' }], ['https://node.example.test'], async (url, options) => {
    const path = new URL(url).pathname;
    paths.push(path);
    expect(new Headers(options.headers).get('Authorization')!.split('.')).toHaveLength(3);
    if (path === '/space/retire-owner') return Response.json({ version: 1, hostId: 'node-test', state: 'retired' }, { status: 202 });
    if (path === '/space/list') return Response.json({ version: 1, hostId: 'node-test', ownerDid: owner, spaces: [space], nextCursor: null, lastPage: true });
    return Response.json({ version: 1, hostId: 'node-test', purge_id: purgeId, state: path.endsWith('/status') ? 'complete' : 'purging', accepted_at: '2026-11-12T00:00:00Z', updated_at: '2026-11-12T00:00:00Z' }, { status: path.endsWith('/status') ? 200 : 202 });
  });
  const job: DeletionJob = { state: 'deletion_requested', hosts: {}, unreachableHosts: [] };
  let complete = false;
  await advanceDeletion(job, adapter, { save: async () => {}, complete: async () => { complete = true; } });
  expect(paths).toEqual(['/space/retire-owner', '/space/list', '/space/purge', '/space/purge/status']);
  expect(complete).toBe(true);
});

test('configured host mapping cannot be narrowed, duplicated or repaired by responses', async () => {
  const wallet = Wallet.createRandom();
  const configured = { hostId: 'node-test', url: 'https://node.example.test' };
  let requests = 0;
  const adapter = createDeletionAdapter(wallet.privateKey, [configured], [configured.url], async () => {
    requests += 1;
    return Response.json({ version: 1, hostId: 'unexpected-node', state: 'retired' }, { status: 202 });
  });
  expect(() => adapter.retire('https://other.example.test', crypto.randomUUID())).toThrow();
  expect(requests).toBe(0);
  expect(() => createDeletionAdapter(wallet.privateKey, [configured, { ...configured, url: 'https://other.example.test' }], [])).toThrow();
  const job: DeletionJob = { state: 'deletion_requested', hosts: {}, unreachableHosts: [] };
  let completed = false;
  await advanceDeletion(job, adapter, { save: async () => {}, complete: async () => { completed = true; } });
  expect(completed).toBe(false);
  expect(job.unreachableHosts).toEqual([configured.url]);
  expect(job.hosts[configured.url]?.retired).toBe(false);
  expect(await adapter.hosts()).toEqual([configured.url]);
});
