// TC-2490: all approved spaces must be node-confirmed before aggregate readiness.
// Real owner signatures and HTTP against the loopback node; only Prisma is in memory.
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { privateKeyToAccount } from 'viem/accounts';
import { createFakeBootstrapStore } from './fake-bootstrap-state';
import { startFakeTinyCloudNode, type FakeTinyCloudNode } from './fake-tinycloud-node';
import type { BootstrapSpaceName } from '@tinycloud/bootstrap';
import { hostRequestedSpaceWithinBudget } from '../services/tinycloud-bootstrap-budget';

const service = await import('../services/tinycloud-bootstrap?requested-spaces' as string) as typeof import('../services/tinycloud-bootstrap');
const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const key = { id: 'aggregate-key', address: account.address, keyType: 'MANAGED' };
const spaceId = (name: string) => `tinycloud:pkh:eip155:1:${account.address}:${name}`;
const originalEnv = { host: process.env.TINYCLOUD_BOOTSTRAP_HOST, node: process.env.NODE_ENV, on: process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN };
let node: FakeTinyCloudNode;
let store: ReturnType<typeof createFakeBootstrapStore>;
let reports: Array<{ status: string; errorCode?: string }>;
let skipped: readonly BootstrapSpaceName[] | undefined;

beforeEach(() => {
  node = startFakeTinyCloudNode();
  store = createFakeBootstrapStore();
  reports = [];
  skipped = undefined;
  process.env.NODE_ENV = 'test';
  process.env.TINYCLOUD_BOOTSTRAP_HOST = node.url;
  delete process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN;
  service.setTinyCloudBootstrapProbeForTests(async () => {});
  service.setTinyCloudBootstrapExecutorForTests(async (input) => { skipped = input.skipHostSpaces; });
});
afterEach(() => {
  node.stop();
  service.setTinyCloudBootstrapProbeForTests();
  service.setTinyCloudBootstrapExecutorForTests();
  for (const [name, value] of Object.entries({ TINYCLOUD_BOOTSTRAP_HOST: originalEnv.host, NODE_ENV: originalEnv.node, TINYCLOUD_BOOTSTRAP_ON_SIGN: originalEnv.on })) {
    if (value === undefined) delete process.env[name]; else process.env[name] = value;
  }
});

function run(spaces: readonly BootstrapSpaceName[] = ['default', 'public'], alreadyHosted = false) {
  return service.ensureTinyCloudBootstrap({
    prisma: store.prisma, userId: 'aggregate-user', key, privateKey, host: node.url,
    requestedSpaces: { spaces, alreadyHosted, nodeReportedUnhosted: true, report: (report) => { reports.push(report); } },
  });
}
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((res) => { resolve = res; });
  return { promise, resolve };
}

describe('TC-2490 aggregate requested-space bootstrap', () => {
  test('waits for the last requested space before reporting once and continuing bootstrap', async () => {
    const entered = deferred();
    const release = deferred();
    node.beforeHost = async (id) => {
      if (id === spaceId('public')) { entered.resolve(); await release.promise; }
    };
    const work = run();
    try {
      await Promise.race([entered.promise, work]);
      expect(node.hosted.has(spaceId('default'))).toBe(true);
      expect(reports).toEqual([]);
      expect(skipped).toBeUndefined();
    } finally { release.resolve(); }
    expect(await work).toEqual({ status: 'complete' });
    expect(reports).toEqual([{ status: 'hosted' }]);
    expect(node.hosted.has(spaceId('public'))).toBe(true);
    expect(skipped).toEqual(['default', 'public']);
  });

  test('reports failure when a later requested space is not node-confirmed', async () => {
    node.beforeHost = async (id) => { if (id === spaceId('public')) node.hostActivates = false; };
    expect(await run()).toMatchObject({ status: 'failed', errorCode: 'tinycloud_bootstrap_space_not_hosted' });
    expect(reports).toEqual([expect.objectContaining({ status: 'failed', errorCode: 'tinycloud_bootstrap_space_not_hosted' })]);
    expect(skipped).toBeUndefined();
    expect(store.rows[0]?.status).toBe('failed');
  });

  test('already-hosted retries skip every requested host signature', async () => {
    expect(await run(['default', 'public'], true)).toEqual({ status: 'complete' });
    expect(node.hostPosts).toEqual([]);
    expect(node.peerGets).toEqual([]);
    expect(reports).toEqual([]);
    expect(skipped).toEqual(['default', 'public']);
  });

  test('a fresh node-unhosted result reclaims a cached complete row for every requested space', async () => {
    store.addRow({ userId: 'aggregate-user', keyId: key.id, address: key.address, chainId: 1, tinycloudHost: node.url,
      bootstrapVersion: service.TINYCLOUD_BOOTSTRAP_VERSION, status: 'complete', checkedAt: new Date() });
    expect(await run()).toEqual({ status: 'complete' });
    expect(node.hostPosts.map((post) => post.spaceId)).toEqual([spaceId('default'), spaceId('public')]);
    expect(reports).toEqual([{ status: 'hosted' }]);
  });

  test('aggregate budget reports readiness while seeding continues, then retries without rehosting', async () => {
    const failSeed = deferred();
    const retried = deferred();
    let executions = 0;
    let background!: Promise<unknown>;
    const attempts: boolean[] = [];
    service.setTinyCloudBootstrapExecutorForTests(async (input) => {
      expect(input.skipHostSpaces).toEqual(['default', 'public']);
      if (++executions === 1) { await failSeed.promise; throw new Error('seed failed'); }
      retried.resolve();
    });
    const result = await hostRequestedSpaceWithinBudget(({ alreadyHosted, report }) => {
      attempts.push(alreadyHosted);
      const work = service.ensureTinyCloudBootstrap({
        prisma: store.prisma, userId: 'aggregate-user', key, privateKey, host: node.url,
        requestedSpaces: { spaces: ['default', 'public'], alreadyHosted, nodeReportedUnhosted: true, report },
      });
      background = work;
      return work;
    }, { timeoutMs: 1000, retryDelaysMs: [0] });
    try {
      expect(result).toEqual({ status: 'hosted' });
      expect(store.rows[0]?.status).toBe('in_progress');
      expect(node.hostPosts).toHaveLength(2);
    } finally { failSeed.resolve(); }
    await retried.promise;
    await background;
    expect(attempts).toEqual([false, true]);
    expect(node.hostPosts).toHaveLength(2);
    expect(store.rows[0]?.status).toBe('complete');
  });

  test('full bootstrap continues after aggregate readiness without hosting requested spaces again', async () => {
    service.setTinyCloudBootstrapProbeForTests();
    service.setTinyCloudBootstrapExecutorForTests();
    expect(await run()).toEqual({ status: 'complete' });
    expect(reports).toEqual([{ status: 'hosted' }]);
    for (const name of ['default', 'public', 'applications', 'account', 'secrets', 'agents']) {
      expect(node.hostPosts.filter((post) => post.spaceId === spaceId(name))).toHaveLength(1);
    }
    expect(node.invokes).toBeGreaterThan(0);
    expect(store.rows[0]?.status).toBe('complete');
  });
});
