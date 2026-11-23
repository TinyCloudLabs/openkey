// Only a first-party authority makes the TinyCloud bootstrap touch the node or write its state.
// Real signatures, real WASM and real HTTP against the loopback node; only Prisma is in memory.

import { afterEach, beforeEach, describe, expect, mock, spyOn, test } from 'bun:test';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import { createFakeBootstrapStore, type FakeBootstrapStore } from './fake-bootstrap-state';
import { startFakeTinyCloudNode, type FakeTinyCloudNode } from './fake-tinycloud-node';
import {
  SWEEP_PROVISION_AUTHORITY,
  UNATTRIBUTED_PROVISION_AUTHORITY,
  nativeClientProvisionAuthority,
  oauthClientProvisionAuthority,
  originProvisionAuthority,
  type ProvisionAuthority,
} from '../services/provision-authority';

const service = await import('../services/tinycloud-bootstrap?provision-authority' as string) as typeof import('../services/tinycloud-bootstrap');
const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const key = { id: 'authority-key', address: account.address, keyType: 'MANAGED' };
const userId = 'authority-user';
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const spaceId = (name: string) => `tinycloud:pkh:eip155:1:${account.address}:${name}`;
const FIRST_PARTY = 'https://home.tinycloud.xyz';

const originalEnv = { host: process.env.TINYCLOUD_BOOTSTRAP_HOST, node: process.env.NODE_ENV, on: process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN };
let node: FakeTinyCloudNode;
let store: FakeBootstrapStore;
const executor = mock(async () => undefined);
const probe = mock(async () => undefined);
let fetchSpy: ReturnType<typeof spyOn>;

beforeEach(() => {
  node = startFakeTinyCloudNode();
  store = createFakeBootstrapStore({
    users: [{ id: userId, autoSignEnabled: true }],
    keys: [{ ...key, userId, archivedAt: null, sealedBlob: null, sealingContext: null } as never],
  });
  process.env.NODE_ENV = 'test';
  process.env.TINYCLOUD_BOOTSTRAP_HOST = node.url;
  delete process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN;
  executor.mockClear();
  probe.mockClear();
  service.setTinyCloudBootstrapExecutorForTests(executor);
  service.setTinyCloudBootstrapProbeForTests(probe);
  fetchSpy = spyOn(globalThis, 'fetch');
});

afterEach(() => {
  fetchSpy.mockRestore();
  node.stop();
  service.setTinyCloudBootstrapExecutorForTests();
  service.setTinyCloudBootstrapProbeForTests();
  for (const [name, value] of Object.entries({ TINYCLOUD_BOOTSTRAP_HOST: originalEnv.host, NODE_ENV: originalEnv.node, TINYCLOUD_BOOTSTRAP_ON_SIGN: originalEnv.on })) {
    if (value === undefined) delete process.env[name]; else process.env[name] = value;
  }
});

/** The sign-in the SDK prepares for a space of the signer's own. */
function ownSpaceSiwe(name: string) {
  const space = spaceId(name);
  const now = Date.now();
  return prepareSession({
    address: account.address, chainId: 1, domain: 'example.com',
    issuedAt: new Date(now).toISOString(), expirationTime: new Date(now + 3_600_000).toISOString(),
    spaceId: space, jwk, abilities: { kv: { [space]: ['tinycloud.kv/get'] } } as never,
  } as never).siwe as string;
}

/** The approved sign-in the full account bootstrap is triggered by. */
function bootstrapSiwe() {
  const now = Date.now();
  return prepareSession({
    address: account.address, chainId: 1, domain: 'listen.tinycloud.xyz',
    issuedAt: new Date(now).toISOString(), expirationTime: new Date(now + 3_600_000).toISOString(),
    spaceId: spaceId('account'), jwk, abilities: { capabilities: { capabilities: ['tinycloud.capabilities/read'] } },
  } as never).siwe;
}

const signed = (message: string, authority: ProvisionAuthority) =>
  service.ensureTinyCloudBootstrapForApprovedSign({
    prisma: store.prisma, userId, key, privateKey, message, format: 'personal_sign', authority,
  });

/** Nothing reached the node, nothing was read or written to the bootstrap state, and no node client ran. */
function expectUntouched() {
  expect(node.peerGets).toEqual([]);
  expect(node.hostPosts).toEqual([]);
  expect(node.sessionPosts).toEqual([]);
  expect(node.invokes).toBe(0);
  expect(fetchSpy).not.toHaveBeenCalled();
  expect(executor).not.toHaveBeenCalled();
  expect(probe).not.toHaveBeenCalled();
  expect(store.rows).toEqual([]);
}

const notFirstParty: Array<[string, ProvisionAuthority]> = [
  ['a third-party origin', originProvisionAuthority('https://example.com')],
  ['a missing origin', originProvisionAuthority(undefined)],
  ['a malformed origin', originProvisionAuthority(`${FIRST_PARTY}/`)],
  ['an origin that only contains a first-party one', originProvisionAuthority(`${FIRST_PARTY}.evil.example`)],
  ['an unattributed request', UNATTRIBUTED_PROVISION_AUTHORITY],
  ['an OAuth client that is not listed', oauthClientProvisionAuthority('coordinationos')],
  ['a native client with the wrong redirect', nativeClientProvisionAuthority('ok_e1d13d0b220379f37a553aa0391d28a4', 'xyz.tinycloud.test://openkey/callback')],
];

describe('a signature that is not from a first-party authority sets nothing up', () => {
  for (const [name, authority] of notFirstParty) {
    test(`${name}: an own-space sign-in is skipped and the node is never called`, async () => {
      expect(await signed(ownSpaceSiwe('applications'), authority)).toEqual({ status: 'skipped' });
      expectUntouched();
    });

    test(`${name}: an account bootstrap sign-in is skipped and the node is never called`, async () => {
      expect(await signed(bootstrapSiwe(), authority)).toEqual({ status: 'skipped' });
      expectUntouched();
    });
  }

  test('the same request the kill switch skips has the same outcome', async () => {
    process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN = 'off';
    expect(await signed(ownSpaceSiwe('applications'), originProvisionAuthority(FIRST_PARTY))).toEqual({ status: 'skipped' });
    expect(await signed(ownSpaceSiwe('applications'), originProvisionAuthority('https://example.com'))).toEqual({ status: 'skipped' });
    expectUntouched();
  });

  test('the core bootstrap (link, device and approval flows) refuses an unattributed run before the node or the database', async () => {
    const outcome = await service.ensureTinyCloudBootstrap({
      prisma: store.prisma, userId, key, privateKey, host: node.url, chainId: 1, authority: UNATTRIBUTED_PROVISION_AUTHORITY,
    });
    expect(outcome).toEqual({ status: 'skipped' });
    expectUntouched();
  });

  test('the core bootstrap refuses a requested-space run of a third party', async () => {
    const reports: unknown[] = [];
    const outcome = await service.ensureTinyCloudBootstrap({
      prisma: store.prisma, userId, key, privateKey, host: node.url, authority: originProvisionAuthority('https://example.com'),
      requestedSpaces: { spaces: ['default', 'public'], alreadyHosted: false, nodeReportedUnhosted: true, report: (report) => { reports.push(report); } },
    });
    expect(outcome).toEqual({ status: 'skipped' });
    expect(reports).toEqual([]);
    expectUntouched();
  });
});

describe('a first-party authority keeps setting the account up', () => {
  test('an own-space sign-in hosts the space it names', async () => {
    const outcome = await signed(ownSpaceSiwe('applications'), originProvisionAuthority(FIRST_PARTY));

    expect(outcome.status).not.toBe('skipped');
    expect(node.hosted.has(spaceId('applications'))).toBe(true);
    expect(node.hostPosts.filter((post) => post.spaceId === spaceId('applications'))).toHaveLength(1);
  });

  test('an account bootstrap sign-in runs the bootstrap and records its state', async () => {
    const outcome = await signed(bootstrapSiwe(), originProvisionAuthority(FIRST_PARTY));

    expect(outcome).toEqual({ status: 'complete' });
    expect(executor).toHaveBeenCalledTimes(1);
    expect(store.rows.map((row) => row.status)).toEqual(['complete']);
  });

  test('TinyChat web is first-party', async () => {
    expect(await signed(bootstrapSiwe(), originProvisionAuthority('https://tinycloud.chat'))).toEqual({ status: 'complete' });
    expect(executor).toHaveBeenCalledTimes(1);
  });

  test('the background retry of a row OpenKey already made still runs', async () => {
    const outcome = await service.ensureTinyCloudBootstrap({
      prisma: store.prisma, userId, key, privateKey, host: node.url, chainId: 1, authority: SWEEP_PROVISION_AUTHORITY,
    });
    expect(outcome).toEqual({ status: 'complete' });
    expect(executor).toHaveBeenCalledTimes(1);
  });
});

describe('a client that needs an account that is already set up', () => {
  const accepting = (authority: ProvisionAuthority) =>
    service.ensureTinyCloudBootstrapForApprovedSign({
      prisma: store.prisma, userId, key, privateKey, message: bootstrapSiwe(), format: 'personal_sign', authority, acceptCompleteRow: true,
    });

  test('is answered complete when the account is recorded complete, without a node call', async () => {
    store.addRow({
      keyId: key.id, userId, address: key.address, chainId: 1, tinycloudHost: node.url,
      bootstrapVersion: service.TINYCLOUD_BOOTSTRAP_VERSION, status: 'complete', checkedAt: new Date(), completedAt: new Date(),
    });
    const before = store.rows.map((row) => ({ ...row }));

    expect(await accepting(oauthClientProvisionAuthority('coordinationos'))).toEqual({ status: 'complete' });

    expect(node.peerGets).toEqual([]);
    expect(node.hostPosts).toEqual([]);
    expect(node.sessionPosts).toEqual([]);
    expect(executor).not.toHaveBeenCalled();
    expect(store.rows).toEqual(before);
  });

  test('is skipped, with no node call and no row, when the account is not set up', async () => {
    expect(await accepting(oauthClientProvisionAuthority('coordinationos'))).toEqual({ status: 'skipped' });
    expectUntouched();
  });

  test('is skipped when the recorded setup is not complete', async () => {
    for (const status of ['failed', 'in_progress']) {
      store.rows.length = 0;
      store.addRow({
        keyId: key.id, userId, address: key.address, chainId: 1, tinycloudHost: node.url,
        bootstrapVersion: service.TINYCLOUD_BOOTSTRAP_VERSION, status, checkedAt: new Date(),
      });
      expect(await accepting(oauthClientProvisionAuthority('coordinationos'))).toEqual({ status: 'skipped' });
      expect(store.rows).toHaveLength(1);
      expect(store.rows[0]!.status).toBe(status);
    }
    expect(node.peerGets).toEqual([]);
    expect(node.hostPosts).toEqual([]);
    expect(executor).not.toHaveBeenCalled();
  });

  test('is not given the exemption by a caller that does not ask for it', async () => {
    store.addRow({
      keyId: key.id, userId, address: key.address, chainId: 1, tinycloudHost: node.url,
      bootstrapVersion: service.TINYCLOUD_BOOTSTRAP_VERSION, status: 'complete', checkedAt: new Date(), completedAt: new Date(),
    });
    expect(await signed(bootstrapSiwe(), originProvisionAuthority('https://example.com'))).toEqual({ status: 'skipped' });
  });
});
