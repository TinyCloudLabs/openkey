// The authority a bootstrap row stores, and what the background retry reads from it.
// The row has no authority before this column: such a row is not first-party and is never retried.

import { afterEach, beforeEach, describe, expect, mock, test } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import { privateKeyToAccount } from 'viem/accounts';
import { createFakeBootstrapStore, type FakeBootstrapStore } from './fake-bootstrap-state';
import {
  STORED_PROVISION_AUTHORITIES,
  UNATTRIBUTED_PROVISION_AUTHORITY,
  nativeClientProvisionAuthority,
  oauthClientProvisionAuthority,
  originProvisionAuthority,
  ownPageProvisionAuthority,
  retryableStoredAuthorities,
  storedProvisionAuthority,
  type ProvisionAuthority,
} from '../services/provision-authority';
import {
  TINYCLOUD_BOOTSTRAP_VERSION,
  ensureTinyCloudBootstrap,
  setTinyCloudBootstrapExecutorForTests,
  setTinyCloudBootstrapProbeForTests,
  trustedTinyCloudBootstrapHost,
} from '../services/tinycloud-bootstrap';
import { sweepTinyCloudBootstrapOnce } from '../services/tinycloud-bootstrap-sweep';

const PRIVATE_KEY: `0x${string}` = `0x${'11'.repeat(32)}`;
const ADDRESS = privateKeyToAccount(PRIVATE_KEY).address;
const HOST = trustedTinyCloudBootstrapHost();
const NOW = new Date('2026-10-21T12:00:00.000Z');
const TWO_HOURS = 2 * 60 * 60_000;
const FIRST_PARTY = 'https://home.tinycloud.xyz';

const executor = mock(async () => undefined);
const probe = mock(async () => undefined);
let store: FakeBootstrapStore;
let savedSweep: string | undefined;

beforeEach(() => {
  savedSweep = process.env.TINYCLOUD_BOOTSTRAP_SWEEP;
  delete process.env.TINYCLOUD_BOOTSTRAP_SWEEP;
  executor.mockClear();
  probe.mockClear();
  setTinyCloudBootstrapExecutorForTests(executor);
  setTinyCloudBootstrapProbeForTests(probe);
  store = createFakeBootstrapStore({ users: [], keys: [] });
});

afterEach(() => {
  setTinyCloudBootstrapExecutorForTests();
  setTinyCloudBootstrapProbeForTests();
  if (savedSweep === undefined) delete process.env.TINYCLOUD_BOOTSTRAP_SWEEP; else process.env.TINYCLOUD_BOOTSTRAP_SWEEP = savedSweep;
});

function seedKey(n: number): void {
  store.users.set(`user-${n}`, { id: `user-${n}`, autoSignEnabled: true });
  store.keys.set(`key-${n}`, { id: `key-${n}`, userId: `user-${n}`, address: ADDRESS, keyType: 'MANAGED', archivedAt: null, sealedBlob: `sealed-${n}`, sealingContext: null });
}

function seedFailedRow(n: number, authority?: string | null) {
  seedKey(n);
  return store.addRow({
    userId: `user-${n}`,
    keyId: `key-${n}`,
    address: ADDRESS,
    chainId: 1,
    tinycloudHost: HOST,
    bootstrapVersion: TINYCLOUD_BOOTSTRAP_VERSION,
    status: 'failed',
    checkedAt: new Date(NOW.getTime() - TWO_HOURS),
    failureCode: 'tinycloud_bootstrap_node_timeout',
    failureReason: 'node timed out',
    ...(authority === undefined ? {} : { authority }),
  });
}

function approve(n: number, authority: ProvisionAuthority) {
  seedKey(n);
  return ensureTinyCloudBootstrap({
    prisma: store.prisma,
    authority,
    userId: `user-${n}`,
    key: { id: `key-${n}`, address: ADDRESS, keyType: 'MANAGED' },
    privateKey: PRIVATE_KEY,
    host: HOST,
    chainId: 1,
  });
}

const sweep = () => sweepTinyCloudBootstrapOnce({ prisma: store.prisma, now: NOW, resolveKey: async () => PRIVATE_KEY });

describe('the stored authority set', () => {
  test('the SQL check constraint lists exactly the values the code can write', () => {
    // The newest migration that sets the CHECK: each widening replaces the constraint in a migration of its own.
    const migrations = new URL('../../../../packages/db/prisma/migrations/', import.meta.url);
    const sql = readdirSync(migrations).sort().reverse()
      .map((name) => { try { return readFileSync(new URL(`${name}/migration.sql`, migrations), 'utf8'); } catch { return ''; } })
      .find((text) => text.includes('ADD CONSTRAINT "tinycloud_bootstrap_state_authority_check"')) ?? '';
    const list = /"authority" IN \(([^)]*)\)/.exec(sql)?.[1] ?? '';
    const inSql = [...list.matchAll(/'([^']+)'/g)].map((match) => match[1]);
    expect(inSql.sort()).toEqual([...STORED_PROVISION_AUTHORITIES].sort());
  });

  test('every first-party authority stores a value inside the set, and no other authority stores one', () => {
    const stored = [
      originProvisionAuthority(FIRST_PARTY),
      originProvisionAuthority('https://tinycloud.chat'),
      nativeClientProvisionAuthority('ok_e1d13d0b220379f37a553aa0391d28a4', 'xyz.tinycloud.exo://openkey/callback'),
      ownPageProvisionAuthority('approval-request'),
      ownPageProvisionAuthority('device-approval'),
      ownPageProvisionAuthority('delegate-link-local'),
    ].map(storedProvisionAuthority);
    expect(stored.every((value) => value !== null && (STORED_PROVISION_AUTHORITIES as readonly string[]).includes(value))).toBe(true);
    expect(stored).toEqual(['first-party-origin', 'first-party-origin', 'first-party-native-client', 'approval-request', 'device-approval', 'delegate-link-local']);
    for (const refused of [
      originProvisionAuthority('https://evil.example'),
      originProvisionAuthority(undefined),
      oauthClientProvisionAuthority('some-client'),
      nativeClientProvisionAuthority('ok_e1d13d0b220379f37a553aa0391d28a4', 'https://evil.example/cb'),
      UNATTRIBUTED_PROVISION_AUTHORITY,
    ]) {
      expect(storedProvisionAuthority(refused)).toBeNull();
    }
  });

  test('the retry reads the first-party values only', () => {
    expect(retryableStoredAuthorities()).toEqual(['first-party-origin', 'first-party-native-client', 'approval-request', 'device-approval', 'delegate-link-local', 'account-setup']);
  });
});

describe('what an approval writes on the row', () => {
  test('a first-party origin approval creates the row with that authority', async () => {
    expect(await approve(1, originProvisionAuthority(FIRST_PARTY))).toEqual({ status: 'complete' });
    expect(store.rows.map((row) => row.authority)).toEqual(['first-party-origin']);
  });

  test('an approval on OpenKey\'s own page stores which one', async () => {
    await approve(1, ownPageProvisionAuthority('approval-request'));
    await approve(2, ownPageProvisionAuthority('device-approval'));
    await approve(3, ownPageProvisionAuthority('delegate-link-local'));
    expect(store.rows.map((row) => row.authority)).toEqual(['approval-request', 'device-approval', 'delegate-link-local']);
  });

  test('a third-party or unattributed approval writes no row', async () => {
    expect(await approve(1, originProvisionAuthority('https://evil.example'))).toEqual({ status: 'skipped' });
    expect(await approve(2, UNATTRIBUTED_PROVISION_AUTHORITY)).toEqual({ status: 'skipped' });
    expect(store.rows).toEqual([]);
    expect(executor).not.toHaveBeenCalled();
  });

  test('a first-party approval that takes over a row with no authority records its own', async () => {
    const row = seedFailedRow(1);
    await approve(1, ownPageProvisionAuthority('approval-request'));
    expect(row.authority).toBe('approval-request');
  });
});

describe('the background retry', () => {
  test('retries rows a first-party approval made', async () => {
    seedFailedRow(1, 'first-party-origin');
    seedFailedRow(2, 'approval-request');
    seedFailedRow(3, 'device-approval');
    seedFailedRow(4, 'delegate-link-local');
    const summary = await sweep();
    expect(summary.claimed).toBe(4);
    expect(executor).toHaveBeenCalledTimes(4);
  });

  test('never retries a row with no stored authority', async () => {
    const legacy = seedFailedRow(1);
    const nulled = seedFailedRow(2, null);
    const summary = await sweep();
    expect(summary.candidates).toBe(0);
    expect(executor).not.toHaveBeenCalled();
    expect([legacy.status, nulled.status, legacy.sweepAttempts, nulled.sweepAttempts]).toEqual(['failed', 'failed', 0, 0]);
  });

  test('never retries a row whose stored authority is not a first-party value', async () => {
    const row = seedFailedRow(1, 'third-party');
    const summary = await sweep();
    expect(summary.candidates).toBe(0);
    expect(executor).not.toHaveBeenCalled();
    expect(row.status).toBe('failed');
  });

  test('a mixed batch retries only the rows with a first-party authority', async () => {
    seedFailedRow(1);
    const first = seedFailedRow(2, 'first-party-origin');
    seedFailedRow(3, 'third-party');
    const summary = await sweep();
    expect(summary.claimed).toBe(1);
    expect(executor).toHaveBeenCalledTimes(1);
    expect(first.status).toBe('complete');
    expect(first.authority).toBe('first-party-origin');
  });
});
