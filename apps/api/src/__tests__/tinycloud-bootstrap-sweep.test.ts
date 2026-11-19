import { afterEach, beforeAll, beforeEach, describe, expect, setSystemTime, spyOn, test } from 'bun:test';
import { jest } from 'bun:test';
import { readdir, readFile } from 'node:fs/promises';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { privateKeyToAccount } from 'viem/accounts';
import { createFakeBootstrapStore, type FakeBootstrapRow, type FakeBootstrapStore } from './fake-bootstrap-state';
import { recapOf, startFakeTinyCloudNode, type FakeTinyCloudNode } from './fake-tinycloud-node';
import {
  ensureTinyCloudBootstrap,
  isTinyCloudBootstrapComplete,
  setTinyCloudBootstrapExecutorForTests,
  setTinyCloudBootstrapProbeForTests,
  TINYCLOUD_BOOTSTRAP_VERSION,
  TinyCloudBootstrapError,
  trustedTinyCloudBootstrapHost,
} from '../services/tinycloud-bootstrap';
import { hostRequestedSpaceWithinBudget, SWEEP_RETRYABLE_CODES } from '../services/tinycloud-bootstrap-budget';
import { startTinyCloudBootstrapSweep, sweepTinyCloudBootstrapOnce, type SweepOptions } from '../services/tinycloud-bootstrap-sweep';

const MIN = 60_000;
const DAY = 24 * 60 * MIN;
const T0 = new Date('2026-10-21T12:00:00.000Z');
const HOST = trustedTinyCloudBootstrapHost();
const PRIVATE_KEY: `0x${string}` = `0x${'11'.repeat(32)}`;
const ADDRESS = privateKeyToAccount(PRIVATE_KEY).address;
const ENV_NAMES = ['TINYCLOUD_BOOTSTRAP_HOST', 'TINYCLOUD_BOOTSTRAP_SWEEP', 'TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS', 'NODE_ENV'];

/** A timestamp offset from T0, in milliseconds. */
const at = (ms: number): Date => new Date(T0.getTime() + ms);

type SeedOptions = {
  status?: string;
  failureCode?: string | null;
  checkedAt?: Date;
  sweepAttempts?: number;
  tinycloudHost?: string;
  bootstrapVersion?: string;
  autoSignEnabled?: boolean;
  keyType?: 'MANAGED' | 'EXTERNAL';
  archivedAt?: Date | null;
  sealedBlob?: string | null;
  lockExpiresAt?: Date | null;
  attemptId?: string | null;
};

type LogLine = Record<string, unknown>;

let store: FakeBootstrapStore;
let executions: number;
let savedEnv: Record<string, string | undefined>;
let stdoutChunks: string[];
let restoreStdout: (() => void) | undefined;

function seedKey(n: number, opts: SeedOptions = {}): void {
  const userId = `user-${n}`;
  const keyId = `key-${n}`;
  store.users.set(userId, { id: userId, autoSignEnabled: opts.autoSignEnabled ?? true });
  store.keys.set(keyId, {
    id: keyId,
    userId,
    address: ADDRESS,
    keyType: opts.keyType ?? 'MANAGED',
    archivedAt: opts.archivedAt ?? null,
    sealedBlob: opts.sealedBlob === undefined ? `sealed-${n}` : opts.sealedBlob,
    sealingContext: null,
  });
}

function seedRow(n: number, opts: SeedOptions = {}): FakeBootstrapRow {
  seedKey(n, opts);
  return store.addRow({
    userId: `user-${n}`,
    keyId: `key-${n}`,
    address: ADDRESS,
    chainId: 1,
    tinycloudHost: opts.tinycloudHost ?? HOST,
    bootstrapVersion: opts.bootstrapVersion ?? TINYCLOUD_BOOTSTRAP_VERSION,
    status: opts.status ?? 'failed',
    checkedAt: opts.checkedAt ?? T0,
    failureCode: opts.failureCode !== undefined ? opts.failureCode : 'tinycloud_bootstrap_node_timeout',
    failureReason: 'node timed out',
    sweepAttempts: opts.sweepAttempts ?? 0,
    attemptId: opts.attemptId ?? null,
    lockExpiresAt: opts.lockExpiresAt ?? null,
  });
}

function rowOf(n: number): FakeBootstrapRow {
  const row = store.rows.find((candidate) => candidate.keyId === `key-${n}`);
  if (!row) throw new Error(`no bootstrap row for key-${n}`);
  return row;
}

function sweep(extra: SweepOptions = {}) {
  return sweepTinyCloudBootstrapOnce({ prisma: store.prisma, resolveKey: async () => PRIVATE_KEY, ...extra });
}

function approve(n: number, host = HOST) {
  return ensureTinyCloudBootstrap({
    prisma: store.prisma,
    userId: `user-${n}`,
    key: { id: `key-${n}`, address: ADDRESS, keyType: 'MANAGED' },
    privateKey: PRIVATE_KEY,
    host,
    chainId: 1,
  });
}

function succeed(): void {
  setTinyCloudBootstrapExecutorForTests(async () => {
    executions += 1;
  });
}

function failWith(code: string): void {
  setTinyCloudBootstrapExecutorForTests(async () => {
    executions += 1;
    throw new TinyCloudBootstrapError('node call failed', code);
  });
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function captureStdout(): void {
  stdoutChunks = [];
  const original = process.stdout.write.bind(process.stdout);
  process.stdout.write = ((chunk: unknown) => {
    stdoutChunks.push(String(chunk));
    return true;
  }) as typeof process.stdout.write;
  restoreStdout = () => {
    process.stdout.write = original;
  };
}

function capturedText(): string {
  return stdoutChunks.join('');
}

function logLines(): LogLine[] {
  return capturedText()
    .split('\n')
    .filter((line) => line.trim().startsWith('{'))
    .map((line) => JSON.parse(line) as LogLine);
}

function sweepEvents(name: string): LogLine[] {
  return logLines().filter((line) => line.event === name);
}

async function sweepOnNode(node: FakeTinyCloudNode, n: number, run: () => Promise<unknown>): Promise<unknown> {
  process.env.TINYCLOUD_BOOTSTRAP_HOST = node.url;
  seedRow(n, { tinycloudHost: node.url, checkedAt: at(-60 * MIN) });
  return run();
}

let migratedDump: Blob | undefined;

/** The repo's migration chain applied in directory order; the PGlite tests run against this schema. */
async function buildMigratedTemplate(): Promise<PGlite> {
  const root = new URL('../../../../packages/db/prisma/migrations/', import.meta.url);
  const names = (await readdir(root, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  const template = new PGlite();
  await template.waitReady;
  for (const name of names) {
    await template.exec(await readFile(new URL(`${name}/migration.sql`, root), 'utf8'));
  }
  return template;
}

beforeAll(async () => {
  const template = await buildMigratedTemplate();
  migratedDump = await template.dumpDataDir();
  await template.close();
}, 120_000);

/** A fresh database loaded from the migrated schema dump, with a Prisma client on top; each PGlite test owns one. */
async function pgliteStore(): Promise<{ database: PGlite; prisma: PrismaClient; close: () => Promise<void> }> {
  if (!migratedDump) throw new Error('migrated schema was not built');
  const database = new PGlite({ loadDataDir: migratedDump });
  await database.waitReady;
  const prisma = new PrismaClient({ adapter: new PrismaPGlite(database) });
  return {
    database,
    prisma,
    close: async () => {
      await prisma.$disconnect();
      await database.close();
    },
  };
}

/** A failed, retryable row for key-n, written through Prisma so the schema's own required fields and defaults apply. */
async function seedPgliteRow(prisma: PrismaClient, n: number): Promise<void> {
  await prisma.user.create({ data: { id: `user-${n}`, email: `user-${n}@example.test` } });
  await prisma.ethereumKey.create({
    data: { id: `key-${n}`, userId: `user-${n}`, address: ADDRESS, publicKey: '', sealedBlob: 'sealed' },
  });
  await prisma.tinyCloudBootstrapState.create({
    data: {
      id: `state-${n}`,
      userId: `user-${n}`,
      keyId: `key-${n}`,
      address: ADDRESS,
      chainId: 1,
      tinycloudHost: HOST,
      bootstrapVersion: TINYCLOUD_BOOTSTRAP_VERSION,
      status: 'failed',
      checkedAt: at(-3 * 60 * MIN),
      failureCode: 'tinycloud_bootstrap_node_timeout',
      failureReason: 'node timed out',
      sweepAttempts: 2,
    },
  });
}

function pgliteStateOf(prisma: PrismaClient, n: number) {
  return prisma.tinyCloudBootstrapState.findFirst({ where: { keyId: `key-${n}` } });
}

function approveOn(prisma: PrismaClient, n: number) {
  return ensureTinyCloudBootstrap({
    prisma,
    userId: `user-${n}`,
    key: { id: `key-${n}`, address: ADDRESS, keyType: 'MANAGED' },
    privateKey: PRIVATE_KEY,
    host: HOST,
    chainId: 1,
  });
}

/** Runs `afterFind` after the real candidate `findMany` resolves and before the sweep claims. */
function afterCandidateRead(prisma: PrismaClient, afterFind: () => Promise<void>): PrismaClient {
  return new Proxy(prisma, {
    get(target, property) {
      if (property !== 'tinyCloudBootstrapState') return Reflect.get(target, property, target);
      const delegate = target.tinyCloudBootstrapState;
      return new Proxy(delegate, {
        get(delegateTarget, method) {
          const value = Reflect.get(delegateTarget, method, delegateTarget);
          if (method !== 'findMany' || typeof value !== 'function') {
            return typeof value === 'function' ? value.bind(delegateTarget) : value;
          }
          return async (args: unknown) => {
            const found = await value.call(delegateTarget, args);
            await afterFind();
            return found;
          };
        },
      });
    },
  });
}

beforeEach(() => {
  savedEnv = Object.fromEntries(ENV_NAMES.map((name) => [name, process.env[name]]));
  delete process.env.TINYCLOUD_BOOTSTRAP_HOST;
  delete process.env.TINYCLOUD_BOOTSTRAP_SWEEP;
  process.env.TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS = 'off';
  setSystemTime(T0);
  store = createFakeBootstrapStore();
  executions = 0;
  succeed();
  setTinyCloudBootstrapProbeForTests(async () => {});
});

afterEach(() => {
  restoreStdout?.();
  restoreStdout = undefined;
  setSystemTime();
  setTinyCloudBootstrapExecutorForTests();
  setTinyCloudBootstrapProbeForTests();
  for (const name of ENV_NAMES) {
    const value = savedEnv[name];
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

describe('TinyCloud bootstrap background sweep', () => {
  test('1. an outage longer than the short retries heals on the sweep', async () => {
    const node = startFakeTinyCloudNode();
    try {
      setTinyCloudBootstrapExecutorForTests();
      process.env.TINYCLOUD_BOOTSTRAP_HOST = node.url;
      seedKey(1);
      node.hostStatus = 503;

      await approve(1, node.url);
      expect(rowOf(1).status).toBe('failed');
      expect(SWEEP_RETRYABLE_CODES).toContain(rowOf(1).failureCode as string);

      node.hostStatus = 200;
      setSystemTime(at(5 * MIN));
      const summary = await sweep();

      expect(summary.healed).toBe(1);
      expect(rowOf(1).status).toBe('complete');
      expect(new Set(node.hostPosts.map((post) => post.spaceId)).size).toBe(6);
    } finally {
      node.stop();
    }
  });

  test('2. each retry waits for its own tier before it runs', async () => {
    seedRow(2);
    failWith('tinycloud_bootstrap_failed');

    setSystemTime(at(5 * MIN - 1000));
    expect((await sweep()).candidates).toBe(0);
    expect(executions).toBe(0);

    setSystemTime(at(5 * MIN));
    await sweep();
    expect(executions).toBe(1);
    expect(rowOf(2).sweepAttempts).toBe(1);

    setSystemTime(at(35 * MIN - 1000));
    await sweep();
    expect(executions).toBe(1);

    setSystemTime(at(35 * MIN));
    await sweep();
    expect(executions).toBe(2);
    expect(rowOf(2).sweepAttempts).toBe(2);

    setSystemTime(at(155 * MIN - 1000));
    await sweep();
    expect(executions).toBe(2);

    setSystemTime(at(155 * MIN));
    await sweep();
    expect(executions).toBe(3);
    expect(rowOf(2).sweepAttempts).toBe(3);
  });

  test('3. the attempt cap stops the sweep after four runs', async () => {
    seedRow(3);
    failWith('tinycloud_bootstrap_failed');
    captureStdout();

    for (const offset of [5 * MIN, 35 * MIN, 155 * MIN, 515 * MIN]) {
      setSystemTime(at(offset));
      await sweep();
    }
    expect(executions).toBe(4);
    expect(rowOf(3).sweepAttempts).toBe(4);
    expect(sweepEvents('tinycloud_bootstrap_sweep_exhausted')).toHaveLength(1);
    expect(sweepEvents('tinycloud_bootstrap_sweep_still_failed')).toHaveLength(3);

    setSystemTime(at(365 * DAY));
    await sweep();
    expect(executions).toBe(4);
    expect(rowOf(3).sweepAttempts).toBe(4);
  });

  test('4. a successful sweep leaves the row complete and later runs do nothing', async () => {
    seedRow(4);
    setSystemTime(at(5 * MIN));
    await sweep();
    expect(executions).toBe(1);
    expect(rowOf(4).sweepAttempts).toBe(1);

    const row = rowOf(4);
    expect(row.status).toBe('complete');
    expect(row.completedAt).not.toBeNull();
    expect(row.failureCode).toBeNull();
    expect(row.failureReason).toBeNull();
    expect(row.attemptId).toBeNull();
    expect(row.lockExpiresAt).toBeNull();

    setSystemTime(at(60 * MIN));
    await sweep();
    await approve(4);
    expect(executions).toBe(1);
    expect(await isTinyCloudBootstrapComplete(store.prisma, { keyId: 'key-4', chainId: 1, host: HOST })).toBe(true);
  });

  test('5. a fresh sweep call resumes from the stored counter, not in-process state', async () => {
    seedRow(5);
    failWith('tinycloud_bootstrap_failed');

    setSystemTime(at(5 * MIN));
    await sweep();
    expect(rowOf(5).sweepAttempts).toBe(1);

    setSystemTime(at(6 * MIN));
    await sweep();
    expect(executions).toBe(1);

    setSystemTime(at(35 * MIN));
    await sweep();
    expect(executions).toBe(2);
    expect(rowOf(5).sweepAttempts).toBe(2);
  });

  test('6. a tick takes at most ten due rows; the next tick takes the rest', async () => {
    for (let i = 0; i < 12; i += 1) seedRow(10 + i);
    setSystemTime(at(5 * MIN));

    const first = await sweep();
    expect(first.claimed).toBe(10);
    expect(executions).toBe(10);
    expect(store.rows.filter((row) => row.status === 'complete')).toHaveLength(10);

    await sweep();
    expect(executions).toBe(12);
    expect(store.rows.filter((row) => row.status === 'complete')).toHaveLength(12);
  });

  test('7. non-retryable and unknown codes stay failed and are never claimed', async () => {
    const codes: Array<string | null> = [
      'tinycloud_bootstrap_expired_request',
      'tinycloud_bootstrap_untrusted_host',
      'tinycloud_bootstrap_in_progress',
      'tinycloud_bootstrap_crashed',
      null,
      'some_unknown_code',
    ];
    codes.forEach((failureCode, i) => seedRow(30 + i, { failureCode }));
    seedRow(36);

    setSystemTime(at(5 * MIN));
    const summary = await sweep();

    expect(summary.claimed).toBe(1);
    expect(executions).toBe(1);
    for (let i = 0; i < codes.length; i += 1) {
      expect(rowOf(30 + i).status).toBe('failed');
      expect(rowOf(30 + i).sweepAttempts).toBe(0);
    }
    expect(rowOf(36).status).toBe('complete');
  });

  test('8. each retryable code is swept exactly once', async () => {
    const codes = ['tinycloud_bootstrap_node_timeout', 'tinycloud_bootstrap_failed', 'tinycloud_bootstrap_space_not_hosted'];
    codes.forEach((failureCode, i) => seedRow(40 + i, { failureCode }));

    setSystemTime(at(5 * MIN));
    await sweep();

    expect(executions).toBe(3);
    for (let i = 0; i < codes.length; i += 1) {
      expect(rowOf(40 + i).status).toBe('complete');
      expect(rowOf(40 + i).sweepAttempts).toBe(1);
    }
  });

  test('9. other bootstrap versions, other hosts, and rows older than thirty days are not touched', async () => {
    seedRow(50, { bootstrapVersion: '@tinycloud/bootstrap:other' });
    seedRow(51, { tinycloudHost: 'https://other.example.com' });
    seedRow(52, { checkedAt: at(-31 * DAY) });
    seedRow(53);

    setSystemTime(at(5 * MIN));
    await sweep();

    expect(executions).toBe(1);
    for (const n of [50, 51, 52]) expect(rowOf(n).sweepAttempts).toBe(0);
    expect(rowOf(53).sweepAttempts).toBe(1);
  });

  test('10a. auto-sign off, archived, external, and sealed-less keys are never claimed or unsealed', async () => {
    seedRow(60, { autoSignEnabled: false });
    seedRow(61, { archivedAt: at(-DAY) });
    seedRow(62, { keyType: 'EXTERNAL' });
    seedRow(63, { sealedBlob: null });
    seedRow(65);
    let unseals = 0;

    setSystemTime(at(5 * MIN));
    await sweep({
      resolveKey: async () => {
        unseals += 1;
        return PRIVATE_KEY;
      },
    });

    expect(executions).toBe(1);
    expect(unseals).toBe(1);
    for (const n of [60, 61, 62, 63]) expect(rowOf(n).sweepAttempts).toBe(0);
    expect(rowOf(65).sweepAttempts).toBe(1);
  });

  test('10b. auto-sign switched off between the read and the claim signs nothing', async () => {
    seedRow(64);
    seedRow(66);
    store.hooks.onFindMany = () => {
      const user = store.users.get('user-64');
      if (user) user.autoSignEnabled = false;
    };
    let unseals = 0;

    setSystemTime(at(5 * MIN));
    const summary = await sweep({
      resolveKey: async () => {
        unseals += 1;
        return PRIVATE_KEY;
      },
    });

    expect(summary.claimed).toBe(1);
    expect(executions).toBe(1);
    expect(unseals).toBe(1);
    expect(rowOf(64).sweepAttempts).toBe(0);
    expect(rowOf(66).status).toBe('complete');
  });

  test('11. an unseal failure spends an attempt and ends at the cap', async () => {
    seedRow(70);
    let unseals = 0;
    const failingUnseal = async () => {
      unseals += 1;
      throw new Error('unseal failed');
    };

    setSystemTime(at(5 * MIN));
    await sweep({ resolveKey: failingUnseal });
    expect(rowOf(70).status).toBe('failed');
    expect(rowOf(70).failureCode).toBe('tinycloud_bootstrap_failed');
    expect(rowOf(70).sweepAttempts).toBe(1);

    for (const offset of [35 * MIN, 155 * MIN, 515 * MIN]) {
      setSystemTime(at(offset));
      await sweep({ resolveKey: failingUnseal });
    }
    expect(rowOf(70).sweepAttempts).toBe(4);

    setSystemTime(at(365 * DAY));
    await sweep({ resolveKey: failingUnseal });
    expect(unseals).toBe(4);
    expect(executions).toBe(0);
  });

  test('12. a row locked by a concurrent writer after the read is skipped', async () => {
    const row = seedRow(80);
    seedRow(81);
    store.hooks.onFindMany = () => {
      row.status = 'in_progress';
      row.lockExpiresAt = at(10 * MIN);
      row.attemptId = 'held-elsewhere';
    };

    setSystemTime(at(5 * MIN));
    const summary = await sweep();

    expect(summary.claimed).toBe(1);
    expect(summary.skipped).toBe(1);
    expect(executions).toBe(1);
    expect(rowOf(80).sweepAttempts).toBe(0);
    expect(rowOf(80).attemptId).toBe('held-elsewhere');
    expect(rowOf(81).status).toBe('complete');
  });

  test('13. an approval claim racing the sweep wins on Prisma (PGlite)', async () => {
    const pg = await pgliteStore();
    try {
      await seedPgliteRow(pg.prisma, 90);
      const approvalStarted = deferred();
      const release = deferred();
      setTinyCloudBootstrapExecutorForTests(async () => {
        executions += 1;
        approvalStarted.resolve();
        await release.promise;
      });

      let approval: Promise<unknown> | undefined;
      const racing = afterCandidateRead(pg.prisma, async () => {
        approval = approveOn(pg.prisma, 90);
        await approvalStarted.promise;
      });

      setSystemTime(at(5 * MIN));
      const summary = await sweepTinyCloudBootstrapOnce({ prisma: racing, resolveKey: async () => PRIVATE_KEY });
      release.resolve();
      const approved = await approval;

      expect(summary.claimed).toBe(0);
      expect(summary.skipped).toBe(1);
      expect(executions).toBe(1);
      expect(approved).toMatchObject({ status: 'complete' });
      expect(await pgliteStateOf(pg.prisma, 90)).toMatchObject({ status: 'complete', sweepAttempts: 0 });
    } finally {
      await pg.close();
    }
  });

  test('13a. a sweep claim that lands first leaves the approval waiting; nothing double-signs (PGlite)', async () => {
    const pg = await pgliteStore();
    try {
      await seedPgliteRow(pg.prisma, 91);
      const sweepStarted = deferred();
      const release = deferred();
      setTinyCloudBootstrapExecutorForTests(async () => {
        executions += 1;
        sweepStarted.resolve();
        await release.promise;
      });

      setSystemTime(at(5 * MIN));
      const sweeping = sweepTinyCloudBootstrapOnce({ prisma: pg.prisma, resolveKey: async () => PRIVATE_KEY });
      await sweepStarted.promise;
      const approved = await hostRequestedSpaceWithinBudget(() => approveOn(pg.prisma, 91), { timeoutMs: 5_000, retryDelaysMs: [] });
      release.resolve();
      const summary = await sweeping;

      expect(summary.claimed).toBe(1);
      expect(approved).toEqual({ status: 'pending', errorCode: 'tinycloud_bootstrap_in_progress' });
      expect(executions).toBe(1);
      expect(await pgliteStateOf(pg.prisma, 91)).toMatchObject({ status: 'complete', sweepAttempts: 3 });
    } finally {
      await pg.close();
    }
  });

  test('13b. auto-sign switched off between the candidate read and the claim updates nothing (PGlite)', async () => {
    const pg = await pgliteStore();
    try {
      await seedPgliteRow(pg.prisma, 92);
      const racing = afterCandidateRead(pg.prisma, async () => {
        await pg.prisma.user.update({ where: { id: 'user-92' }, data: { autoSignEnabled: false } });
      });
      let unseals = 0;

      setSystemTime(at(5 * MIN));
      const summary = await sweepTinyCloudBootstrapOnce({
        prisma: racing,
        resolveKey: async () => {
          unseals += 1;
          return PRIVATE_KEY;
        },
      });

      expect(summary.claimed).toBe(0);
      expect(summary.skipped).toBe(1);
      expect(unseals).toBe(0);
      expect(executions).toBe(0);
      expect(await pgliteStateOf(pg.prisma, 92)).toMatchObject({ status: 'failed', attemptId: null, sweepAttempts: 2 });
    } finally {
      await pg.close();
    }
  });

  // TC-1518: an ORG key never reaches a personal path. A state row can point at one structurally (the foreign
  // key allows it), so the sweep must filter on custody itself, in both the candidate read and the claim.
  const ORG_ADDRESS = privateKeyToAccount(`0x${'22'.repeat(32)}`).address;
  async function seedOrgKeyRow(prisma: PrismaClient, n: number): Promise<void> {
    await prisma.user.create({ data: { id: `user-${n}`, email: `user-${n}@example.test` } });
    await prisma.ethereumKey.create({
      data: { id: `key-${n}`, custody: 'ORG', userId: null, keyType: 'MANAGED', sealingContext: 'o'.repeat(43), isCanonicalTinyCloud: false, address: ORG_ADDRESS, publicKey: '', sealedBlob: 'sealed' },
    });
    await prisma.tinyCloudBootstrapState.create({
      data: {
        id: `state-${n}`, userId: `user-${n}`, keyId: `key-${n}`, address: ORG_ADDRESS, chainId: 1, tinycloudHost: HOST,
        bootstrapVersion: TINYCLOUD_BOOTSTRAP_VERSION, status: 'failed', checkedAt: at(-3 * 60 * MIN),
        failureCode: 'tinycloud_bootstrap_node_timeout', failureReason: 'node timed out', sweepAttempts: 2,
      },
    });
  }

  test('13c. the sweep never selects, unseals or runs for an ORG-custody key (PGlite)', async () => {
    const pg = await pgliteStore();
    try {
      await seedOrgKeyRow(pg.prisma, 95);
      await seedPgliteRow(pg.prisma, 96);
      const unsealed: string[] = [];
      setTinyCloudBootstrapExecutorForTests(async () => { executions += 1; });

      setSystemTime(at(5 * MIN));
      const summary = await sweepTinyCloudBootstrapOnce({
        prisma: pg.prisma,
        resolveKey: async (key) => { unsealed.push(key.id); return PRIVATE_KEY; },
      });

      expect(unsealed).toEqual(['key-96']);
      expect(summary.candidates).toBe(1);
      expect(executions).toBe(1);
      expect(await pgliteStateOf(pg.prisma, 95)).toMatchObject({ status: 'failed', attemptId: null, sweepAttempts: 2 });
    } finally {
      await pg.close();
    }
  });

  test('13d. a sweep claim on an ORG-custody key updates nothing (PGlite)', async () => {
    const pg = await pgliteStore();
    try {
      await seedOrgKeyRow(pg.prisma, 97);
      const before = await pgliteStateOf(pg.prisma, 97);
      let claimed = false;
      setTinyCloudBootstrapExecutorForTests(async () => { executions += 1; });

      setSystemTime(at(5 * MIN));
      await ensureTinyCloudBootstrap({
        prisma: pg.prisma,
        userId: 'user-97',
        key: { id: 'key-97', address: ADDRESS, keyType: 'MANAGED' },
        privateKey: PRIVATE_KEY,
        host: HOST,
        chainId: 1,
        sweepClaim: {
          observed: { status: 'failed', sweepAttempts: 2, checkedAt: before!.checkedAt, attemptId: null },
          onClaimed: () => { claimed = true; },
        },
      });

      expect(claimed).toBe(false);
      expect(executions).toBe(0);
      expect(await pgliteStateOf(pg.prisma, 97)).toMatchObject({ status: 'failed', attemptId: null, sweepAttempts: 2 });
    } finally {
      await pg.close();
    }
  });

  test.each(['claim', 'candidate selection'] as const)('13e. the sweep %s requires both PERSONAL custody and a sealed blob (PGlite)', async (path) => {
    const pg = await pgliteStore();
    try {
      await seedOrgKeyRow(pg.prisma, 98);
      await seedPgliteRow(pg.prisma, 99);
      const noBlobAddress = privateKeyToAccount(`0x${'33'.repeat(32)}`).address;
      await pg.prisma.ethereumKey.update({ where: { id: 'key-99' }, data: { address: noBlobAddress, sealedBlob: null } });
      await pg.prisma.tinyCloudBootstrapState.update({ where: { id: 'state-99' }, data: { address: noBlobAddress } });
      await seedPgliteRow(pg.prisma, 100);
      await pg.prisma.user.updateMany({ data: { autoSignEnabled: true } });
      const orgBefore = await pgliteStateOf(pg.prisma, 98);
      const unsealedBefore = await pgliteStateOf(pg.prisma, 99);
      const claimed: string[] = [];
      const resolved: string[] = [];
      setTinyCloudBootstrapExecutorForTests(async () => { executions += 1; });
      setSystemTime(at(5 * MIN));

      if (path === 'claim') {
        // Bypass candidate selection to exercise the real claim's own restrictions.
        for (const n of [98, 99, 100]) {
          const before = await pgliteStateOf(pg.prisma, n);
          let won = false;
          await ensureTinyCloudBootstrap({
            prisma: pg.prisma,
            userId: `user-${n}`,
            key: { id: `key-${n}`, address: before!.address, keyType: 'MANAGED' },
            privateKey: async () => { resolved.push(`key-${n}`); return PRIVATE_KEY; },
            host: HOST,
            chainId: 1,
            sweepClaim: {
              observed: { status: 'failed', sweepAttempts: 2, checkedAt: before!.checkedAt, attemptId: null },
              onClaimed: () => { won = true; claimed.push(`key-${n}`); },
            },
          });
          expect(won).toBe(n === 100);
        }
        expect(claimed).toEqual(['key-100']);
      } else {
        const summary = await sweepTinyCloudBootstrapOnce({
          prisma: pg.prisma,
          resolveKey: async (key) => { resolved.push(key.id); return PRIVATE_KEY; },
        });
        expect(summary.candidates).toBe(1);
        expect(summary.claimed).toBe(1);
        expect(summary.healed).toBe(1);
      }

      expect(resolved).toEqual(['key-100']);
      expect(executions).toBe(1);
      expect(await pgliteStateOf(pg.prisma, 98)).toEqual(orgBefore);
      expect(await pgliteStateOf(pg.prisma, 99)).toEqual(unsealedBefore);
      expect(await pgliteStateOf(pg.prisma, 100)).toMatchObject({ status: 'complete', attemptId: null, sweepAttempts: 3 });
    } finally {
      await pg.close();
    }
  });

  test('14. a stale in-progress lock with a retryable code is swept; a null code is not; the reaper only marks it failed', async () => {
    seedRow(100, { status: 'in_progress', lockExpiresAt: at(-MIN), attemptId: 'dead', checkedAt: at(-60 * MIN) });
    seedRow(101, { status: 'in_progress', lockExpiresAt: at(-MIN), attemptId: 'dead', failureCode: null, checkedAt: at(-60 * MIN) });

    setSystemTime(T0);
    await sweep();

    expect(rowOf(100).status).toBe('complete');
    expect(rowOf(100).sweepAttempts).toBe(1);
    expect(rowOf(101).status).toBe('failed');
    expect(rowOf(101).failureCode).toBe('tinycloud_bootstrap_lease_expired');
    expect(rowOf(101).sweepAttempts).toBe(0);
    expect(executions).toBe(1);
  });

  test('15. concurrent sweeps and an approval racing a sweep sign once per run', async () => {
    const solo = startFakeTinyCloudNode();
    const raced = startFakeTinyCloudNode();
    const mixed = startFakeTinyCloudNode();
    try {
      setTinyCloudBootstrapExecutorForTests();
      await sweepOnNode(solo, 110, () => sweep());
      const expected = { hosts: solo.hostPosts.length, sessions: solo.sessionPosts.length };
      expect(expected.hosts).toBeGreaterThan(0);

      const pair = await sweepOnNode(raced, 111, () => Promise.all([sweep(), sweep()])) as Awaited<ReturnType<typeof sweep>>[];
      expect(pair.reduce((total, summary) => total + summary.claimed, 0)).toBe(1);
      expect({ hosts: raced.hostPosts.length, sessions: raced.sessionPosts.length }).toEqual(expected);

      await sweepOnNode(mixed, 112, () => Promise.all([approve(112, mixed.url), sweep()]));
      expect({ hosts: mixed.hostPosts.length, sessions: mixed.sessionPosts.length }).toEqual(expected);
      expect(rowOf(112).status).toBe('complete');
    } finally {
      solo.stop();
      raced.stop();
      mixed.stop();
    }
  });

  test('16. a sweep run requests the same delegations as an approval run', async () => {
    const approvalNode = startFakeTinyCloudNode();
    const sweepNode = startFakeTinyCloudNode();
    try {
      setTinyCloudBootstrapExecutorForTests();
      process.env.TINYCLOUD_BOOTSTRAP_HOST = approvalNode.url;
      seedKey(120);
      await approve(120, approvalNode.url);

      await sweepOnNode(sweepNode, 121, () => sweep());

      const shape = (node: FakeTinyCloudNode) => ({
        hosts: node.hostPosts.length,
        spaces: node.sessionPosts.map((post) => post.spaceId).sort(),
        recaps: node.sessionPosts
          .map((post) => Object.entries(recapOf(post.authorization)).map(([key, value]) => `${key}:${Object.keys(value).sort().join(',')}`).sort().join('|'))
          .sort(),
      });
      expect(approvalNode.sessionPosts.length).toBeGreaterThan(0);
      expect(sweepNode.sessionPosts.length).toBeGreaterThan(0);
      expect(shape(sweepNode)).toEqual(shape(approvalNode));
    } finally {
      approvalNode.stop();
      sweepNode.stop();
    }
  });

  test('17. an approval resets the counter; a sweep claim adds exactly one', async () => {
    seedRow(130, { sweepAttempts: 2, checkedAt: at(-MIN) });
    await approve(130);
    expect(rowOf(130).sweepAttempts).toBe(0);

    seedRow(131, { sweepAttempts: 2, checkedAt: at(-3 * 60 * MIN) });
    await sweep();
    expect(rowOf(131).status).toBe('complete');
    expect(rowOf(131).sweepAttempts).toBe(3);
  });

  test('18. metrics: one tick logs its totals and one event per outcome', async () => {
    seedRow(140, { checkedAt: at(-2 * 60 * MIN) });
    seedRow(141, { checkedAt: at(-60 * MIN) });
    const locked = seedRow(142, { checkedAt: at(-30 * MIN) });
    store.hooks.onFindMany = () => {
      locked.status = 'in_progress';
      locked.lockExpiresAt = at(10 * MIN);
      locked.attemptId = 'held-elsewhere';
    };
    let call = 0;
    setTinyCloudBootstrapExecutorForTests(async () => {
      call += 1;
      if (call > 1) throw new TinyCloudBootstrapError('node call failed', 'tinycloud_bootstrap_node_timeout');
    });
    captureStdout();

    setSystemTime(at(5 * MIN));
    await sweep();

    const tick = sweepEvents('tinycloud_bootstrap_sweep_tick');
    expect(tick).toHaveLength(1);
    expect(tick[0]).toMatchObject({ candidates: 3, claimed: 2, healed: 1, still_failed: 1, skipped: 1 });
    const healed = sweepEvents('tinycloud_bootstrap_sweep_healed');
    expect(healed).toHaveLength(1);
    expect(healed[0]).toMatchObject({ sweep_attempt: 1 });
    const stillFailed = sweepEvents('tinycloud_bootstrap_sweep_still_failed');
    expect(stillFailed).toHaveLength(1);
    expect(stillFailed[0]).toMatchObject({ error_code: 'tinycloud_bootstrap_node_timeout' });
  });

  test('18b. a tick with nothing due writes no sweep log line', async () => {
    captureStdout();
    setSystemTime(at(5 * MIN));
    await sweep();
    expect(logLines().filter((line) => String(line.event).startsWith('tinycloud_bootstrap_sweep'))).toHaveLength(0);

    seedRow(170);
    await sweep();
    expect(sweepEvents('tinycloud_bootstrap_sweep_tick')).toHaveLength(1);
  });

  test('19. sweep log lines carry only allowlisted fields and no key, user, address, or failure text', async () => {
    seedRow(150, { checkedAt: at(-2 * 60 * MIN) });
    seedRow(151, { checkedAt: at(-60 * MIN) });
    let call = 0;
    setTinyCloudBootstrapExecutorForTests(async () => {
      call += 1;
      if (call > 1) throw new TinyCloudBootstrapError('node call failed', 'tinycloud_bootstrap_node_timeout');
    });
    captureStdout();

    setSystemTime(at(5 * MIN));
    await sweep();

    const allowed: Record<string, string[]> = {
      tinycloud_bootstrap_sweep_tick: ['candidates', 'claimed', 'healed', 'still_failed', 'skipped'],
      tinycloud_bootstrap_sweep_healed: ['sweep_attempt', 'duration_ms'],
      tinycloud_bootstrap_sweep_still_failed: ['error_code', 'sweep_attempt', 'duration_ms'],
    };
    const base = ['event', 'level', 'request_id', 'ts'];
    const lines = logLines().filter((line) => String(line.event).startsWith('tinycloud_bootstrap_sweep'));
    expect(lines.length).toBeGreaterThan(0);
    for (const line of lines) {
      const fields = allowed[String(line.event)];
      expect(fields).toBeDefined();
      expect(Object.keys(line).sort()).toEqual([...base, ...(fields ?? [])].sort());
    }
    const text = capturedText();
    for (const secret of [PRIVATE_KEY, ADDRESS, 'key-150', 'user-150', 'key-151', 'user-151', 'node timed out']) {
      expect(text).not.toContain(secret);
    }
  });

  test('20a. the kill switch makes a tick a no-op', async () => {
    seedRow(160);
    process.env.TINYCLOUD_BOOTSTRAP_SWEEP = 'off';

    setSystemTime(at(5 * MIN));
    const summary = await sweep();

    expect(summary).toEqual({ candidates: 0, claimed: 0, healed: 0, still_failed: 0, skipped: 0 });
    expect(executions).toBe(0);
    expect(rowOf(160).sweepAttempts).toBe(0);
    delete process.env.TINYCLOUD_BOOTSTRAP_SWEEP;
    expect((await sweep()).claimed).toBe(1);
    expect(executions).toBe(1);
    expect(rowOf(160).sweepAttempts).toBe(1);
  });

  test('20b. the timer starts once, is unref\'d, and never overlaps ticks', async () => {
    let findManyCalls = 0;
    const hanging = {
      tinyCloudBootstrapState: {
        findMany: () => {
          findManyCalls += 1;
          return new Promise(() => {});
        },
      },
    } as unknown as PrismaClient;
    const timers = spyOn(globalThis, 'setInterval');
    const clears = spyOn(globalThis, 'clearInterval');

    const stop = startTinyCloudBootstrapSweep({ prisma: hanging });
    startTinyCloudBootstrapSweep({ prisma: hanging });
    try {
      expect(timers).toHaveBeenCalledTimes(1);
      const handle = timers.mock.results[0]?.value as { hasRef: () => boolean };
      expect(handle.hasRef()).toBe(false);

      const tick = timers.mock.calls[0]?.[0] as () => void;
      tick();
      tick();
      await Bun.sleep(10);
      expect(findManyCalls).toBe(1);
      stop();
      expect(clears).toHaveBeenCalledWith(handle);
    } finally {
      stop();
      timers.mockRestore();
      clears.mockRestore();
    }
  });
});

// TC-2380 (PR-1a): a lease that was never released is marked failed and never re-signed; each
// run is bounded; the sweep claim and its log are hardened; a node that says "not hosted" beats a
// cached `complete`. None of this adds a path that signs without a fresh user approval.

const SEC = 1000;
const LEASE_EXPIRED = 'tinycloud_bootstrap_lease_expired';
const DEADLINE = 'tinycloud_bootstrap_deadline';

/** Lets every already-resolved promise continue; fake timers do not advance microtasks. */
async function flush(): Promise<void> {
  for (let i = 0; i < 300; i += 1) await Promise.resolve();
}

/** Moves the fake clock in 5 s steps, letting the awaiting code run between steps. */
async function advance(ms: number): Promise<void> {
  for (let left = ms; left > 0; left -= 5 * SEC) {
    jest.advanceTimersByTime(Math.min(5 * SEC, left));
    await flush();
  }
}

/** An in-progress row whose holder is gone. */
function seedAbandoned(n: number, opts: SeedOptions = {}): FakeBootstrapRow {
  return seedRow(n, {
    status: 'in_progress',
    failureCode: null,
    lockExpiresAt: at(-MIN),
    attemptId: 'dead-holder',
    checkedAt: at(-60 * MIN),
    ...opts,
  });
}

describe('TC-2380 lease reaper', () => {
  test('an in-progress row with no code and an expired lease becomes failed(lease_expired), unsealed by no one', async () => {
    seedAbandoned(200);
    seedAbandoned(201, { lockExpiresAt: null });
    let unseals = 0;
    captureStdout();

    const summary = await sweep({ resolveKey: async () => { unseals += 1; return PRIVATE_KEY; } });

    for (const n of [200, 201]) {
      expect(rowOf(n)).toMatchObject({
        status: 'failed',
        failureCode: LEASE_EXPIRED,
        lockExpiresAt: null,
        attemptId: 'dead-holder',
        sweepAttempts: 0,
      });
      expect(rowOf(n).failureReason).toBeTruthy();
    }
    expect(summary).toMatchObject({ reaped: 2, claimed: 0, healed: 0 });
    expect(unseals).toBe(0);
    expect(executions).toBe(0);
    expect(sweepEvents('tinycloud_bootstrap_sweep_tick')[0]).toMatchObject({ reaped: 2 });
    const reaped = sweepEvents('tinycloud_bootstrap_sweep_reaped');
    expect(reaped).toHaveLength(2);
    expect(reaped[0]).toMatchObject({ error_code: LEASE_EXPIRED });
    expect(capturedText()).not.toContain('key-200');
    expect(capturedText()).not.toContain('dead-holder');
  });

  test('a row that already has a code keeps it; one with a live lease is not touched', async () => {
    seedAbandoned(202, { failureCode: DEADLINE });
    const live = seedAbandoned(203, { lockExpiresAt: at(MIN) });
    const before = structuredClone(live);

    const summary = await sweep();

    expect(rowOf(202)).toMatchObject({ status: 'failed', failureCode: DEADLINE, lockExpiresAt: null });
    expect(rowOf(203)).toEqual(before);
    expect(summary.reaped).toBe(1);
    expect(executions).toBe(0);
  });

  test('a row whose code the sweep retries still goes the existing route: claimed, signed and healed, not reaped', async () => {
    seedAbandoned(204, { failureCode: 'tinycloud_bootstrap_node_timeout' });

    const summary = await sweep();

    expect(summary).toMatchObject({ claimed: 1, healed: 1, reaped: 0 });
    expect(rowOf(204).status).toBe('complete');
    expect(executions).toBe(1);
  });

  test('the reaper never makes lease_expired or deadline a retryable code', () => {
    expect(SWEEP_RETRYABLE_CODES).not.toContain(LEASE_EXPIRED);
    expect(SWEEP_RETRYABLE_CODES).not.toContain(DEADLINE);
  });

  test('a failed(deadline) row is not picked for a sweep re-run; an approval can still claim it', async () => {
    seedRow(205, { status: 'failed', failureCode: DEADLINE, lockExpiresAt: null, checkedAt: at(-60 * MIN) });
    let unseals = 0;

    const summary = await sweep({ resolveKey: async () => { unseals += 1; return PRIVATE_KEY; } });

    expect(summary).toMatchObject({ candidates: 0, claimed: 0, reaped: 0 });
    expect(unseals).toBe(0);
    expect(executions).toBe(0);
    expect(rowOf(205).status).toBe('failed');

    expect(await approve(205)).toEqual({ status: 'complete' });
    expect(executions).toBe(1);
  });

  test('an approval re-claims a reaped row and resets its counter', async () => {
    seedAbandoned(206);
    await sweep();
    expect(rowOf(206).status).toBe('failed');

    expect(await approve(206)).toEqual({ status: 'complete' });
    expect(rowOf(206)).toMatchObject({ status: 'complete', sweepAttempts: 0, lockExpiresAt: null });
  });

  test('the same version, host, chain and age filters apply, and a tick reaps at most the batch size', async () => {
    seedAbandoned(210, { bootstrapVersion: 'other-version' });
    seedAbandoned(211, { tinycloudHost: 'https://elsewhere.example' });
    seedAbandoned(212, { checkedAt: at(-31 * DAY) });
    rowOf(212);
    for (let n = 213; n < 216; n += 1) seedAbandoned(n);

    const summary = await sweep({ batch: 2 });

    expect(summary.reaped).toBe(2);
    for (const n of [210, 211, 212]) expect(rowOf(n).status).toBe('in_progress');
    expect([213, 214, 215].filter((n) => rowOf(n).status === 'failed')).toHaveLength(2);
  });

  test('an approval that claims the row between the read and the reaper write wins; the reaper changes nothing', async () => {
    const row = seedAbandoned(220);
    let claimed = false;
    store.hooks.onFindMany = (found) => {
      if (claimed || !found.some((candidate) => candidate.id === row.id)) return;
      claimed = true;
      row.attemptId = 'approval-claim';
      row.lockExpiresAt = at(2 * MIN);
      row.checkedAt = at(0);
    };

    const summary = await sweep();

    expect(claimed).toBe(true);
    expect(summary.reaped).toBe(0);
    expect(row).toMatchObject({ status: 'in_progress', attemptId: 'approval-claim', failureCode: null, lockExpiresAt: at(2 * MIN) });
  });

  test('the kill switch also stops the reaper', async () => {
    seedAbandoned(221);
    process.env.TINYCLOUD_BOOTSTRAP_SWEEP = 'off';

    await sweep();

    expect(rowOf(221).status).toBe('in_progress');
  });

  test('on Prisma, NULL codes and NULL leases are selected and a live lease is left alone (PGlite)', async () => {
    const pg = await pgliteStore();
    try {
      for (const n of [230, 231, 232]) {
        const address = `0x${n.toString(16).padStart(40, '0')}`;
        await pg.prisma.user.create({ data: { id: `user-${n}`, email: `user-${n}@example.test` } });
        await pg.prisma.ethereumKey.create({ data: { id: `key-${n}`, userId: `user-${n}`, address, publicKey: '', sealedBlob: 'sealed' } });
        await pg.prisma.tinyCloudBootstrapState.create({
          data: { id: `state-${n}`, userId: `user-${n}`, keyId: `key-${n}`, address, chainId: 1, tinycloudHost: HOST, bootstrapVersion: TINYCLOUD_BOOTSTRAP_VERSION, status: 'failed', checkedAt: at(-60 * MIN) },
        });
      }
      const abandoned = { status: 'in_progress', failureCode: null, failureReason: null, sweepAttempts: 0, attemptId: 'dead', checkedAt: at(-60 * MIN) };
      await pg.prisma.tinyCloudBootstrapState.update({ where: { id: 'state-230' }, data: { ...abandoned, lockExpiresAt: at(-MIN) } });
      await pg.prisma.tinyCloudBootstrapState.update({ where: { id: 'state-231' }, data: { ...abandoned, lockExpiresAt: null } });
      await pg.prisma.tinyCloudBootstrapState.update({ where: { id: 'state-232' }, data: { ...abandoned, lockExpiresAt: at(MIN) } });
      let unseals = 0;

      const summary = await sweepTinyCloudBootstrapOnce({
        prisma: pg.prisma,
        resolveKey: async () => { unseals += 1; return PRIVATE_KEY; },
      });

      expect(summary.reaped).toBe(2);
      expect(await pgliteStateOf(pg.prisma, 230)).toMatchObject({ status: 'failed', failureCode: LEASE_EXPIRED, lockExpiresAt: null, attemptId: 'dead' });
      expect(await pgliteStateOf(pg.prisma, 231)).toMatchObject({ status: 'failed', failureCode: LEASE_EXPIRED, lockExpiresAt: null });
      expect(await pgliteStateOf(pg.prisma, 232)).toMatchObject({ status: 'in_progress', failureCode: null });
      expect(unseals).toBe(0);
      expect(executions).toBe(0);
    } finally {
      await pg.close();
    }
  });
});

describe('TC-2380 sweep claim hardening (TC-1779)', () => {
  test('L1: a key whose sealed blob disappears between the read and the claim is not claimed or unsealed', async () => {
    seedRow(240);
    store.hooks.onFindMany = () => {
      const key = store.keys.get('key-240');
      if (key) key.sealedBlob = null;
    };
    let unseals = 0;

    setSystemTime(at(5 * MIN));
    const summary = await sweep({ resolveKey: async () => { unseals += 1; return PRIVATE_KEY; } });

    expect(summary).toMatchObject({ claimed: 0, skipped: 1 });
    expect(unseals).toBe(0);
    expect(executions).toBe(0);
    expect(rowOf(240)).toMatchObject({ status: 'failed', sweepAttempts: 0 });
  });

  test('L2: a throw after the claim was won still counts the attempt and logs exhausted on the last one', async () => {
    seedRow(241, { sweepAttempts: 3, checkedAt: at(-7 * 60 * MIN) });
    failWith('tinycloud_bootstrap_failed');
    const updateMany = store.prisma.tinyCloudBootstrapState.updateMany.bind(store.prisma.tinyCloudBootstrapState);
    const spy = spyOn(store.prisma.tinyCloudBootstrapState, 'updateMany').mockImplementation(((args: { data: { status?: string } }) => {
      if (args.data.status === 'failed') throw new Error('database unavailable');
      return updateMany(args as never);
    }) as never);
    captureStdout();

    try {
      const summary = await sweep();

      expect(summary).toMatchObject({ claimed: 1, still_failed: 1, healed: 0 });
      expect(sweepEvents('tinycloud_bootstrap_sweep_exhausted')).toHaveLength(1);
      expect(sweepEvents('tinycloud_bootstrap_sweep_failed')).toHaveLength(1);
    } finally {
      spy.mockRestore();
    }
  });

  test('L3: switching the sweep off during a tick stops it before the next row', async () => {
    seedRow(242);
    seedRow(243);
    setTinyCloudBootstrapExecutorForTests(async () => {
      executions += 1;
      process.env.TINYCLOUD_BOOTSTRAP_SWEEP = 'off';
    });

    setSystemTime(at(5 * MIN));
    const summary = await sweep();

    expect(executions).toBe(1);
    expect(summary.claimed).toBe(1);
    const untouched = [242, 243].filter((n) => rowOf(n).sweepAttempts === 0);
    expect(untouched).toHaveLength(1);
    expect(rowOf(untouched[0]!).status).toBe('failed');
  });
});

describe('TC-2380 each run is bounded', () => {
  let originalFetch: typeof fetch;
  let envBefore: Record<string, string | undefined>;

  beforeEach(async () => {
    await import('@openkey/tee');
    originalFetch = globalThis.fetch;
    envBefore = {
      TINYCLOUD_BOOTSTRAP_NODE_TIMEOUT_MS: process.env.TINYCLOUD_BOOTSTRAP_NODE_TIMEOUT_MS,
      TINYCLOUD_BOOTSTRAP_NODE_INVOKE_TIMEOUT_MS: process.env.TINYCLOUD_BOOTSTRAP_NODE_INVOKE_TIMEOUT_MS,
    };
    // Per-call limits above every step below, so only the run limits can end a run.
    process.env.TINYCLOUD_BOOTSTRAP_NODE_TIMEOUT_MS = '60000';
    process.env.TINYCLOUD_BOOTSTRAP_NODE_INVOKE_TIMEOUT_MS = '60000';
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
    globalThis.fetch = originalFetch;
    for (const [name, value] of Object.entries(envBefore)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });

  /** Every node call takes `delayMs` of fake time and then answers; an aborted call rejects with the signal's reason. */
  function slowNode(delayMs: number): { signals: AbortSignal[] } {
    const signals: AbortSignal[] = [];
    globalThis.fetch = ((input: unknown, init?: RequestInit) => {
      const signal = init?.signal as AbortSignal;
      signals.push(signal);
      return new Promise<Response>((resolve, reject) => {
        const timer = setTimeout(() => {
          const url = String(input);
          resolve(new Response(url.includes('/peer/generate/') ? 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK' : '{"activated":[],"skipped":[]}'));
        }, delayMs);
        signal.addEventListener('abort', () => {
          clearTimeout(timer);
          reject(signal.reason);
        });
      });
    }) as unknown as typeof fetch;
    return { signals };
  }

  test('a run whose calls keep answering slowly is aborted at the deadline; the lock is released and the code is recorded', async () => {
    setTinyCloudBootstrapExecutorForTests();
    seedKey(250);
    const node = slowNode(50 * SEC);
    const result = approve(250);
    await flush();

    await advance(179 * SEC);
    expect(rowOf(250)).toMatchObject({ status: 'in_progress' });
    expect(node.signals.at(-1)?.aborted).toBe(false);

    await advance(2 * SEC);

    expect(await result).toMatchObject({ status: 'failed', errorCode: DEADLINE });
    expect(rowOf(250)).toMatchObject({ status: 'failed', failureCode: DEADLINE, lockExpiresAt: null });
    expect(node.signals.at(-1)?.aborted).toBe(true);
  });

  test('a step that never ends and never calls the node is cut off at the deadline too', async () => {
    seedKey(251);
    setTinyCloudBootstrapExecutorForTests(() => new Promise<void>(() => {}));
    const result = approve(251);
    await flush();

    await advance(179 * SEC);
    expect(rowOf(251).status).toBe('in_progress');
    await advance(2 * SEC);

    expect(await result).toMatchObject({ status: 'failed', errorCode: DEADLINE });
    expect(rowOf(251)).toMatchObject({ status: 'failed', failureCode: DEADLINE, lockExpiresAt: null });
  });

  test('the heartbeat never extends the lease past the deadline plus 30 s', async () => {
    seedKey(252);
    setTinyCloudBootstrapExecutorForTests(() => new Promise<void>(() => {}));
    const started = Date.now();
    const result = approve(252);
    await flush();
    let latest = 0;

    for (let elapsed = 0; elapsed < 180 * SEC; elapsed += 5 * SEC) {
      await advance(5 * SEC);
      latest = Math.max(latest, rowOf(252).lockExpiresAt?.getTime() ?? 0);
    }

    expect(latest).toBeLessThanOrEqual(started + 210 * SEC);
    // The plain two-minute lease would reach started + 270 s by the 150 s heartbeat.
    expect(latest).toBe(started + 210 * SEC);
    await advance(5 * SEC);
    await result;
    expect(rowOf(252).lockExpiresAt).toBeNull();
  });

  test('a lost lease aborts the run at the next heartbeat instead of after it returns', async () => {
    seedKey(253);
    setTinyCloudBootstrapExecutorForTests(() => new Promise<void>(() => {}));
    const result = approve(253);
    await flush();
    await advance(10 * SEC);
    rowOf(253).attemptId = 'new-holder';

    await advance(25 * SEC);

    const outcome = await result;
    expect(outcome).toMatchObject({ status: 'failed' });
    expect(rowOf(253)).toMatchObject({ status: 'in_progress', attemptId: 'new-holder' });
  });

  test('a lost lease aborts the node call in flight', async () => {
    setTinyCloudBootstrapExecutorForTests();
    seedKey(254);
    const node = slowNode(50 * SEC);
    const result = approve(254);
    await flush();
    await advance(10 * SEC);
    expect(node.signals.length).toBeGreaterThan(0);
    rowOf(254).attemptId = 'new-holder';

    await advance(25 * SEC);

    expect(node.signals.every((signal) => signal.aborted)).toBe(true);
    expect(await result).toMatchObject({ status: 'failed' });
    expect(rowOf(254)).toMatchObject({ status: 'in_progress', attemptId: 'new-holder' });
  });

  test('a run whose row was reaped while it was in flight is aborted by its next heartbeat and leaves the reaped row as it is', async () => {
    setTinyCloudBootstrapExecutorForTests();
    seedKey(256);
    const node = slowNode(50 * SEC);
    const result = approve(256);
    await flush();
    await advance(10 * SEC);
    // The holder looks dead to the reaper: its lease is in the past when a tick reads it.
    rowOf(256).lockExpiresAt = new Date(Date.now() - SEC);
    expect((await sweep()).reaped).toBe(1);
    const reaped = structuredClone(rowOf(256));
    expect(reaped).toMatchObject({ status: 'failed', failureCode: LEASE_EXPIRED, lockExpiresAt: null });
    const callsBefore = node.signals.length;

    await advance(25 * SEC);

    expect(await result).toMatchObject({ status: 'failed' });
    expect(rowOf(256)).toEqual(reaped);
    expect(node.signals.length).toBe(callsBefore);
    expect(node.signals.every((signal) => signal.aborted)).toBe(true);
  });

  test('a run that finishes in time clears its deadline and leaves no timers behind', async () => {
    seedKey(255);

    expect(await approve(255)).toEqual({ status: 'complete' });
    expect(jest.getTimerCount()).toBe(0);
    expect(rowOf(255).status).toBe('complete');
  });
});

describe('TC-2380 a node that says "not hosted" beats a cached complete', () => {
  function requestedDefault(extra: { nodeReportedUnhosted?: boolean } = {}) {
    const reports: Array<{ status: string }> = [];
    return {
      reports,
      requestedSpaces: { spaces: ['default'] as const, alreadyHosted: false, report: (report: { status: string }) => { reports.push(report); }, ...extra },
    };
  }

  function ensureWith(n: number, host: string, requestedSpaces: ReturnType<typeof requestedDefault>['requestedSpaces']) {
    return ensureTinyCloudBootstrap({
      prisma: store.prisma,
      userId: `user-${n}`,
      key: { id: `key-${n}`, address: ADDRESS, keyType: 'MANAGED' },
      privateKey: PRIVATE_KEY,
      host,
      chainId: 1,
      requestedSpaces,
    });
  }

  test('a complete row with a node-skipped approval claims the row and hosts the requested space', async () => {
    const node = startFakeTinyCloudNode();
    try {
      process.env.TINYCLOUD_BOOTSTRAP_HOST = node.url;
      seedRow(260, { status: 'complete', failureCode: null, tinycloudHost: node.url });
      const { reports, requestedSpaces } = requestedDefault({ nodeReportedUnhosted: true });

      const outcome = await ensureWith(260, node.url, requestedSpaces);

      expect(outcome).toEqual({ status: 'complete' });
      expect(node.hostPosts.map((post) => post.spaceId)).toEqual([expect.stringMatching(/:default$/)]);
      expect(reports).toEqual([{ status: 'hosted' }]);
      expect(executions).toBe(1);
      expect(rowOf(260)).toMatchObject({ status: 'complete', lockExpiresAt: null, attemptId: null });
    } finally {
      node.stop();
    }
  });

  test('a complete row with an approval the node did not skip adds no node calls', async () => {
    const node = startFakeTinyCloudNode();
    try {
      process.env.TINYCLOUD_BOOTSTRAP_HOST = node.url;
      seedRow(261, { status: 'complete', failureCode: null, tinycloudHost: node.url });
      const { reports, requestedSpaces } = requestedDefault();

      const outcome = await ensureWith(261, node.url, requestedSpaces);

      expect(outcome).toEqual({ status: 'complete' });
      expect(node.hostPosts).toHaveLength(0);
      expect(node.peerGets).toHaveLength(0);
      expect(node.sessionPosts).toHaveLength(0);
      expect(reports).toHaveLength(0);
      expect(executions).toBe(0);
    } finally {
      node.stop();
    }
  });
});

describe('TC-2380 a failed re-claim of a complete row is never re-signed by the sweep', () => {
  const RECLAIM_FAILED = 'tinycloud_bootstrap_reclaim_failed';

  function reclaim(n: number, host: string, extra: { alreadyHosted?: boolean } = {}) {
    return ensureTinyCloudBootstrap({
      prisma: store.prisma,
      userId: `user-${n}`,
      key: { id: `key-${n}`, address: ADDRESS, keyType: 'MANAGED' },
      privateKey: PRIVATE_KEY,
      host,
      chainId: 1,
      requestedSpaces: { spaces: ['default'], alreadyHosted: false, nodeReportedUnhosted: true, report: () => {}, ...extra },
    });
  }

  async function sweepLater(): Promise<{ summary: Awaited<ReturnType<typeof sweep>>; unseals: number }> {
    let unseals = 0;
    setSystemTime(at(7 * 24 * 60 * MIN));
    const summary = await sweep({ resolveKey: async () => { unseals += 1; return PRIVATE_KEY; } });
    return { summary, unseals };
  }

  test('a re-claimed complete row that fails on a node timeout ends failed(reclaim_failed) and the sweep leaves it alone', async () => {
    const node = startFakeTinyCloudNode();
    try {
      process.env.TINYCLOUD_BOOTSTRAP_HOST = node.url;
      seedRow(270, { status: 'complete', failureCode: null, tinycloudHost: node.url });
      failWith('tinycloud_bootstrap_node_timeout');

      const outcome = await reclaim(270, node.url);

      expect(outcome).toMatchObject({ status: 'failed', errorCode: 'tinycloud_bootstrap_node_timeout' });
      expect(rowOf(270)).toMatchObject({ status: 'failed', failureCode: RECLAIM_FAILED, failureReason: 'node call failed', lockExpiresAt: null });
      expect(SWEEP_RETRYABLE_CODES).not.toContain(RECLAIM_FAILED);

      const executionsBefore = executions;
      const { summary, unseals } = await sweepLater();
      expect(summary).toMatchObject({ candidates: 0, claimed: 0 });
      expect(unseals).toBe(0);
      expect(executions).toBe(executionsBefore);
    } finally {
      node.stop();
    }
  });

  test('an in-process retry that also times out keeps reclaim_failed, and the sweep still leaves the row alone', async () => {
    const node = startFakeTinyCloudNode();
    try {
      process.env.TINYCLOUD_BOOTSTRAP_HOST = node.url;
      seedRow(271, { status: 'complete', failureCode: null, tinycloudHost: node.url });
      failWith('tinycloud_bootstrap_node_timeout');
      await reclaim(271, node.url);
      expect(rowOf(271).failureCode).toBe(RECLAIM_FAILED);

      await reclaim(271, node.url, { alreadyHosted: true });

      expect(rowOf(271)).toMatchObject({ status: 'failed', failureCode: RECLAIM_FAILED });
      const executionsBefore = executions;
      const { summary, unseals } = await sweepLater();
      expect(summary).toMatchObject({ candidates: 0, claimed: 0 });
      expect(unseals).toBe(0);
      expect(executions).toBe(executionsBefore);
    } finally {
      node.stop();
    }
  });

  test('a later successful approval clears it to complete', async () => {
    const node = startFakeTinyCloudNode();
    try {
      process.env.TINYCLOUD_BOOTSTRAP_HOST = node.url;
      seedRow(272, { status: 'complete', failureCode: null, tinycloudHost: node.url });
      failWith('tinycloud_bootstrap_node_timeout');
      await reclaim(272, node.url);
      succeed();

      expect(await approve(272, node.url)).toEqual({ status: 'complete' });

      expect(rowOf(272)).toMatchObject({ status: 'complete', failureCode: null, failureReason: null, lockExpiresAt: null });
    } finally {
      node.stop();
    }
  });

  test('an ordinary failed row that is not a re-claim keeps its own code', async () => {
    seedRow(273, { status: 'failed', failureCode: 'tinycloud_bootstrap_node_timeout' });
    failWith('tinycloud_bootstrap_node_timeout');

    await approve(273);

    expect(rowOf(273)).toMatchObject({ status: 'failed', failureCode: 'tinycloud_bootstrap_node_timeout' });
  });

  test('an expired in-progress row carrying reclaim_failed is reaped and keeps that code', async () => {
    seedAbandoned(274, { failureCode: RECLAIM_FAILED });

    const summary = await sweep();

    expect(summary.reaped).toBe(1);
    expect(rowOf(274)).toMatchObject({ status: 'failed', failureCode: RECLAIM_FAILED, lockExpiresAt: null });
    expect(executions).toBe(0);
  });
});
