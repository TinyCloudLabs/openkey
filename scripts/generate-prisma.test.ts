import { access, mkdir, mkdtemp, readFile, readdir, rm, utimes, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, test } from 'bun:test';
import { withPrismaGenerateLock } from './generate-prisma';

const testDirectory = await mkdtemp(join(tmpdir(), 'openkey-prisma-generate-test-'));
const workerPath = join(import.meta.dir, 'generate-prisma-lock-worker.ts');
const LOCK_HELD_ENV = 'OPENKEY_BUILD_TOOLING_LOCK';

afterAll(async () => {
  await rm(testDirectory, { recursive: true, force: true });
});

describe('withPrismaGenerateLock', () => {
  async function runCliWorker(
    markerDirectory: string,
    workerId: string,
    operationMs: number,
    inheritedLock = false,
  ) {
    return new Promise<void>((resolveWorker, rejectWorker) => {
      const lockPath = join(testDirectory, 'cli-descendants.lock');
      const child = spawn(process.execPath, [workerPath, '--cli-test', lockPath, markerDirectory, workerId, String(operationMs)], {
        env: inheritedLock ? { ...process.env, [LOCK_HELD_ENV]: 'root-owner' } : process.env,
        stdio: 'inherit',
      });
      child.once('error', rejectWorker);
      child.once('close', (code) => {
        if (code === 0) resolveWorker();
        else rejectWorker(new Error(`CLI worker ${workerId} exited with ${code ?? 'unknown'}`));
      });
    });
  }

  async function waitForMarker(path: string) {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      try {
        await access(path);
        return;
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 2));
      }
    }
    throw new Error(`timed out waiting for ${path}`);
  }

  async function runWorkers(lockPath: string, count: number, operationMs: number, staleLockMs: number, heartbeatMs: number) {
    const markerDirectory = await mkdtemp(join(testDirectory, 'workers-'));
    await Promise.all(Array.from({ length: count }, (_, index) => new Promise<void>((resolveWorker, rejectWorker) => {
      const child = spawn(process.execPath, [workerPath, lockPath, markerDirectory, String(index), String(operationMs), String(staleLockMs), String(heartbeatMs)], {
        stdio: 'inherit',
      });
      child.once('error', rejectWorker);
      child.once('close', (code) => {
        if (code === 0) resolveWorker();
        else rejectWorker(new Error(`lock worker ${index} exited with ${code ?? 'unknown'}`));
      });
    })));

    const intervals = await Promise.all((await readdir(markerDirectory))
      .filter((file) => file.endsWith('.start'))
      .map(async (file) => ({
        start: Number(await readFile(join(markerDirectory, file), 'utf8')),
        end: Number(await readFile(join(markerDirectory, file.replace('.start', '.end')), 'utf8')),
      })));
    intervals.sort((left, right) => left.start - right.start);
    return intervals;
  }

  test('serializes concurrent operations', async () => {
    const lockPath = join(testDirectory, 'concurrent.lock');
    let activeOperations = 0;
    let maximumActiveOperations = 0;

    await Promise.all(
      Array.from({ length: 3 }, () => withPrismaGenerateLock(async () => {
        activeOperations += 1;
        maximumActiveOperations = Math.max(maximumActiveOperations, activeOperations);
        await new Promise((resolve) => setTimeout(resolve, 25));
        activeOperations -= 1;
      }, { lockPath, pollMs: 1, staleLockMs: 1_000 })),
    );

    expect(maximumActiveOperations).toBe(1);
  });

  test('generates once for the root CLI and skips generation in inherited descendants', async () => {
    const lockPath = join(testDirectory, 'cli-descendants.lock');
    const markerDirectory = await mkdtemp(join(testDirectory, 'cli-descendants-'));
    const root = runCliWorker(markerDirectory, 'root', 100);
    await waitForMarker(join(markerDirectory, 'root.generated'));

    await Promise.all(
      Array.from({ length: 4 }, (_, index) => runCliWorker(markerDirectory, `descendant-${index}`, 1, true)),
    );
    await root;

    const markers = await readdir(markerDirectory);
    expect(markers.filter((file) => file.endsWith('.generated'))).toEqual(['root.generated']);
    expect(markers.filter((file) => file.endsWith('.consumer'))).toHaveLength(5);
    await expect(access(lockPath)).rejects.toThrow();
  });

  test('serializes ordinary cross-process operations', async () => {
    const intervals = await runWorkers(join(testDirectory, 'cross-process.lock'), 4, 35, 500, 25);

    expect(intervals).toHaveLength(4);
    for (let index = 1; index < intervals.length; index += 1) {
      expect(intervals[index]!.start).toBeGreaterThanOrEqual(intervals[index - 1]!.end);
    }
  });

  test('recovers a stale lock while keeping sixteen claimants mutually exclusive', async () => {
    const lockPath = join(testDirectory, 'stale-recovery.lock');
    await mkdir(lockPath);
    const staleTime = new Date(Date.now() - 10_000);
    await utimes(lockPath, staleTime, staleTime);

    const intervals = await runWorkers(lockPath, 16, 40, 250, 50);

    expect(intervals).toHaveLength(16);
    for (let index = 1; index < intervals.length; index += 1) {
      expect(intervals[index]!.start).toBeGreaterThanOrEqual(intervals[index - 1]!.end);
    }
  });

  test('preserves a live long-running lease', async () => {
    const lockPath = join(testDirectory, 'live-lease.lock');
    const first = runWorkers(lockPath, 1, 140, 25, 5);
    await new Promise((resolve) => setTimeout(resolve, 45));
    const second = runWorkers(lockPath, 1, 20, 25, 5);
    const intervals = (await Promise.all([first, second])).flat().sort((left, right) => left.start - right.start);

    expect(intervals).toHaveLength(2);
    expect(intervals[1]!.start).toBeGreaterThanOrEqual(intervals[0]!.end);
  });

  test('reclaims a stale lock even when its recorded PID is live', async () => {
    const lockPath = join(testDirectory, 'reused-pid.lock');
    await mkdir(lockPath);
    await writeFile(join(lockPath, 'owner.json'), JSON.stringify({ pid: process.pid, token: 'old-owner' }));
    const staleTime = new Date(Date.now() - 10_000);
    await utimes(lockPath, staleTime, staleTime);

    const intervals = await runWorkers(lockPath, 1, 10, 20, 5);

    expect(intervals).toHaveLength(1);
  });

  test('reclaims a stale lock without an owner record', async () => {
    const lockPath = join(testDirectory, 'stale.lock');
    await mkdir(lockPath);
    const staleTime = new Date(Date.now() - 10_000);
    await utimes(lockPath, staleTime, staleTime);

    let ran = false;
    await withPrismaGenerateLock(() => {
      ran = true;
    }, { lockPath, pollMs: 1, staleLockMs: 10 });

    expect(ran).toBe(true);
  });
});
