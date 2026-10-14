import { afterEach, beforeEach, describe, expect, mock, spyOn, test } from 'bun:test';
import type { TinyCloudBootstrapOutcome } from '../services/tinycloud-bootstrap';
import {
  awaitTinyCloudBootstrapWithinBudget,
  setTinyCloudBootstrapBackgroundObserverForTests,
  tinyCloudBootstrapSyncBudgetMs,
} from '../services/tinycloud-bootstrap-budget';

function deferred() {
  let resolve!: (outcome: TinyCloudBootstrapOutcome) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<TinyCloudBootstrapOutcome>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

const options = { budgetMs: 30 };
const flush = async () => {
  await Promise.resolve();
  await Promise.resolve();
};
const output: string[] = [];
const originalStdoutWrite = process.stdout.write;
beforeEach(() => {
  output.length = 0;
  process.stdout.write = ((chunk: string | Uint8Array) => { output.push(String(chunk)); return true; }) as typeof process.stdout.write;
});
afterEach(() => {
  process.stdout.write = originalStdoutWrite;
  setTinyCloudBootstrapBackgroundObserverForTests();
});

describe('TC-945 TinyCloud bootstrap budget', () => {
  test('fast bootstrap clears its timer and has no async log', async () => {
    const clear = spyOn(globalThis, 'clearTimeout');
    try {
      const start = performance.now();
      expect(await awaitTinyCloudBootstrapWithinBudget(Promise.resolve({ status: 'complete' }), {
        budgetMs: 10_000,
      })).toEqual({ status: 'complete' });
      expect(performance.now() - start).toBeLessThan(500);
      expect(clear).toHaveBeenCalledTimes(1);
      expect(output).toHaveLength(0);
    } finally { clear.mockRestore(); }
  });

  test('slow bootstrap returns pending, then observes completion exactly once without key material', async () => {
    const work = deferred();
    const observer = mock(() => {});
    setTinyCloudBootstrapBackgroundObserverForTests(observer);
    try {
      const start = performance.now();
      expect(await awaitTinyCloudBootstrapWithinBudget(work.promise, options)).toEqual({ status: 'pending' });
      expect(performance.now() - start).toBeLessThan(500);
      expect(observer).not.toHaveBeenCalled();
      work.resolve({ status: 'complete' });
      await flush();
      expect(observer).toHaveBeenCalledTimes(1);
      expect(observer).toHaveBeenCalledWith({ status: 'complete' });
      expect(output).toHaveLength(1);
      const line = JSON.parse(output[0]!);
      expect(line).toMatchObject({ level: 'info', event: 'tinycloud_bootstrap_background_completed', request_id: 'startup' });
      expect(Object.keys(line).sort()).toEqual(['event', 'level', 'request_id', 'ts']);
    } finally { work.resolve({ status: 'complete' }); }
  });

  test('background failure is observed and logged with its code', async () => {
    const work = deferred();
    const observer = mock(() => {});
    setTinyCloudBootstrapBackgroundObserverForTests(observer);
    const outcome = { status: 'failed' as const, errorCode: 'tinycloud_bootstrap_failed', errorMessage: 'seed failed' };
    try {
      expect(await awaitTinyCloudBootstrapWithinBudget(work.promise, options)).toEqual({ status: 'pending' });
      work.resolve(outcome);
      await flush();
      expect(observer).toHaveBeenCalledTimes(1);
      expect(observer).toHaveBeenCalledWith(outcome);
      const line = JSON.parse(output[0]!);
      expect(line).toMatchObject({ level: 'error', event: 'tinycloud_bootstrap_background_failed', error_code: outcome.errorCode, request_id: 'startup' });
      expect(Object.keys(line).sort()).toEqual(['error_code', 'event', 'level', 'request_id', 'ts']);
    } finally { work.resolve(outcome); }
  });

  test('background rejection is normalized and never unhandled', async () => {
    const work = deferred();
    const observer = mock(() => {});
    const unhandled = mock(() => {});
    setTinyCloudBootstrapBackgroundObserverForTests(observer);
    process.on('unhandledRejection', unhandled);
    try {
      expect(await awaitTinyCloudBootstrapWithinBudget(work.promise, options)).toEqual({ status: 'pending' });
      work.reject(new Error('database unavailable'));
      await flush();
      expect(observer).toHaveBeenCalledTimes(1);
      expect(observer).toHaveBeenCalledWith({ status: 'failed', errorCode: 'tinycloud_bootstrap_crashed', errorMessage: 'database unavailable' });
      const line = JSON.parse(output[0]!);
      expect(line).toMatchObject({ level: 'error', event: 'tinycloud_bootstrap_background_failed', error_code: 'tinycloud_bootstrap_crashed', request_id: 'startup' });
      expect(Object.keys(line).sort()).toEqual(['error_code', 'event', 'level', 'request_id', 'ts']);
    } finally { work.resolve({ status: 'complete' }); process.off('unhandledRejection', unhandled); }
  });

  test('rejection before the budget returns failed synchronously without logging', async () => {
    expect(await awaitTinyCloudBootstrapWithinBudget(Promise.reject(new Error('database unavailable')), options)).toEqual({
      status: 'failed', errorCode: 'tinycloud_bootstrap_crashed', errorMessage: 'database unavailable',
    });
    expect(output).toHaveLength(0);
  });

  test('reads the current environment and defaults invalid or negative budgets', () => {
    for (const value of [undefined, '', 'abc', '-1', 'Infinity']) {
      expect(tinyCloudBootstrapSyncBudgetMs({ TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS: value })).toBe(2500);
    }
    expect(tinyCloudBootstrapSyncBudgetMs({ TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS: '0' })).toBe(0);
    expect(tinyCloudBootstrapSyncBudgetMs({ TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS: '75' })).toBe(75);
  });

  test('clamps configured budgets to 60000 ms so oversized timers cannot overflow', () => {
    for (const value of ['60000', '60001', '3000000000', String(Number.MAX_SAFE_INTEGER)]) {
      expect(tinyCloudBootstrapSyncBudgetMs({ TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS: value })).toBe(60_000);
    }
    expect(tinyCloudBootstrapSyncBudgetMs({ TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS: '59999' })).toBe(59_999);
  });

  test('clamps an explicit budget override before scheduling its timer', async () => {
    const timer = spyOn(globalThis, 'setTimeout');
    try {
      expect(await awaitTinyCloudBootstrapWithinBudget(Promise.resolve({ status: 'complete' }), {
        ...options, budgetMs: 3_000_000_000,
      })).toEqual({ status: 'complete' });
      expect(timer).toHaveBeenCalledWith(expect.any(Function), 60_000);
    } finally { timer.mockRestore(); }
  });

  test('a throwing background observer cannot cause an unhandled rejection', async () => {
    const work = deferred();
    const unhandled = mock(() => {});
    process.on('unhandledRejection', unhandled);
    setTinyCloudBootstrapBackgroundObserverForTests(() => { throw new Error('observer failed'); });
    try {
      expect(await awaitTinyCloudBootstrapWithinBudget(work.promise, options)).toEqual({ status: 'pending' });
      work.resolve({ status: 'complete' });
      await flush();
      expect(unhandled).not.toHaveBeenCalled();
    } finally { work.resolve({ status: 'complete' }); process.off('unhandledRejection', unhandled); }
  });
});
