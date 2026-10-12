import { afterEach, describe, expect, mock, spyOn, test } from 'bun:test';
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
const options = { logPrefix: '[Budget test]', logContext: { keyId: 'key_1' }, budgetMs: 30 };
const flush = () => new Promise((resolve) => setTimeout(resolve, 20));

afterEach(() => { setTinyCloudBootstrapBackgroundObserverForTests(); });

describe('TC-945 TinyCloud bootstrap budget', () => {
  test('fast bootstrap clears its timer and has no async log', async () => {
    const log = spyOn(console, 'log').mockImplementation(() => {});
    const clear = spyOn(globalThis, 'clearTimeout');
    try {
      const start = performance.now();
      expect(await awaitTinyCloudBootstrapWithinBudget(Promise.resolve({ status: 'complete' }), {
        ...options, budgetMs: 10_000,
      })).toEqual({ status: 'complete' });
      expect(performance.now() - start).toBeLessThan(500);
      expect(clear).toHaveBeenCalledTimes(1);
      expect(log).not.toHaveBeenCalled();
    } finally { log.mockRestore(); clear.mockRestore(); }
  });

  test('slow bootstrap returns pending, then observes completion exactly once without key material', async () => {
    const work = deferred();
    const observer = mock(() => {});
    setTinyCloudBootstrapBackgroundObserverForTests(observer);
    const log = spyOn(console, 'log').mockImplementation(() => {});
    try {
      const start = performance.now();
      expect(await awaitTinyCloudBootstrapWithinBudget(work.promise, options)).toEqual({ status: 'pending' });
      expect(performance.now() - start).toBeLessThan(500);
      expect(observer).not.toHaveBeenCalled();
      work.resolve({ status: 'complete' });
      await flush();
      expect(observer).toHaveBeenCalledTimes(1);
      expect(observer).toHaveBeenCalledWith({ status: 'complete' });
      expect(log).toHaveBeenCalledWith('[Budget test] TinyCloud bootstrap finished (async)', {
        keyId: 'key_1', status: 'complete',
      });
      expect(log.mock.calls[0]![1]).not.toHaveProperty('privateKey');
    } finally { work.resolve({ status: 'complete' }); log.mockRestore(); }
  });

  test('background failure is observed and logged with its code', async () => {
    const work = deferred();
    const observer = mock(() => {});
    setTinyCloudBootstrapBackgroundObserverForTests(observer);
    const error = spyOn(console, 'error').mockImplementation(() => {});
    const outcome = { status: 'failed' as const, errorCode: 'tinycloud_bootstrap_failed', errorMessage: 'seed failed' };
    try {
      expect(await awaitTinyCloudBootstrapWithinBudget(work.promise, options)).toEqual({ status: 'pending' });
      work.resolve(outcome);
      await flush();
      expect(observer).toHaveBeenCalledTimes(1);
      expect(observer).toHaveBeenCalledWith(outcome);
      expect(error).toHaveBeenCalledWith('[Budget test] TinyCloud bootstrap failed (async)', {
        keyId: 'key_1', errorCode: outcome.errorCode, errorMessage: outcome.errorMessage,
      });
    } finally { work.resolve(outcome); error.mockRestore(); }
  });

  test('background rejection is normalized and never unhandled', async () => {
    const work = deferred();
    const observer = mock(() => {});
    const unhandled = mock(() => {});
    setTinyCloudBootstrapBackgroundObserverForTests(observer);
    process.on('unhandledRejection', unhandled);
    const error = spyOn(console, 'error').mockImplementation(() => {});
    try {
      expect(await awaitTinyCloudBootstrapWithinBudget(work.promise, options)).toEqual({ status: 'pending' });
      work.reject(new Error('database unavailable'));
      await flush();
      expect(observer).toHaveBeenCalledTimes(1);
      expect(observer).toHaveBeenCalledWith({ status: 'failed', errorCode: 'tinycloud_bootstrap_crashed', errorMessage: 'database unavailable' });
      expect(error).toHaveBeenCalledWith('[Budget test] TinyCloud bootstrap crashed (async)', {
        keyId: 'key_1', errorCode: 'tinycloud_bootstrap_crashed', errorMessage: 'database unavailable',
      });
      expect(unhandled).not.toHaveBeenCalled();
    } finally { work.resolve({ status: 'complete' }); process.off('unhandledRejection', unhandled); error.mockRestore(); }
  });

  test('rejection before the budget returns failed synchronously', async () => {
    const error = spyOn(console, 'error').mockImplementation(() => {});
    try {
      expect(await awaitTinyCloudBootstrapWithinBudget(Promise.reject(new Error('database unavailable')), options)).toEqual({
        status: 'failed', errorCode: 'tinycloud_bootstrap_crashed', errorMessage: 'database unavailable',
      });
      expect(error).not.toHaveBeenCalled();
    } finally { error.mockRestore(); }
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
    const log = spyOn(console, 'log').mockImplementation(() => {});
    process.on('unhandledRejection', unhandled);
    setTinyCloudBootstrapBackgroundObserverForTests(() => { throw new Error('observer failed'); });
    try {
      expect(await awaitTinyCloudBootstrapWithinBudget(work.promise, options)).toEqual({ status: 'pending' });
      work.resolve({ status: 'complete' });
      await flush();
      expect(unhandled).not.toHaveBeenCalled();
    } finally { work.resolve({ status: 'complete' }); process.off('unhandledRejection', unhandled); log.mockRestore(); }
  });
});
