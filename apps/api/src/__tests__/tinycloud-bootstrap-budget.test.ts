import { afterEach, beforeEach, describe, expect, mock, spyOn, test } from 'bun:test';
import type { TinyCloudBootstrapOutcome } from '../services/tinycloud-bootstrap';
import {
  awaitTinyCloudBootstrapWithinBudget,
  hostRequestedSpaceWithinBudget,
  setTinyCloudBootstrapBackgroundObserverForTests,
  tinyCloudBootstrapRetryDelaysMs,
  tinyCloudBootstrapSyncBudgetMs,
  tinyCloudRequestedSpaceTimeoutMs,
  type RequestedSpaceAttempt,
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
      expect(line).toMatchObject({ level: 'info', event: 'tinycloud_bootstrap_background_completed', attempt: 1, request_id: 'startup' });
      expect(line.duration_ms).toBeGreaterThanOrEqual(0);
      expect(Object.keys(line).sort()).toEqual(['attempt', 'duration_ms', 'event', 'level', 'request_id', 'ts']);
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
      expect(line).toMatchObject({ level: 'error', event: 'tinycloud_bootstrap_background_failed', error_code: outcome.errorCode, attempt: 1, request_id: 'startup' });
      expect(Object.keys(line).sort()).toEqual(['attempt', 'duration_ms', 'error_code', 'event', 'level', 'request_id', 'ts']);
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
      expect(line).toMatchObject({ level: 'error', event: 'tinycloud_bootstrap_background_failed', error_code: 'tinycloud_bootstrap_crashed', attempt: 1, request_id: 'startup' });
      expect(Object.keys(line).sort()).toEqual(['attempt', 'duration_ms', 'error_code', 'event', 'level', 'request_id', 'ts']);
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

// TC-1608: wait only for the requested space, then retry a failed run in the background.
describe('TC-1608 requested space within its timeout', () => {
  const failed = (errorCode: string): TinyCloudBootstrapOutcome => ({ status: 'failed', errorCode, errorMessage: `${errorCode} happened` });
  const events = () => output.map((line) => JSON.parse(line) as Record<string, unknown>);
  const until = async (condition: () => boolean) => {
    for (let turn = 0; turn < 200 && !condition(); turn += 1) await new Promise((resolve) => setTimeout(resolve, 5));
    expect(condition()).toBe(true);
  };

  test('answers hosted as soon as the space is reported, and logs the run when it ends', async () => {
    const work = deferred();
    const result = await hostRequestedSpaceWithinBudget(({ report }) => {
      report({ status: 'hosted' });
      return work.promise;
    }, { timeoutMs: 10_000, retryDelaysMs: [] });
    expect(result).toEqual({ status: 'hosted' });
    expect(output).toHaveLength(0);
    work.resolve({ status: 'complete' });
    await until(() => output.length === 1);
    expect(events()[0]).toMatchObject({ event: 'tinycloud_bootstrap_background_completed', attempt: 1, requested_space_hosted: 'yes' });
  });

  test('answers timeout when the space is not reported in time and keeps the run going', async () => {
    const work = deferred();
    expect(await hostRequestedSpaceWithinBudget(() => work.promise, { timeoutMs: 20, retryDelaysMs: [] })).toEqual({ status: 'timeout' });
    work.resolve({ status: 'complete' });
    await until(() => output.length === 1);
    expect(events()[0]).toMatchObject({ event: 'tinycloud_bootstrap_background_completed', requested_space_hosted: 'timeout' });
  });

  test('maps a run that ends without reporting to the matching answer', async () => {
    const answer = (outcome: TinyCloudBootstrapOutcome) =>
      hostRequestedSpaceWithinBudget(async () => outcome, { timeoutMs: 1000, retryDelaysMs: [] });
    expect(await answer({ status: 'complete' })).toEqual({ status: 'complete' });
    expect(await answer({ status: 'skipped' })).toEqual({ status: 'skipped' });
    expect(await answer(failed('tinycloud_bootstrap_in_progress'))).toEqual({ status: 'pending' });
    expect(await answer(failed('tinycloud_bootstrap_failed'))).toEqual({
      status: 'failed', errorCode: 'tinycloud_bootstrap_failed', errorMessage: 'tinycloud_bootstrap_failed happened',
    });
    expect(await hostRequestedSpaceWithinBudget(async () => { throw new Error('database unavailable'); }, { timeoutMs: 1000, retryDelaysMs: [] }))
      .toEqual({ status: 'failed', errorCode: 'tinycloud_bootstrap_crashed', errorMessage: 'database unavailable' });
  });

  test('a failure a retry will try again is "retrying"; it is "failed" when none will follow', async () => {
    const answer = (errorCode: string, retryDelaysMs: readonly number[]) =>
      hostRequestedSpaceWithinBudget(async () => failed(errorCode), { timeoutMs: 1000, retryDelaysMs });
    const retrying = (errorCode: string) => ({ status: 'retrying' as const, errorCode, errorMessage: `${errorCode} happened` });
    const final = (errorCode: string) => ({ status: 'failed' as const, errorCode, errorMessage: `${errorCode} happened` });

    expect(await answer('tinycloud_bootstrap_failed', [0])).toEqual(retrying('tinycloud_bootstrap_failed'));
    expect(await answer('tinycloud_bootstrap_node_timeout', [0])).toEqual(retrying('tinycloud_bootstrap_node_timeout'));
    expect(await answer('tinycloud_bootstrap_failed', [])).toEqual(final('tinycloud_bootstrap_failed'));
    // What a retry cannot fix is final even when retries are configured.
    expect(await answer('tinycloud_bootstrap_expired_request', [0])).toEqual(final('tinycloud_bootstrap_expired_request'));
    expect(await answer('tinycloud_bootstrap_untrusted_host', [0])).toEqual(final('tinycloud_bootstrap_untrusted_host'));
    // Let the background logs land (two runs each for the two retried answers, one for the rest)
    // before the next test reads the shared output.
    await until(() => output.length === 7);
  });

  test('retries a failed run after each delay until it succeeds, carrying the confirmed space forward', async () => {
    const attempts: RequestedSpaceAttempt[] = [];
    const outcomes = [failed('tinycloud_bootstrap_failed'), failed('tinycloud_bootstrap_node_timeout'), { status: 'complete' } as const];
    const result = await hostRequestedSpaceWithinBudget(async (attempt) => {
      attempts.push(attempt);
      if (attempt.attempt === 1) attempt.report({ status: 'hosted' });
      return outcomes[attempt.attempt - 1]!;
    }, { timeoutMs: 1000, retryDelaysMs: [0, 0, 0] });
    expect(result).toEqual({ status: 'hosted' });

    await until(() => output.length === 3);
    expect(attempts.map(({ attempt, alreadyHosted }) => [attempt, alreadyHosted])).toEqual([[1, false], [2, true], [3, true]]);
    expect(events().map((line) => [line.event, line.attempt, line.error_code ?? null])).toEqual([
      ['tinycloud_bootstrap_background_failed', 1, 'tinycloud_bootstrap_failed'],
      ['tinycloud_bootstrap_background_failed', 2, 'tinycloud_bootstrap_node_timeout'],
      ['tinycloud_bootstrap_background_completed', 3, null],
    ]);
  });

  test('stops after the last delay: the first run plus one retry per delay', async () => {
    const run = mock(async (): Promise<TinyCloudBootstrapOutcome> => failed('tinycloud_bootstrap_failed'));
    await hostRequestedSpaceWithinBudget(run, { timeoutMs: 1000, retryDelaysMs: [0, 0] });
    await until(() => output.length === 3);
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(run).toHaveBeenCalledTimes(3);
    expect(output).toHaveLength(3);
  });

  test('does not retry what a retry cannot fix, and leaves lock contention to the run holding it', async () => {
    for (const errorCode of ['tinycloud_bootstrap_expired_request', 'tinycloud_bootstrap_untrusted_host']) {
      output.length = 0;
      const run = mock(async (): Promise<TinyCloudBootstrapOutcome> => failed(errorCode));
      await hostRequestedSpaceWithinBudget(run, { timeoutMs: 1000, retryDelaysMs: [0, 0] });
      await until(() => output.length === 1);
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(run).toHaveBeenCalledTimes(1);
      expect(output).toHaveLength(1);
    }

    output.length = 0;
    const contended = mock(async (): Promise<TinyCloudBootstrapOutcome> => failed('tinycloud_bootstrap_in_progress'));
    expect(await hostRequestedSpaceWithinBudget(contended, { timeoutMs: 1000, retryDelaysMs: [0, 0] })).toEqual({ status: 'pending' });
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(contended).toHaveBeenCalledTimes(1);
    expect(output).toHaveLength(0);
  });

  test('reads its timeout and retry delays from the environment, with safe defaults', () => {
    for (const value of [undefined, '', 'abc', '-1', 'Infinity']) {
      expect(tinyCloudRequestedSpaceTimeoutMs({ TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS: value })).toBe(10_000);
    }
    expect(tinyCloudRequestedSpaceTimeoutMs({ TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS: '250' })).toBe(250);
    expect(tinyCloudRequestedSpaceTimeoutMs({ TINYCLOUD_BOOTSTRAP_REQUESTED_SPACE_TIMEOUT_MS: '3000000000' })).toBe(60_000);

    for (const value of [undefined, '', '  ', 'abc', '1,x', '5,-1', '1,,2']) {
      expect(tinyCloudBootstrapRetryDelaysMs({ TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS: value })).toEqual([5_000, 15_000, 45_000]);
    }
    expect(tinyCloudBootstrapRetryDelaysMs({ TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS: 'off' })).toEqual([]);
    expect(tinyCloudBootstrapRetryDelaysMs({ TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS: '10, 20' })).toEqual([10, 20]);
    expect(tinyCloudBootstrapRetryDelaysMs({ TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS: '1,2,3,4,5,6,7' })).toEqual([1, 2, 3, 4, 5]);
    expect(tinyCloudBootstrapRetryDelaysMs({ TINYCLOUD_BOOTSTRAP_RETRY_DELAYS_MS: '999999999' })).toEqual([300_000]);
  });
});
