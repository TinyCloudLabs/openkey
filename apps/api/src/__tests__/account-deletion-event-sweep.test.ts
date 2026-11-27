import { afterEach, expect, jest, test } from 'bun:test';
import { sweepAccountDeletionEventsOnce, startAccountDeletionEventSweep } from '../services/account-deletion-event-sweep';
import {
  ACCOUNT_DELETION_EVENT_RETENTION_DAYS,
  ACCOUNT_DELETION_EVENT_SWEEP_FIRST_PASS_DELAY_MS,
  ACCOUNT_DELETION_EVENT_SWEEP_INTERVAL_MS,
} from '../services/account-deletion-event';

const NOW = new Date('2026-11-27T00:00:00.000Z');
const day = 86_400_000;

afterEach(() => { jest.useRealTimers(); });

test('the sweep deletes events strictly older than 60 days', async () => {
  const wheres: Array<{ deletedAt: { lt: Date } }> = [];
  const db = { accountDeletionEvent: { deleteMany: async ({ where }: { where: { deletedAt: { lt: Date } } }) => { wheres.push(where); return { count: 3 }; } } };
  expect(ACCOUNT_DELETION_EVENT_RETENTION_DAYS).toBe(60);
  expect(await sweepAccountDeletionEventsOnce(db as never, () => NOW)).toBe(3);
  expect(wheres).toEqual([{ deletedAt: { lt: new Date(NOW.getTime() - 60 * day) } }]);
});

test('a failing pass is logged by class and neither throws nor stops the next pass', async () => {
  jest.useFakeTimers();
  let attempts = 0;
  const db = { accountDeletionEvent: { deleteMany: async () => { attempts++; throw Object.assign(new Error('0x' + 'ab'.repeat(20) + ' secret detail'), { code: 'P2010' }); } } };
  const lines: string[] = [];
  const originalWrite = process.stdout.write;
  process.stdout.write = ((chunk: unknown) => { lines.push(String(chunk)); return true; }) as typeof process.stdout.write;
  const stop = startAccountDeletionEventSweep(db as never);
  try {
    jest.advanceTimersByTime(ACCOUNT_DELETION_EVENT_SWEEP_FIRST_PASS_DELAY_MS);
    await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
    jest.advanceTimersByTime(ACCOUNT_DELETION_EVENT_SWEEP_INTERVAL_MS);
    await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
  } finally {
    stop();
    process.stdout.write = originalWrite;
  }
  expect(attempts).toBeGreaterThanOrEqual(2);
  const output = lines.join('');
  expect(output).toContain('account_deletion_event_sweep_failed');
  expect(output).not.toContain('secret detail');
  expect(output).not.toMatch(/0x[0-9a-f]{40}/i);
});
