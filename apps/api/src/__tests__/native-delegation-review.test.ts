import { expect, test } from 'bun:test';
import { randomUUID } from 'node:crypto';
import { nativeDelegationLockResponse, nativeDelegationSqlState } from '../services/native-delegation/errors';
import { createParBackstop } from '../services/native-delegation/par';
import { createNativeUserLimiter } from '../services/native-delegation/user-rate-limit';

test('Prisma driver adapter lock SQLSTATE maps to 503 with retry', async () => {
  const error = { code: 'P2010', meta: { driverAdapterError: { cause: { code: '55P03' } } } };
  expect(nativeDelegationSqlState(error)).toBe('55P03');
  const response = nativeDelegationLockResponse(error)!;
  expect(response.status).toBe(503);
  expect(response.headers.get('Retry-After')).toBe('2');
  expect(await response.json()).toEqual({ error: 'temporarily_unavailable' });
  expect(nativeDelegationLockResponse({ code: 'P2010', meta: { driverAdapterError: { cause: { code: '40P01' } } } })?.status).toBe(503);
  expect(nativeDelegationLockResponse({ code: 'P2002' })).toBeNull();
});

test('PAR global storage backstop alerts once and resets without a client budget', () => {
  const alerts: number[] = [];
  const retryAfter = createParBackstop(3, limit => alerts.push(limit));
  const now = 1_000_000;
  for (let i = 0; i < 3; i++) expect(retryAfter(now)).toBe(0);
  expect(retryAfter(now)).toBe(60);
  expect(retryAfter(now)).toBe(60);
  expect(alerts).toEqual([3]);
  expect(retryAfter(now + 60_000)).toBe(0);
});

test('authenticated native steps have separate per-user budgets', () => {
  const id = randomUUID();
  const retryAfter = createNativeUserLimiter({ authorize: 2, prepare: 2, approve: 1, deny: 1 });
  const now = 1_000_000;
  expect(retryAfter(id, 'prepare', now)).toBe(0);
  expect(retryAfter(id, 'prepare', now)).toBe(0);
  expect(retryAfter(id, 'prepare', now)).toBe(60);
  expect(retryAfter(id, 'approve', now)).toBe(0);
  expect(retryAfter(id, 'approve', now)).toBe(60);
  expect(retryAfter(id, 'deny', now)).toBe(0);
  expect(retryAfter(`${id}-other`, 'prepare', now)).toBe(0);
  expect(retryAfter(id, 'prepare', now + 60_000)).toBe(0);
});
