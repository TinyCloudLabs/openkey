import { expect, test } from 'bun:test';
import { randomUUID } from 'node:crypto';
import { nativeDelegationLockResponse, nativeDelegationSqlState } from '../services/native-delegation/errors';
import { createParLimiter } from '../services/native-delegation/par';

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

test('PAR limits validated clients and the global flow without IP headers', () => {
  const id = randomUUID();
  const limiter = createParLimiter(3, 5, 2);
  const now = 1_000_000;
  for (let i = 0; i < 3; i++) expect(limiter.retryAfter(`client-a-${id}`, now)).toBe(0);
  expect(limiter.retryAfter(`client-a-${id}`, now)).toBe(60);
  expect(limiter.retryAfter(`client-b-${id}`, now)).toBe(0);
  expect(limiter.retryAfter(`client-c-${id}`, now)).toBe(0);
  expect(limiter.clientBucketCount()).toBe(2);
  expect(limiter.retryAfter(`client-d-${id}`, now)).toBe(60);
  expect(limiter.retryAfter(`client-d-${id}`, now + 60_000)).toBe(0);
  expect(limiter.clientBucketCount()).toBeLessThanOrEqual(2);
});
