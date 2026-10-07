import { expect, test } from 'bun:test';
import { randomUUID } from 'node:crypto';
import { nativeDelegationLockResponse, nativeDelegationSqlState } from '../services/native-delegation/errors';
import { parRetryAfter } from '../services/native-delegation/par';

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

test('PAR limits each client and IP independently', () => {
  const id = randomUUID();
  const now = 1_000_000;
  for (let i = 0; i < 60; i++) expect(parRetryAfter(`client-a-${id}`, `ip-${id}`, now)).toBe(0);
  expect(parRetryAfter(`client-a-${id}`, `ip-${id}`, now)).toBe(60);
  expect(parRetryAfter(`client-b-${id}`, `other-ip-${id}`, now)).toBe(0);
  for (let i = 0; i < 119; i++) expect(parRetryAfter(`client-c-${id}`, `new-ip-${id}-${i}`, now)).toBe(0);
  expect(parRetryAfter(`client-c-${id}`, `last-ip-${id}`, now)).toBe(0);
  expect(parRetryAfter(`client-c-${id}`, `overflow-ip-${id}`, now)).toBe(60);
  expect(parRetryAfter(`client-a-${id}`, `ip-${id}`, now + 60_000)).toBe(0);
});
