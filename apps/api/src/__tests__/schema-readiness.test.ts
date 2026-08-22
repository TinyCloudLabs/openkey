import { expect, test } from 'bun:test';
import { Hono } from 'hono';
import { requiredRuntimeMigrationChecksums, type MigrationRecord } from '@openkey/db';

import { checkApiReadiness, readinessHandler } from '../readiness';

const validRows: MigrationRecord[] = [...requiredRuntimeMigrationChecksums].map(([migration_name, checksum]) => ({
  migration_name,
  checksum,
  finished_at: new Date('2026-08-22T00:00:00.000Z'),
  rolled_back_at: null,
}));

function healthApp(rows: MigrationRecord[]) {
  const app = new Hono();
  app.get('/health', readinessHandler(() => checkApiReadiness({
    $queryRawUnsafe: async <T>() => rows as T,
  })));
  return app;
}

test('readiness HTTP path returns non-2xx for a controlled required migration mismatch without secrets', async () => {
  const response = await healthApp([{ ...validRows[0]!, checksum: 'controlled-mismatch' }, ...validRows.slice(1)]).request('/health');
  expect(response.status).toBe(503);
  expect(await response.json()).toEqual({ status: 'not_ready' });
});

test('readiness HTTP path returns 200 for a valid required migration contract', async () => {
  const response = await healthApp(validRows).request('/health');
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({ status: 'ok', tee: 'development' });
});
