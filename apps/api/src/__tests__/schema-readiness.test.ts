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

async function requestHealthOverHttp(rows: MigrationRecord[]) {
  const server = Bun.serve({
    port: 0,
    fetch: healthApp(rows).fetch,
  });

  try {
    return await fetch(`http://127.0.0.1:${server.port}/health`);
  } finally {
    server.stop(true);
  }
}

test('readiness HTTP path returns non-2xx for a controlled required migration mismatch without secrets', async () => {
  const response = await requestHealthOverHttp([{ ...validRows[0]!, checksum: 'controlled-mismatch' }, ...validRows.slice(1)]);
  expect(response.status).toBe(503);
  expect(await response.json()).toEqual({ status: 'not_ready' });
});

test('readiness HTTP path returns 200 for a valid required migration contract', async () => {
  const response = await requestHealthOverHttp(validRows);
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({ status: 'ok', tee: 'development' });
});
