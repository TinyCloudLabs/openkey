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

async function requestHealthOverHttp(rows: MigrationRecord[], path = '/health', headers?: HeadersInit) {
  const server = Bun.serve({
    hostname: '127.0.0.1',
    port: 0,
    fetch: healthApp(rows).fetch,
  });

  try {
    return await fetch(`http://127.0.0.1:${server.port}${path}`, { headers });
  } finally {
    server.stop(true);
  }
}

test('readiness HTTP path returns non-2xx for a controlled required migration mismatch without secrets', async () => {
  const response = await requestHealthOverHttp([{ ...validRows[0]!, checksum: 'controlled-mismatch' }, ...validRows.slice(1)]);
  expect(response.status).toBe(503);
  expect(await response.json()).toEqual({ status: 'not_ready' });
});

for (const mode of ['development', 'production'] as const) {
  test(`readiness HTTP path reports ${mode} client mode without claiming an OS image`, async () => {
    const savedMode = process.env.TEE_MODE;
    const savedNodeEnv = process.env.NODE_ENV;
    process.env.TEE_MODE = mode;
    process.env.NODE_ENV = mode === 'production' ? 'production' : 'test';
    try {
      const response = await requestHealthOverHttp(
        validRows,
        '/health?tee_mode=development&os_image=dstack-0.5.5',
        { 'X-OS-Image': 'dstack-0.5.5', 'X-TEE-Mode': 'development' },
      );
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ status: 'ok', tee_mode: mode, os_image: 'unknown' });
    } finally {
      if (savedMode === undefined) delete process.env.TEE_MODE;
      else process.env.TEE_MODE = savedMode;
      if (savedNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = savedNodeEnv;
    }
  });
}
