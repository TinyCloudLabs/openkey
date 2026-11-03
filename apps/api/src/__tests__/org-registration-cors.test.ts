import { afterAll, beforeAll, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { PrismaClient } from '@openkey/db';

const root = resolve(import.meta.dir, '../../../..');
if (process.env.OPENKEY_REGISTRATION_CORS_CHILD !== '1') {
  test('actual API index isolates registration CORS from the existing credentialed policy', async () => {
    const child = Bun.spawn([process.execPath, '--no-env-file', 'test', import.meta.path], {
      cwd: root,
      env: { ...process.env, OPENKEY_REGISTRATION_CORS_CHILD: '1', NODE_ENV: 'test', TEE_MODE: 'development', BETTER_AUTH_URL: 'https://api.openkey.test', BETTER_AUTH_SECRET: 'registration-cors-isolated-fixture-secret', WEBAUTHN_RP_ID: 'openkey.so', WEBAUTHN_ORIGIN: 'https://openkey.so', CORS_ORIGIN: 'http://localhost:5173', ORG_KEY_CUSTODY_ENABLED: 'false', RESEND_API_KEY: '', GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '' },
      stdout: 'pipe', stderr: 'pipe',
    });
    const [stdout, stderr, code] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
    expect(code, stdout + stderr).toBe(0);
  }, 60_000);
} else {
  let directory: string;
  let prisma: PrismaClient;
  let app: { fetch(request: Request): Response | Promise<Response> };
  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'registration-cors-'));
    const engine = new PGlite(directory);
    try {
      const migrationRoot = join(root, 'packages/db/prisma/migrations');
      const names = (await readdir(migrationRoot, { withFileTypes: true })).filter(entry => entry.isDirectory()).map(entry => entry.name).sort();
      for (const name of names) await engine.exec(await readFile(join(migrationRoot, name, 'migration.sql'), 'utf8'));
    } finally { await engine.close(); }
    process.env.DATABASE_URL = `pglite:${directory}`;
    delete process.env.OPENKEY_DATABASE_SCHEMA;
    ({ prisma } = await import('../auth'));
    app = (await import('../index')).default;
  }, 30_000);
  afterAll(async () => { await prisma?.$disconnect(); if (directory) await rm(directory, { recursive: true, force: true }); });

  async function request(path: string, method: string, origin: string, preflightMethod?: string) {
    return app.fetch(new Request('https://api.openkey.test' + path, {
      method, headers: { origin, ...(preflightMethod ? { 'access-control-request-method': preflightMethod } : {}) },
    }));
  }
  test('registration POST and its preflight allow only the fixed OpenKey origin', async () => {
    for (const [method, requested] of [['POST', undefined], ['OPTIONS', 'POST']] as const) {
      const allowed = await request('/api/org-keys', method, 'https://openkey.so', requested);
      expect(allowed.headers.get('access-control-allow-origin')).toBe('https://openkey.so');
      expect(allowed.headers.get('access-control-allow-credentials')).toBe('true');
      for (const origin of ['http://localhost:5173', 'https://untrusted.example']) {
        expect((await request('/api/org-keys', method, origin, requested)).headers.get('access-control-allow-origin')).toBeNull();
      }
    }
    expect(await prisma.ethereumKey.count()).toBe(0);
  });
  test('GET, its preflight and signing paths retain the existing CORS policy', async () => {
    for (const [path, method, requested] of [
      ['/api/org-keys', 'GET', undefined], ['/api/org-keys', 'OPTIONS', 'GET'],
      ['/api/org-keys/fixture/sign', 'POST', undefined], ['/api/org-keys/fixture/sign', 'OPTIONS', 'POST'],
    ] as const) {
      const response = await request(path, method, 'http://localhost:5173', requested);
      expect(response.headers.get('access-control-allow-origin')).toBe('http://localhost:5173');
      expect(response.headers.get('access-control-allow-credentials')).toBe('true');
    }
  });
}
