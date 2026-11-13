import { afterAll, beforeAll, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { PrismaClient } from '@openkey/db';

// TC-128 OK-1 test 10 through the real API index: the owner-check route is server-to-server and must
// not inherit the credentialed CORS policy that every other path gets.
const root = resolve(import.meta.dir, '../../../..');
if (process.env.OPENKEY_OWNER_CHECK_CORS_CHILD !== '1') {
  test('actual API index serves the owner-check route with no CORS headers', async () => {
    const child = Bun.spawn([process.execPath, '--no-env-file', 'test', import.meta.path], {
      cwd: root,
      env: { ...process.env, OPENKEY_OWNER_CHECK_CORS_CHILD: '1', NODE_ENV: 'test', TEE_MODE: 'development', BETTER_AUTH_URL: 'https://api.openkey.test', BETTER_AUTH_SECRET: 'owner-check-cors-isolated-fixture-secret', WEBAUTHN_RP_ID: 'openkey.so', WEBAUTHN_ORIGIN: 'https://openkey.so', CORS_ORIGIN: 'http://localhost:5173', ORG_KEY_CUSTODY_ENABLED: 'true', RESEND_API_KEY: '', GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '' },
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
    directory = await mkdtemp(join(tmpdir(), 'owner-check-cors-'));
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

  function request(path: string, method: string, origin: string, preflightMethod?: string) {
    return app.fetch(new Request('https://api.openkey.test' + path, {
      method, headers: { origin, ...(preflightMethod ? { 'access-control-request-method': preflightMethod } : {}) },
    }));
  }
  function corsHeaders(response: Response): string[] {
    return [...response.headers.keys()].filter((name) => name.toLowerCase().startsWith('access-control-'));
  }
  test('POST and its preflight carry no Access-Control-* header for any browser Origin', async () => {
    // Control: the same Origin on another path still gets the credentialed policy, so this test can fail.
    expect((await request('/api/org-keys', 'GET', 'http://localhost:5173')).headers.get('access-control-allow-origin')).toBe('http://localhost:5173');
    expect((await request('/api/internal/metrics', 'GET', 'http://localhost:5173')).headers.get('access-control-allow-origin')).toBe('http://localhost:5173');
    for (const origin of ['http://localhost:5173', 'https://openkey.so', 'https://credentials.org', 'https://untrusted.example']) {
      const post = await request('/api/internal/org-owner-check', 'POST', origin);
      expect(post.status).toBe(401);
      expect(corsHeaders(post)).toEqual([]);
      const preflight = await request('/api/internal/org-owner-check', 'OPTIONS', origin, 'POST');
      expect(corsHeaders(preflight)).toEqual([]);
    }
    // The route is read-only.
    expect(await prisma.keyGrant.count()).toBe(0);
  });
}
