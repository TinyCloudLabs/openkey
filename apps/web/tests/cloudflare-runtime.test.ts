// @ts-nocheck -- this production-worker check runs in Bun, outside the web client tsconfig.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { request } from 'node:http';
import { join } from 'node:path';

const appDirectory = join(import.meta.dir, '..');
const port = 8791;
let worker: ReturnType<typeof Bun.spawn>;

function fetchHost(host: string, path: string) {
  return new Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }>((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, headers: { host } }, (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { body += chunk; });
      response.on('end', () => resolve({ status: response.statusCode ?? 0, headers: response.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

async function waitForWorker() {
  let lastError: unknown;
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      await fetchHost('openkey.so', '/');
      return;
    } catch (error) {
      lastError = error;
      await Bun.sleep(250);
    }
  }
  throw lastError;
}

describe('Cloudflare Pages console host boundary', () => {
  beforeAll(async () => {
    worker = Bun.spawn([
      'wrangler', 'pages', 'dev', '.svelte-kit/cloudflare',
      '--port', String(port), '--ip', '127.0.0.1', '--log-level', 'error',
    ], { cwd: appDirectory, stdout: 'ignore', stderr: 'ignore' });
    await waitForWorker();
  }, 15_000);

  afterAll(() => worker?.kill());

  test('serves managed-account documents only through the account host', async () => {
    for (const path of ['/managed-accounts-architecture', '/managed-accounts-project']) {
      const consoleResponse = await fetchHost('console.openkey.so', path);
      expect(consoleResponse.status).toBe(404);
      expect(consoleResponse.body).toContain('Page not found');
      expect(consoleResponse.body).not.toContain('OpenKey managed accounts');

      const accountResponse = await fetchHost('openkey.so', path);
      expect(accountResponse.status).toBe(200);
      expect(accountResponse.headers['content-type']).toContain('text/html');
      expect(accountResponse.body).toContain('OpenKey managed accounts');

      // Static-era bookmarks are intentionally no longer documents on either
      // host. They still traverse the worker and cannot bypass the guard.
      await expect(fetchHost('console.openkey.so', `${path}/index.html`)).resolves.toMatchObject({ status: 404 });
      await expect(fetchHost('openkey.so', `${path}/index.html`)).resolves.toMatchObject({ status: 404 });
    }
  });

  test('keeps the console and account redirect contracts at the worker boundary', async () => {
    // Prove the public happy path at the same boundary that blocks account
    // pages. A host guard regression must not turn the console into a 404.
    for (const path of ['/console', '/console/org_123/apps?tab=active']) {
      const response = await fetchHost('console.openkey.so', path);
      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toContain('text/html');
    }
    await expect(fetchHost('openkey.so', '/dashboard')).resolves.toMatchObject({
      status: 200,
      headers: { 'content-type': expect.stringContaining('text/html') },
    });

    await expect(fetchHost('console.openkey.so', '/')).resolves.toMatchObject({
      status: 308,
      headers: { location: 'https://console.openkey.so/console' },
    });
    await expect(fetchHost('console.openkey.so', '/dashboard?q=1')).resolves.toMatchObject({
      status: 308,
      headers: { location: 'https://openkey.so/dashboard?q=1' },
    });
    await expect(fetchHost('console.openkey.so', '/auth/login')).resolves.toMatchObject({ status: 404 });
    await expect(fetchHost('console.openkey.so', '/dashboard/settings')).resolves.toMatchObject({
      status: 308,
      headers: { location: 'https://openkey.so/dashboard/settings' },
    });
    await expect(fetchHost('openkey.so', '/console/org_123/apps?tab=active')).resolves.toMatchObject({
      status: 308,
      headers: { location: 'https://console.openkey.so/console/org_123/apps?tab=active' },
    });
  });
});
