// @ts-nocheck -- runs in Bun against a Vite dev server, outside the web client tsconfig.
// Run by api-tests.yml, step "Capability review and web lib tests" (`bun test ... apps/web/src/lib`).
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { join } from 'node:path';
import { createServer, type ViteDevServer } from 'vite';
// Forces the Terms release on in the dev server, so the result does not depend on terms-release.json.
// The dev server only reads the shipped Terms release when this says so; the test does not depend on the release file; the first test fails when the server renders the shell.
process.env.VITE_OPENKEY_TERMS_RELEASE = 'on';

let server: ViteDevServer;
let base: string;

beforeAll(async () => {
  server = await createServer({ root: join(import.meta.dir, '../..'), logLevel: 'silent', server: { port: 0, host: '127.0.0.1' } });
  await server.listen();
  base = `http://127.0.0.1:${server.httpServer.address().port}`;
}, 120_000);

afterAll(async () => {
  await server?.close();
});

describe('server-rendered /dashboard', () => {
  test('holds the loading state until the session read answers, without the signed-in shell', async () => {
    const response = await fetch(`${base}/dashboard`, { headers: { accept: 'text/html' } });
    const html = await response.text();

    expect(html).toContain('data-testid="terms-checking"');
    expect(html).toContain('Loading');
    for (const shellText of ['Your Keys', 'Connected apps', 'Secrets &amp; Variables', 'Secrets & Variables', 'Sign Out', 'Welcome back']) {
      expect(html).not.toContain(shellText);
    }
  }, 120_000);
});
