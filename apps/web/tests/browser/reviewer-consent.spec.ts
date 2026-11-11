import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { ORIGIN } from './e2e-port';

test('the hosted consent page loads bound public metadata with a real reviewer cookie', async ({ page, context }) => {
  test.setTimeout(90_000);
  const home = await mkdtemp(join(tmpdir(), 'openkey-reviewer-browser-'));
  const root = resolve(import.meta.dirname, '../../../..');
  const child = spawn('bun', ['apps/api/src/__tests__/fixtures/reviewer-consent-browser.ts'], {
    cwd: root, env: { PATH: process.env.PATH, HOME: home, OPENKEY_BROWSER_ORIGIN: ORIGIN },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stderr.resume();
  try {
    const fixture = await new Promise<{ api: string; clientId: string; cookie: string; consentQuery: string }>((resolveReady, reject) => {
      let buffer = '';
      child.once('error', reject);
      child.once('exit', () => reject(new Error('Reviewer browser fixture exited before ready')));
      child.stdout.on('data', (chunk) => {
        buffer += String(chunk);
        if (!buffer.includes('\n')) return;
        const value = JSON.parse(buffer.slice(0, buffer.indexOf('\n')));
        if (value.error) reject(new Error(value.error));
        else resolveReady(value);
      });
    });
    const separator = fixture.cookie.indexOf('=');
    await context.addCookies([{ name: fixture.cookie.slice(0, separator), value: fixture.cookie.slice(separator + 1),
      url: ORIGIN, httpOnly: true, sameSite: 'Lax' }]);
    let metadataCookie = false;
    await page.route('**/api/**', async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      const headers = await request.allHeaders();
      delete headers.host;
      if (url.pathname === '/api/auth/oauth2/public-client') metadataCookie = (headers.cookie ?? '').includes(fixture.cookie);
      const response = await route.fetch({ url: fixture.api + url.pathname + url.search, headers });
      await route.fulfill({ response });
    });
    await page.goto('/oauth/consent?' + fixture.consentQuery);
    await expect(page.getByRole('heading', { name: 'Reviewer consent fixture' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Allow', exact: true })).toBeEnabled();
    expect(metadataCookie).toBe(true);
    const results = await page.evaluate(async (clientId) => {
      const read = async (id: string) => {
        const response = await fetch('/api/auth/oauth2/public-client?client_id=' + encodeURIComponent(id), { credentials: 'include' });
        return { status: response.status, body: await response.json() };
      };
      return { bound: await read(clientId), other: await read('another-client') };
    }, fixture.clientId);
    expect(results.bound.status).toBe(200);
    expect(results.other.status).toBe(403);
    expect(results.bound.body.client_id).toBe(fixture.clientId);
    expect(Object.keys(results.bound.body).every((key) => ['client_id', 'client_name', 'client_uri', 'contacts', 'logo_uri', 'tos_uri', 'policy_uri', 'redirect_uris'].includes(key))).toBe(true);
    expect(results.bound.body.redirect_uris).toEqual([]);
    expect(JSON.stringify(results.bound.body)).not.toContain('synthetic-private-client-field');
  } finally {
    child.kill('SIGTERM');
    if (child.exitCode === null) await new Promise<void>((done) => child.once('exit', () => done()));
    await rm(home, { recursive: true, force: true });
  }
});
