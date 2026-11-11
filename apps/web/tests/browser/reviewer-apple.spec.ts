import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { ORIGIN } from './e2e-port';

test('native review code and fresh-browser account deletion use the dedicated screens at 390px', async ({ page }) => {
  test.setTimeout(90_000);
  const home = await mkdtemp(join(tmpdir(), 'openkey-apple-browser-'));
  const root = resolve(import.meta.dirname, '../../../..');
  const child = spawn('bun', ['--no-env-file', 'apps/api/src/__tests__/fixtures/reviewer-apple-browser.ts'], {
    cwd: root, env: { PATH: process.env.PATH, HOME: home, OPENKEY_BROWSER_ORIGIN: ORIGIN }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stderr.resume();
  try {
    const fixture = await new Promise<{ api: string; loginQuery: string }>((resolveReady, reject) => {
      let buffer = '';
      child.once('error', reject);
      child.once('exit', () => reject(new Error('Apple reviewer browser fixture exited before ready')));
      child.stdout.on('data', chunk => {
        buffer += String(chunk);
        if (!buffer.includes('\n')) return;
        const value = JSON.parse(buffer.slice(0, buffer.indexOf('\n')));
        if (value.error) reject(new Error(value.error));
        else resolveReady(value);
      });
    });
    let otpSend = 0;
    let deletionIntent = 0;
    await page.route('**/api/**', async route => {
      const request = route.request();
      const url = new URL(request.url());
      if (url.pathname.includes('send-verification-otp')) otpSend++;
      if (url.pathname === '/api/review-account/delete-intent') deletionIntent++;
      const headers = await request.allHeaders();
      delete headers.host;
      const response = await route.fetch({ url: fixture.api + url.pathname + url.search, headers });
      await route.fulfill({ response });
    });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/auth/login?' + fixture.loginQuery);
    await expect(page.getByRole('heading', { name: 'Sign in to TinyCloud Home', exact: true })).toBeVisible();
    await expect(page.getByLabel('Review code', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
    await expect(page.getByText('Enter the review code for appreview@tinycloud.xyz.')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Use a different email' })).toBeVisible();
    await expect(page.getByRole('button', { name: /Resend/ })).toHaveCount(0);
    expect(await page.getByLabel('Review code', { exact: true }).getAttribute('type')).toBe('password');
    expect(otpSend).toBe(0);
    const shots = process.env.OPENKEY_REVIEWER_CAPTURE_DIR;
    if (shots) { await mkdir(shots, { recursive: true }); await page.screenshot({ path: join(shots, 'apple-native-390.png'), fullPage: true }); }
    // No native-sheet cookie is copied into the fresh deletion browser path.
    await page.context().clearCookies();
    await page.goto('/dashboard/settings/delete-account');
    await expect(page).toHaveURL(/\/auth\/login\?redirect=/);
    await page.getByLabel('Email address', { exact: true }).fill('appreview@tinycloud.xyz');
    await page.getByRole('button', { name: 'Continue with email', exact: true }).click();
    await expect(page).toHaveURL(/\/auth\/review\/delete$/);
    await expect(page.getByLabel('Review account', { exact: true })).toBeVisible();
    await expect(page.getByLabel('Review code', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Verify and delete account' })).toBeDisabled();
    await expect.poll(() => deletionIntent).toBe(1);
    await expect(page.getByRole('alert')).toHaveCount(0);
    expect(otpSend).toBe(0);
    if (shots) await page.screenshot({ path: join(shots, 'apple-delete-390.png'), fullPage: true });
  } finally {
    child.kill('SIGTERM');
    if (child.exitCode === null) await new Promise<void>(done => child.once('exit', () => done()));
    await rm(home, { recursive: true, force: true });
  }
});
