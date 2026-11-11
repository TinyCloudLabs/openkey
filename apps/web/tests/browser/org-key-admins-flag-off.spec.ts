import { expect, test } from '@playwright/test';
import { ORIGIN } from './e2e-port';

test('organisation admin pages remain unavailable on the default flag-off server', async ({ page }) => {
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.origin !== ORIGIN) { await route.abort(); return; }
    if (url.pathname.startsWith('/api/')) { await route.fulfill({ status: 401, json: {} }); return; }
    await route.continue();
  });
  for (const path of ['/dashboard/org-keys/example/admins', '/org-key-invitations/example']) {
    const response = await page.goto(path);
    expect(response?.status()).toBe(404);
  }
});
