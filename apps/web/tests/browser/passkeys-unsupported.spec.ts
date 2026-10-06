// Clients that cannot use WebAuthn open OpenKey with `passkeys=false`; the
// sign-in screens must then offer only email and social sign-in. Every API
// call is answered by `page.route` with a signed-out session; no API server runs.

import { test, expect, type Page } from '@playwright/test';

const origin = encodeURIComponent('https://app.test');

async function signedOut(page: Page) {
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/auth/get-session') {
      return route.fulfill({ status: 200, contentType: 'application/json', body: 'null' });
    }
    if (url.pathname === '/api/auth/providers') {
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ providers: ['google'] }) });
    }
    return route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: `unmocked ${url.pathname}` }) });
  });
}

for (const path of ['/widget/embed/connect', '/widget/connect']) {
  test(`${path} offers passkeys by default`, async ({ page }) => {
    await signedOut(page);
    await page.goto(`${path}?origin=${origin}`);
    await expect(page.getByRole('button', { name: 'Continue with email' })).toBeVisible();
    await expect(page.getByRole('button', { name: /passkey/i })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Recover account' })).toBeVisible();
    await expect(page.getByTestId('passkeys-unavailable')).toHaveCount(0);
  });

  test(`${path} hides passkey options when passkeys=false`, async ({ page }) => {
    await signedOut(page);
    await page.goto(`${path}?origin=${origin}&passkeys=false`);
    await expect(page.getByRole('button', { name: 'Continue with email' })).toBeVisible();
    if (path === '/widget/embed/connect') {
      await expect(page.getByRole('button', { name: /Google/ })).toBeVisible();
    }
    await expect(page.getByRole('button', { name: /passkey/i })).toHaveCount(0);
    await expect(page.getByText('Register', { exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Recover account' })).toHaveCount(0);
    await expect(page.getByTestId('passkeys-unavailable')).toBeVisible();
  });
}

test('popup connect carries passkeys=false to the email sign-in page', async ({ page }) => {
  await signedOut(page);
  await page.goto(`/widget/connect?origin=${origin}&passkeys=false`);
  await page.getByRole('button', { name: 'Continue with email' }).click();
  await expect(page).toHaveURL(/\/auth\/login\?.*passkeys=false/);
  await expect(page.getByRole('button', { name: 'Continue with email' })).toBeVisible();
  await expect(page.getByRole('button', { name: /passkey/i })).toHaveCount(0);
});

test('login page offers passkeys by default', async ({ page }) => {
  await signedOut(page);
  await page.goto('/auth/login');
  await expect(page.getByRole('button', { name: 'Use a passkey instead' })).toBeVisible();
});
