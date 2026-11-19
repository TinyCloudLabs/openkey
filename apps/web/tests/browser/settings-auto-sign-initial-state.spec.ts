import { test, expect, type Route } from '@playwright/test';
import { ORIGIN } from './e2e-port';

const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const session = { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'u', email: 'owner@example.test', name: 'Owner' } };

async function setup(page: import('@playwright/test').Page) {
  await page.context().addCookies([{ name: 'better-auth.session_token', value: 'cookie-session', url: ORIGIN }]);
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, session);
    if (path === '/api/auth/providers') return json(route, { providers: [] });
    if (path === '/api/account/auto-sign' && route.request().method() === 'GET') return json(route, { autoSignEnabled: true });
    if (path === '/api/account/auto-sign' && route.request().method() === 'PATCH') return json(route, { autoSignEnabled: (route.request().postDataJSON() as { autoSignEnabled: boolean }).autoSignEnabled });
    if (path === '/api/keys') return json(route, { keys: [] });
    if (path.includes('passkey/list-user-passkeys')) return json(route, []);
    if (path.includes('tinycloud')) return json(route, { tinyCloudManageKeyEnabled: true, mode: 'APP_MANAGED', policyEpoch: 0, apps: [], activity: [] });
    return json(route, {});
  });
}

test('Auto-Sign is neutral while loading, then shows loaded OFF', async ({ page }) => {
  await setup(page);
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  await page.route('**/api/account/auto-sign', async (route) => {
    if (route.request().method() === 'GET') { await held; return json(route, { autoSignEnabled: false }); }
    return json(route, {});
  });
  await page.goto('/dashboard/settings');
  const toggle = page.getByRole('switch', { name: 'Toggle Auto-Sign' });
  await expect(toggle).not.toHaveAttribute('aria-checked', 'true');
  await expect(toggle).toBeDisabled();
  // Neither status word is claimed while the value is unknown.
  await expect(page.getByText('Enabled', { exact: true })).toHaveCount(0);
  await expect(page.getByText('Disabled', { exact: true })).toHaveCount(0);
  release();
  await expect(toggle).toHaveAttribute('aria-checked', 'false');
  await expect(toggle).toBeEnabled();
});

test('failed Auto-Sign load stays neutral and can retry', async ({ page }) => {
  await setup(page);
  let attempts = 0;
  await page.route('**/api/account/auto-sign', (route) => {
    if (route.request().method() === 'GET') return json(route, ++attempts === 1 ? { error: 'load failed' } : { autoSignEnabled: false }, attempts === 1 ? 500 : 200);
    return json(route, {});
  });
  await page.goto('/dashboard/settings');
  const toggle = page.getByRole('switch', { name: 'Toggle Auto-Sign' });
  await expect(toggle).not.toHaveAttribute('aria-checked', 'true');
  await expect(toggle).toBeDisabled();
  await expect(page.getByText('load failed')).toBeVisible();
  await expect(page.getByText('Enabled', { exact: true })).toHaveCount(0);
  await expect(page.getByText('Disabled', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Try again' }).click();
  await expect(toggle).toHaveAttribute('aria-checked', 'false');
  await expect(toggle).toBeEnabled();
});

test('loaded Auto-Sign can still toggle with mocked PATCH', async ({ page }) => {
  await setup(page);
  await page.goto('/dashboard/settings');
  const toggle = page.getByRole('switch', { name: 'Toggle Auto-Sign' });
  await expect(toggle).toHaveAttribute('aria-checked', 'true');
  await toggle.click();
  await expect(toggle).toHaveAttribute('aria-checked', 'false');
});

test('a failed Auto-Sign load can still be retried after the page error is dismissed', async ({ page }) => {
  await setup(page);
  let attempts = 0;
  await page.route('**/api/account/auto-sign', (route) => {
    if (route.request().method() === 'GET') return json(route, ++attempts === 1 ? { error: 'load failed' } : { autoSignEnabled: true }, attempts === 1 ? 500 : 200);
    return json(route, {});
  });
  await page.goto('/dashboard/settings');
  const toggle = page.getByRole('switch', { name: 'Toggle Auto-Sign' });
  await expect(page.getByText('load failed')).toBeVisible();
  // Dismissing the shared page message (or any other action that clears it) must not strand the switch.
  await page.getByText('load failed').locator('button').click();
  await expect(page.getByText('load failed')).toHaveCount(0);
  await expect(toggle).toBeDisabled();
  await page.getByRole('button', { name: 'Try again' }).click();
  await expect(toggle).toHaveAttribute('aria-checked', 'true');
  await expect(toggle).toBeEnabled();
});
