import { test, expect, type Route } from '@playwright/test';
import { ORIGIN } from './e2e-port';

// TC-3442: while the "Passkey for approvals" card is hidden, Settings neither shows it nor reads the setting.
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const session = { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'u', email: 'owner@example.test', name: 'Owner' } };

test('Settings shows no "Passkey for approvals" card and does not read the setting', async ({ page }) => {
  const settingReads: string[] = [];
  await page.context().addCookies([{ name: 'better-auth.session_token', value: 'cookie-session', url: ORIGIN }]);
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, session);
    if (path === '/api/auth/providers') return json(route, { providers: [] });
    if (path === '/api/keys') return json(route, { keys: [] });
    if (path.includes('passkey/list-user-passkeys')) return json(route, [{ id: 'pk-1', name: 'Laptop', deviceType: 'singleDevice', createdAt: new Date().toISOString() }]);
    if (path.startsWith('/api/account/passkey-approval')) {
      settingReads.push(path);
      return json(route, { mode: 'SENSITIVE', effectiveMode: 'SENSITIVE', stepUpPasskeys: 1 });
    }
    if (path.includes('tinycloud')) return json(route, { tinyCloudManageKeyEnabled: true, mode: 'APP_MANAGED', policyEpoch: 0, apps: [], activity: [] });
    return json(route, {});
  });
  await page.goto('/dashboard/settings');
  await expect(page.getByText('Laptop')).toBeVisible();
  await expect(page.getByText('Account bootstrap auto-sign')).toBeVisible();
  await expect(page.locator('#passkey-approvals')).toHaveCount(0);
  await expect(page.getByText('Passkey for approvals')).toHaveCount(0);
  expect(settingReads).toEqual([]);
});
