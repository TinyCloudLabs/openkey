import { expect, test, type Page, type Route } from '@playwright/test';

const sessionBody = {
  session: { id: 'session-1', userId: 'user-1', expiresAt: new Date(Date.now() + 3_600_000).toISOString() },
  user: { id: 'user-1', email: 'owner@example.test', name: 'Owner' },
};
const identityApp = {
  kind: 'identity', consentId: 'identity-consent-1', clientId: 'identity-client-1', name: 'Address Viewer',
  uri: 'https://viewer.example.test/app', host: 'viewer.example.test', icon: null,
  connectedAt: '2026-10-20T12:00:00.000Z', scopes: ['openid', 'email', 'tinycloud:identity'],
};
const json = (route: Route, body: unknown, status = 200) => route.fulfill({
  status, contentType: 'application/json', body: JSON.stringify(body),
});

async function openConsent(page: Page, scopes: string) {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith('/get-session')) return json(route, sessionBody);
    if (path.endsWith('/oauth2/public-client')) return json(route, { client_name: 'Sample App' });
    return json(route, {});
  });
  await page.goto(`/oauth/consent?client_id=sample-client&scope=${encodeURIComponent(scopes)}&sig=test`);
  await expect(page.getByRole('heading', { name: 'Sample App' })).toBeVisible();
}

test('identity-only consent explains address access without signing access', async ({ page }) => {
  await openConsent(page, 'openid email tinycloud:identity');
  await expect(page.getByText('See your OpenKey wallet address', { exact: true })).toBeVisible();
  await expect(page.getByText("This app can't sign anything or use your TinyCloud data.", { exact: true })).toBeVisible();
  await expect(page.getByText(/Silently request TinyCloud delegation signatures/)).toHaveCount(0);
});

test('identity plus manage-key shows both rows and no identity-only reassurance', async ({ page }) => {
  await openConsent(page, 'openid email tinycloud:identity tinycloud:manage-key');
  await expect(page.getByText('See your OpenKey wallet address', { exact: true })).toBeVisible();
  await expect(page.getByText(/Silently request TinyCloud delegation signatures/)).toBeVisible();
  await expect(page.getByText("This app can't sign anything or use your TinyCloud data.", { exact: true })).toHaveCount(0);
});

test('manage-key-only consent remains unchanged', async ({ page }) => {
  await openConsent(page, 'openid email tinycloud:manage-key');
  await expect(page.getByText('See your OpenKey wallet address', { exact: true })).toHaveCount(0);
  await expect(page.getByText(/Silently request TinyCloud delegation signatures/)).toBeVisible();
  await expect(page.getByText("This app can't sign anything or use your TinyCloud data.", { exact: true })).toHaveCount(0);
});
test('identity consent with keys requested does not show identity-only reassurance', async ({ page }) => {
  await openConsent(page, 'openid email tinycloud:identity keys');
  await expect(page.getByText('See your OpenKey wallet address', { exact: true })).toBeVisible();
  await expect(page.getByText("This app can't sign anything or use your TinyCloud data.", { exact: true })).toHaveCount(0);
});

test('identity app settings show the connected app and one-step disconnect dialog', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  let identityApps: typeof identityApp[] = [identityApp];
  let disconnectBody: unknown;
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path.endsWith('/get-session')) return json(route, sessionBody);
    if (path.endsWith('/list-user-passkeys')) return json(route, { data: [] });
    if (path === '/api/keys') return json(route, { keys: [] });
    if (path === '/api/account/auto-sign') return json(route, { autoSignEnabled: false });
    if (path === '/api/account/tinycloud-manage-key') return json(route, {
      tinyCloudManageKeyEnabled: true, mode: 'APP_MANAGED', policyEpoch: 0,
    });
    if (path === '/api/account/tinycloud-apps' && request.method() === 'GET') return json(route, {
      apps: [], mcpApps: [], identityApps, activity: [], mode: 'APP_MANAGED', policyEpoch: 0,
    });
    if (path === '/api/account/tinycloud-apps/identity/identity-consent-1' && request.method() === 'DELETE') {
      disconnectBody = request.postDataJSON();
      identityApps = [];
      return json(route, { consentId: 'identity-consent-1', disconnected: true });
    }
    return json(route, {});
  });

  await page.goto('/dashboard/settings');
  const section = page.locator('#connected-identity-apps');
  await expect(section.getByRole('heading', { name: 'Apps that can see your wallet address' })).toBeVisible();
  await expect(section).toContainText("These apps can see your OpenKey wallet address. They can't sign anything or use your TinyCloud data. Disconnect an app to stop it.");
  await expect(section).toContainText('Address Viewer');
  await expect(section).toContainText('viewer.example.test');
  await expect(section.locator('time')).toHaveAttribute('datetime', identityApp.connectedAt);

  await section.getByRole('button', { name: 'Disconnect Address Viewer' }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByRole('heading', { name: 'Disconnect Address Viewer?' })).toBeVisible();
  await expect(dialog).toContainText("The app won't be able to see your wallet address again. It can ask you to connect again later.");
  await expect(dialog.getByRole('button', { name: 'Cancel' })).toBeVisible();
  await expect(dialog.getByRole('button', { name: 'Disconnect app' })).toBeVisible();
  await expect(dialog.locator('input')).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Disconnect app' }).click();
  await expect(page.getByRole('status')).toHaveText("Disconnected. Within 5 minutes the app can't get your wallet address again. It may keep the address it already has.");
  expect(disconnectBody).toEqual({ confirmation: 'DISCONNECT' });
  await expect(page.locator('#connected-identity-apps')).toHaveCount(0);
});
