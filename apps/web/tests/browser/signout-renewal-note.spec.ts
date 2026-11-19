// TC-2946: signing out leaves approved permissions renewing, so the sign-out buttons say so, but only when the
// account has renewing permissions. Every API call is answered by page.route.
import { test, expect, type Page, type Route } from '@playwright/test';
import { ORIGIN } from './e2e-port';

const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const session = { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'u', email: 'owner@example.test', name: 'Owner' } };
const lease = {
  leaseCid: 'bafkr4ilease', originalCid: 'bafkr4ioriginal', nodeOrigin: 'https://node.tinycloud.xyz', approvedAt: '2026-11-13T12:00:00.000Z',
  leaseExpiresAt: '2027-02-11T12:00:00.000Z', grantExpiresAt: '2026-12-13T12:00:00.000Z', signer: 'openkey', reason: 'Courier keeps your inbox in sync',
  grantSiwe: '',
};
const DASHBOARD_NOTE = 'Signing out doesn’t stop apps renewing the access you approved. Stop renewals';
const APP_NOTE = 'Signing out doesn’t stop apps renewing the access you approved. You can stop renewals in OpenKey Settings.';

async function setup(page: Page, leases: unknown[] | 'error') {
  await page.context().addCookies([{ name: 'better-auth.session_token', value: 'cookie-session', url: ORIGIN }]);
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, session);
    if (path === '/api/auth/providers') return json(route, { providers: [] });
    if (path === '/api/account/auto-sign') return json(route, { autoSignEnabled: false });
    if (path === '/api/account/renewal-leases') return leases === 'error' ? json(route, { error: 'unavailable' }, 503) : json(route, { leases });
    if (path === '/api/keys') return json(route, { keys: [] });
    if (path.includes('passkey/list-user-passkeys') || path.includes('list-accounts')) return json(route, []);
    if (path.includes('tinycloud')) return json(route, { tinyCloudManageKeyEnabled: true, mode: 'APP_MANAGED', policyEpoch: 0, apps: [], mcpApps: [], identityApps: [], activity: [] });
    return json(route, {});
  });
}

test('the dashboard says signing out leaves renewals on, and Stop renewals opens Renewing permissions', async ({ page }) => {
  await setup(page, [lease]);
  await page.goto('/dashboard');
  const note = page.getByTestId('sign-out-renewal-note');
  await expect(note).toHaveText(DASHBOARD_NOTE);
  await note.getByRole('link', { name: 'Stop renewals' }).click();
  await expect(page).toHaveURL(/\/dashboard\/settings#renewing-permissions$/);
  await expect(page.locator('#renewing-permissions')).toBeInViewport();
});

for (const [label, leases] of [['no renewing permissions', []], ['the list fails to load', 'error']] as const) {
  test(`the dashboard shows no sign-out note when ${label}`, async ({ page }) => {
    await setup(page, leases === 'error' ? 'error' : [...leases]);
    const listed = page.waitForResponse((response) => new URL(response.url()).pathname === '/api/account/renewal-leases');
    await page.goto('/dashboard');
    await listed;
    await expect(page.getByRole('button', { name: 'Sign Out' })).toBeVisible();
    await expect(page.getByTestId('sign-out-renewal-note')).toHaveCount(0);
  });
}

async function askToSignOut(page: Page) {
  // Loaded top-level, the embed page's parent is itself: the request comes from the configured origin and window.
  await page.goto(`/widget/embed/sign-out?origin=${encodeURIComponent(ORIGIN)}`);
  await expect(page.getByText('Preparing sign-out…')).toBeVisible();
  await page.evaluate((origin) => window.postMessage({ type: 'openkey:sign-out:request', requestId: 'r1', protocolVersion: 1 }, origin), ORIGIN);
  await expect(page.getByText('Sign out of OpenKey on this device?')).toBeVisible();
}

test('the in-app sign-out confirm says renewals continue when the account has renewing permissions', async ({ page }) => {
  await setup(page, [lease]);
  await askToSignOut(page);
  await expect(page.getByTestId('sign-out-renewal-note')).toHaveText(APP_NOTE);
});

test('the in-app sign-out confirm says nothing about renewals when none are renewing', async ({ page }) => {
  await setup(page, []);
  const listed = page.waitForResponse((response) => new URL(response.url()).pathname === '/api/account/renewal-leases');
  await askToSignOut(page);
  await listed;
  await expect(page.getByTestId('sign-out-renewal-note')).toHaveCount(0);
});
