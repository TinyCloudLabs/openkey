// TC-2946: Renewing permissions in Settings, and the dashboard's sign-out report, against a mocked API.
// Set TC2946_SHOTS_DIR to save screenshots at 390 and 1280 px.
import { test, expect, type Page, type Route } from '@playwright/test';
import { FIXTURE_META, makeRecapResource, siweWithResources } from '../../../../packages/capability-review/test/fixtures/index';
import { ORIGIN } from './e2e-port';

const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const session = { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'u', email: 'owner@example.test', name: 'Owner' } };
const OWNER = '0x1111111111111111111111111111111111111111';
const space = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:default`;
/** A signed grant as the approval screen saw it: its rows come from the same statements. */
const grant = (att: Record<string, Record<string, unknown[]>>) => siweWithResources([makeRecapResource(att)]);
const KV_GRANT = grant({ [`${space}/kv/courier/`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/put': [{}] } });
const lease = (leaseCid: string, overrides: Record<string, unknown> = {}) => ({
  leaseCid, originalCid: 'bafkr4ioriginal', nodeOrigin: 'https://node.tinycloud.xyz', approvedAt: '2026-11-13T12:00:00.000Z',
  leaseExpiresAt: '2027-02-11T12:00:00.000Z', grantExpiresAt: '2026-12-13T12:00:00.000Z', signer: 'openkey', reason: 'Courier keeps your inbox in sync',
  grantSiwe: KV_GRANT, ...overrides,
});

async function setup(page: Page, leases: unknown[], stop: (route: Route, body: unknown) => unknown) {
  await page.context().addCookies([{ name: 'better-auth.session_token', value: 'cookie-session', url: ORIGIN }]);
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, session);
    if (path === '/api/auth/providers') return json(route, { providers: [] });
    if (path === '/api/account/auto-sign') return json(route, { autoSignEnabled: false });
    if (path === '/api/account/renewal-leases') return json(route, { leases });
    if (path.startsWith('/api/account/renewal-leases/') && path.endsWith('/stop')) return stop(route, route.request().postDataJSON());
    if (path === '/api/keys') return json(route, { keys: [] });
    if (path.includes('passkey/list-user-passkeys') || path.includes('list-accounts')) return json(route, []);
    if (path.includes('tinycloud')) return json(route, { tinyCloudManageKeyEnabled: true, mode: 'APP_MANAGED', policyEpoch: 0, apps: [], mcpApps: [], identityApps: [], activity: [] });
    return json(route, {});
  });
}

async function shot(page: Page, name: string) {
  const dir = process.env.TC2946_SHOTS_DIR;
  if (!dir) return;
  for (const width of [390, 1280]) {
    await page.setViewportSize({ width, height: 900 });
    const card = page.locator('#renewing-permissions');
    const path = `${dir}/${name}-${width}.png`;
    if (await card.count()) await card.screenshot({ path });
    else await page.screenshot({ path });
  }
}

test('lists renewing permissions and stops exactly the one chosen', async ({ page }) => {
  const leases = [lease('bafkr4ifirst'), lease('bafkr4isecond', { reason: null, grantSiwe: grant({ [`${space}/sql/`]: { 'tinycloud.sql/read': [{}] } }) })];
  const stopped: string[] = [];
  await setup(page, leases, (route) => {
    stopped.push(new URL(route.request().url()).pathname.split('/').at(-2)!);
    leases.splice(0, 1);
    return json(route, { stopped: true });
  });
  await page.goto('/dashboard/settings');
  const card = page.locator('#renewing-permissions');
  await expect(card.getByTestId('renewal-lease')).toHaveCount(2);
  await expect(card.getByText('Courier keeps your inbox in sync')).toBeVisible();
  await expect(card.getByText('Permission on node.tinycloud.xyz')).toBeVisible();
  // Each row lists the signed grant's permissions in the approval screen's own sentences.
  for (const row of await card.getByTestId('renewal-lease').all()) expect(await row.getByTestId('renewal-lease-permission').count()).toBeGreaterThan(0);
  await shot(page, 'renewing-permissions');
  await card.getByTestId('renewal-lease').first().getByRole('button').click();
  await expect(card.getByRole('status')).toContainText('ends on');
  expect(stopped).toEqual(['bafkr4ifirst']);
  await expect(card.getByTestId('renewal-lease')).toHaveCount(1);
  await shot(page, 'renewal-stopped');
});

test('a node that does not confirm leaves the permission listed, with the reason', async ({ page }) => {
  await setup(page, [lease('bafkr4ifirst')], (route) => json(route, { error: 'refused', code: 'node_unavailable' }, 503));
  await page.goto('/dashboard/settings');
  const card = page.locator('#renewing-permissions');
  await card.getByRole('button').click();
  await expect(card.getByRole('alert')).toBeVisible();
  await expect(card.getByTestId('renewal-lease')).toHaveCount(1);
  await shot(page, 'renewal-not-confirmed');
});

test('a wallet-signed permission is stopped with the wallet signing the exact message', async ({ page }) => {
  const message = `cli.tinycloud.xyz wants you to sign in with your Ethereum account:\n${OWNER}\n\n\nURI: ucan:bafkr4iwallet`;
  const bodies: unknown[] = [];
  await page.addInitScript((owner) => {
    (window as unknown as { signed: unknown[] }).signed = [];
    (window as unknown as { ethereum: unknown }).ethereum = {
      request: async ({ method, params }: { method: string; params?: unknown[] }) => {
        if (method === 'eth_requestAccounts') return [owner];
        if (method === 'personal_sign') { (window as unknown as { signed: unknown[] }).signed.push(params); return `0x${'ab'.repeat(65)}`; }
        throw new Error(method);
      },
    };
  }, OWNER);
  await setup(page, [lease('bafkr4iwallet', { signer: 'wallet' })], (route, body) => {
    bodies.push(body);
    return bodies.length === 1
      ? json(route, { error: 'Sign with your wallet to stop this renewal', code: 'wallet_required', siwe: message }, 409)
      : json(route, { stopped: true });
  });
  await page.goto('/dashboard/settings');
  await page.locator('#renewing-permissions').getByRole('button').click();
  await expect(page.locator('#renewing-permissions').getByRole('status')).toBeVisible();
  expect(await page.evaluate(() => (window as unknown as { signed: unknown[] }).signed)).toEqual([[message, OWNER]]);
  expect(bodies).toEqual([{}, { siwe: message, signature: `0x${'ab'.repeat(65)}` }]);
});

test('signing out from the dashboard says when a permission is still renewing', async ({ page }) => {
  await setup(page, [], (route) => json(route, {}));
  let signedOut = false;
  await page.route('**/api/auth/sign-out', (route) => { signedOut = true; return json(route, { success: true, renewalLeases: { stopped: 1, notStopped: 1, walletRequired: 0 } }); });
  await page.route('**/api/auth/get-session', (route) => json(route, signedOut ? null : session));
  await page.goto('/dashboard');
  // Keys loaded: the page is hydrated and its buttons are wired.
  await expect(page.getByText(/No keys yet/)).toBeVisible();
  await page.getByRole('button', { name: 'Sign Out' }).click();
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page).toHaveURL(/\/dashboard$/);
  await shot(page, 'sign-out-still-renewing');
});
