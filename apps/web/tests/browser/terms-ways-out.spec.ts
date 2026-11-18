// TC-3232: the ways out of the Terms screen. Don't agree says no to the request that brought the account
// there, then declines (renewals stop, the account is signed out); the ways-out page disconnects apps,
// stops renewals and reaches account deletion without agreeing. Every API call is answered by page.route.
// Set TERMS_WAYS_OUT_SHOTS_DIR to keep screenshots at 390 and 1280 px.
import { test, expect, type Page, type Route } from '@playwright/test';
import { FIXTURE_META, makeRecapResource, siweWithResources } from '../../../../packages/capability-review/test/fixtures/index';
import { ORIGIN } from './e2e-port';

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

const SIGNED = new URLSearchParams({
  client_id: 'test-app', redirect_uri: 'https://app.test/callback', response_type: 'code', scope: 'openid',
  state: 'st-1', exp: '9999999999', ba_iat: '1', ba_pl: '1', sig: 'signed',
}).toString();
const APPROVAL_ID = 'abcdefghijklmnopqrstuvwxyz';
const session = {
  session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() },
  user: { id: 'u', email: 'sam@example.test', name: 'Sam' },
};
const FIRST = {
  version: '2027-03-15', effective: '2027-03-15', whatChanged: null, privacyChanged: false,
  requiresAcceptance: true, previouslyAccepted: false,
};
const space = `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}:default`;
const LEASE = {
  leaseCid: 'bafkr4ilease', originalCid: 'bafkr4ioriginal', nodeOrigin: 'https://node.tinycloud.xyz', approvedAt: '2026-11-13T12:00:00.000Z',
  leaseExpiresAt: '2027-02-11T12:00:00.000Z', grantExpiresAt: '2026-12-13T12:00:00.000Z', signer: 'openkey', reason: 'Courier keeps your inbox in sync',
  grantSiwe: siweWithResources([makeRecapResource({ [`${space}/kv/courier/`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/put': [{}] } })]),
};
const SIGNING_APP = {
  kind: 'tinycloud', clientId: 'courier', name: 'Courier', uri: 'https://courier.test', icon: null, disabled: false, enabled: true,
  nativeDelegation: true, activeNativeGrants: 1, status: 'ENABLED',
};
const MCP_APP = {
  kind: 'mcp', consentId: 'consent-1', clientId: 'mcp-client', name: 'Notes Agent', uri: null, host: 'notes.test', icon: null,
  connectedAt: '2026-11-01T12:00:00.000Z', scopes: ['openid', 'tinycloud:mcp'],
};

type Call = { path: string; method: string; body: unknown };

async function mockApi(page: Page, overrides: Record<string, (route: Route) => unknown> = {}) {
  const calls: Call[] = [];
  const state = { accepted: false, apps: [SIGNING_APP], mcpApps: [MCP_APP], leases: [LEASE] };
  await page.context().addCookies([{ name: 'better-auth.session_token', value: 'cookie-session', url: ORIGIN }]);
  await page.route('https://app.test/**', (route) => route.fulfill({ status: 200, contentType: 'text/html', body: '<p>Back at the app</p>' }));
  await page.route('**/api/**', (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    calls.push({ path, method: request.method(), body: request.postDataJSON?.() ?? null });
    if (overrides[path]) return overrides[path]!(route);
    if (path === '/api/auth/get-session') return json(route, session);
    if (path === '/api/auth/providers') return json(route, { providers: [] });
    if (path === '/api/auth/sign-out') return json(route, { success: true });
    if (path === '/api/auth/oauth2/public-client') return json(route, { client_name: 'Test App' });
    if (path === '/api/account/terms') return json(route, state.accepted ? { ...FIRST, requiresAcceptance: false } : FIRST);
    if (path === '/api/account' && request.method() === 'GET') {
      return json(route, { user: { id: 'u', email: session.user.email, name: 'Sam', emailVerified: true, emailUndeliverable: false, stepUpPasskeys: 0, _count: { ethereumKeys: 1, passkeys: 0 } } });
    }
    if (path === '/api/account/tinycloud-apps' && request.method() === 'GET') {
      return json(route, { tinyCloudManageKeyEnabled: true, mode: 'APP_MANAGED', policyEpoch: 0, apps: state.apps, mcpApps: state.mcpApps, identityApps: [], activity: [] });
    }
    if (path === `/api/account/tinycloud-apps/${SIGNING_APP.clientId}` && request.method() === 'DELETE') {
      state.apps = [];
      return json(route, { clientId: SIGNING_APP.clientId, disconnected: true });
    }
    if (path === `/api/account/tinycloud-apps/mcp/${MCP_APP.consentId}` && request.method() === 'DELETE') {
      state.mcpApps = [];
      return json(route, { consentId: MCP_APP.consentId, disconnected: true });
    }
    if (path === '/api/account/renewal-leases') return json(route, { leases: state.leases });
    if (path === `/api/account/renewal-leases/${LEASE.leaseCid}/stop`) {
      state.leases = [];
      return json(route, { stopped: true });
    }
    if (path === '/api/account/step-up/email-otp/send') return json(route, { status: true });
    return json(route, { error: `unmocked ${path}` }, 404);
  });
  return { calls, state };
}

async function shot(page: Page, name: string) {
  const dir = process.env.TERMS_WAYS_OUT_SHOTS_DIR;
  if (!dir) return;
  for (const width of [390, 1280]) {
    await page.setViewportSize({ width, height: 900 });
    await page.screenshot({ path: `${dir}/${name}-${width}.png`, fullPage: true });
  }
}

test('the Terms screen has one button; the ways out sit in a small Other options box', async ({ page }) => {
  await mockApi(page);
  await page.goto(`/auth/terms?${SIGNED}`);
  await expect(page.getByRole('button')).toHaveText(['Agree and continue']);
  await expect(page.getByTestId('terms-other-options')).toContainText('Sign out, disconnect apps or delete your account without agreeing.');
  await shot(page, '1-terms');
});

test('signing out from Other options tells the OAuth app no and goes back to it', async ({ page }) => {
  const { calls } = await mockApi(page, {
    '/api/auth/oauth2/consent': (route) => json(route, { redirect: true, url: 'https://app.test/callback?error=access_denied&state=st-1' }),
  });
  await page.goto(`/auth/terms?${SIGNED}`);
  await page.getByTestId('terms-other-options').click();

  await expect(page.getByRole('heading', { name: 'Other options' })).toBeVisible();
  await expect(page.getByTestId('terms-decline-note')).toContainText('We’ll also tell Test App you said no.');
  await expect(page.getByTestId('terms-delete-account')).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await shot(page, '2-other-options');

  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page).toHaveURL('https://app.test/callback?error=access_denied&state=st-1');
  const paths = calls.map((call) => call.path);
  expect(paths.indexOf('/api/auth/oauth2/consent')).toBeLessThan(paths.indexOf('/api/auth/sign-out'));
  expect(calls.find((call) => call.path === '/api/auth/oauth2/consent')?.body).toEqual({ accept: false, oauth_query: SIGNED });
  expect(paths).not.toContain('/api/account/terms/accept');
});

test('signing out from Other options declines the approval link, then shows the account signed out', async ({ page }) => {
  const { calls } = await mockApi(page, {
    [`/api/approval-requests/${APPROVAL_ID}/deny`]: (route) => json(route, { denied: true }),
  });
  await page.addInitScript((id) => sessionStorage.setItem(`openkey.approval.${id}`, '#tv1.reference'), APPROVAL_ID);
  await page.goto(`/auth/terms?returnTo=${encodeURIComponent(`/a/${APPROVAL_ID}`)}`);
  await page.getByTestId('terms-other-options').click();
  await expect(page.getByTestId('terms-decline-note')).toContainText('We’ll also turn down the request that brought you here.');

  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'You’re signed out' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', `/auth/login?redirect=${encodeURIComponent(`/a/${APPROVAL_ID}`)}`);
  expect(calls.find((call) => call.path === `/api/approval-requests/${APPROVAL_ID}/deny`)?.body).toEqual({ reference: `/a/${APPROVAL_ID}#tv1.reference` });
  expect(calls.map((call) => call.path)).toContain('/api/auth/sign-out');
});

test('without agreeing, Disconnect apps disconnects apps, stops renewals and reaches deletion', async ({ page }) => {
  const { calls } = await mockApi(page);
  await page.goto(`/auth/terms?${SIGNED}`);
  await page.getByTestId('terms-other-options').click();
  await page.getByRole('link', { name: 'Disconnect apps or stop renewals' }).click();

  await expect(page.getByRole('heading', { name: 'Disconnect apps', exact: true })).toBeVisible();
  await expect(page.getByText('You don’t need to agree to the Terms to disconnect apps, stop renewals or delete your account.')).toBeVisible();
  await expect(page.locator('#connected-tinycloud-apps')).toContainText('Courier');
  await expect(page.locator('#connected-mcp-apps')).toContainText('Notes Agent');
  await expect(page.locator('#renewing-permissions').getByTestId('renewal-lease')).toHaveCount(1);
  await expect(page.getByTestId('terms-delete-account')).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await shot(page, '3-disconnect-apps');

  await page.getByRole('button', { name: 'Disconnect Courier' }).click();
  const dialog = page.getByRole('dialog', { name: 'Disconnect Courier' });
  await expect(dialog.getByRole('button', { name: 'Disconnect app' })).toBeDisabled();
  await dialog.getByLabel('Type DISCONNECT to confirm').fill('DISCONNECT');
  await shot(page, '3-disconnect-confirm');
  await dialog.getByRole('button', { name: 'Disconnect app' }).click();
  await expect(page.locator('#connected-tinycloud-apps')).toContainText('No connected apps can request TinyCloud signatures.');

  await page.getByRole('button', { name: 'Disconnect Notes Agent' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Disconnect app' }).click();
  await expect(page.locator('#connected-mcp-apps').getByRole('status')).toContainText('Disconnected.');

  await page.locator('#renewing-permissions').getByTestId('renewal-lease').getByRole('button').click();
  await expect(page.locator('#renewing-permissions').getByRole('status')).toContainText('ends on');

  const mutations = calls.filter((call) => call.method !== 'GET').map((call) => `${call.method} ${call.path}`);
  expect(mutations).toEqual([
    `DELETE /api/account/tinycloud-apps/${SIGNING_APP.clientId}`,
    `DELETE /api/account/tinycloud-apps/mcp/${MCP_APP.consentId}`,
    `POST /api/account/renewal-leases/${LEASE.leaseCid}/stop`,
  ]);
  await shot(page, '3-disconnect-done');

  await page.getByRole('link', { name: 'Delete account…' }).click();
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Type DELETE MY ACCOUNT to confirm').fill('DELETE MY ACCOUNT');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('heading', { name: "Verify it's you" })).toBeVisible();
  await page.getByRole('button', { name: 'Send code' }).click();
  await expect(page.getByText('We sent a code to sam@example.test. It lasts 5 minutes.')).toBeVisible();
});

test('the pages lead back the way they came, and an account that has agreed goes to Settings', async ({ page }) => {
  const { state } = await mockApi(page);
  await page.goto(`/auth/terms?${SIGNED}`);
  await page.getByTestId('terms-other-options').click();
  await page.getByRole('link', { name: 'Disconnect apps or stop renewals' }).click();
  await page.getByRole('link', { name: 'Back to other options' }).click();
  await expect(page.getByRole('heading', { name: 'Other options' })).toBeVisible();
  await page.getByRole('link', { name: 'Back to the Terms' }).click();
  await expect(page).toHaveURL(`/auth/terms?${SIGNED}`);
  await expect(page.getByRole('heading', { name: 'Accept the Terms and Privacy Policy' })).toBeVisible();

  state.accepted = true;
  for (const path of ['/auth/terms/options', '/auth/terms/leave']) {
    await page.goto(path);
    await expect(page).toHaveURL('/dashboard/settings');
  }
});
