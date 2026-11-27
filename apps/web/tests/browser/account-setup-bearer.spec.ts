import { test, expect, type Page, type Route } from '@playwright/test';
import { TERMS_ACCEPTED } from './terms-fixtures';

// The account setup window opened by an OpenKey embed (`?via=embed`) with the embed's session token in the request
// message: with no cookie session of its own it calls the API with that token as a bearer (no cookie), keeps it in
// memory only, and shows the sign-in screen when the API rejects it or none came.
const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const key = { id: 'selected-key', address, publicKey: '0x02', keyIndex: 0, label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z', isPrimary: true };
const TOKEN = 'embed-token.c2lnbmF0dXJl';

type HostWindow = Window & { setupWindow: Window };
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

type Seen = { path: string; authorization: string | undefined; cookie: string | undefined };

/** No cookie session (`get-session` answers null); the keys and `prepare` answer by the token the request carries. */
async function mockApi(page: Page, options: { accept: boolean; rateLimited?: 'send' | 'approve' }) {
  const seen: Seen[] = [];
  await page.context().route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const headers = request.headers();
    seen.push({ path, authorization: headers['authorization'], cookie: headers['cookie'] });
    if (path === '/api/auth/get-session') return json(route, null);
    if (path === '/api/account/terms') return json(route, TERMS_ACCEPTED);
    if (path === '/api/keys' || path === '/api/account-setup/prepare') {
      if (!options.accept || headers['authorization'] !== `Bearer ${TOKEN}`) return json(route, { error: 'Unauthorized' }, 401);
      if (path === '/api/keys') return json(route, { keys: [key] });
      if (options.rateLimited) {
        return json(route, { state: 'ready', id: 'setup-1', record: '{}', nodeUrl: 'https://node.tinycloud.xyz', expiresAt: new Date(Date.now() + 300_000).toISOString(), stepUp: 'email' });
      }
      return json(route, { state: 'present' });
    }
    if (options.rateLimited && path === '/api/account-setup/setup-1/passkey') return json(route, { stepUp: 'email', email: 'n•••@mail.com' });
    if (options.rateLimited === 'approve' && path === '/api/account-setup/setup-1/email-code') return json(route, { sent: true, email: 'n•••@mail.com' });
    if (options.rateLimited && path.startsWith('/api/account-setup/setup-1/')) {
      return json(route, { error: 'Too many requests. Please try again later.', code: 'account_setup_rate_limited' }, 429);
    }
    return json(route, {});
  });
  return seen;
}

/** The OpenKey embed: opens the setup window with `?via=embed`, answers its hello with the request (and the token). */
async function openFromEmbed(page: Page, sessionToken: string | null) {
  await page.goto('/__parity_harness');
  await page.evaluate((sessionToken) => {
    const host = window as unknown as HostWindow;
    window.addEventListener('message', (event) => {
      if (event.source === host.setupWindow && event.data?.type === 'openkey:ready') {
        host.setupWindow.postMessage({
          type: 'openkey:account-setup:request', requestId: 'r1', protocolVersion: 1, keyId: 'selected-key',
          requestOrigin: location.origin, ...(sessionToken ? { sessionToken } : {}),
        }, location.origin);
      }
    });
  }, sessionToken);
  const opened = page.waitForEvent('popup');
  await page.evaluate(() => {
    (window as unknown as HostWindow).setupWindow = window.open(`/widget/account-setup?via=embed&origin=${encodeURIComponent(location.origin)}`)!;
  });
  return await opened;
}

test.describe('account setup window opened by an embed with its session token', () => {
  test('signs in by the token: bearer and no cookie on the key list and on prepare, and nothing stored', async ({ page }) => {
    const seen = await mockApi(page, { accept: true });
    const popup = await openFromEmbed(page, TOKEN);
    await expect(popup.getByRole('heading', { name: 'Set up your TinyCloud account' })).toBeVisible();
    await expect(popup.getByTestId('account-setup-account')).toHaveText(`Account: ${address}`);
    await popup.getByTestId('account-setup-set-up').click();
    await expect(popup.getByRole('heading', { name: 'Your TinyCloud account is set up', exact: true })).toBeVisible();

    const calls = seen.filter((call) => call.path === '/api/keys' || call.path === '/api/account-setup/prepare');
    expect(calls.map((call) => call.path)).toEqual(['/api/keys', '/api/account-setup/prepare']);
    for (const call of calls) {
      expect(call.authorization, call.path).toBe(`Bearer ${TOKEN}`);
      expect(call.cookie, call.path).toBeUndefined();
    }
    // The token is in memory only: not in the URL, storage or a cookie of the window.
    expect(popup.url()).not.toContain(TOKEN);
    const stored = await popup.evaluate(() => ({
      local: JSON.stringify({ ...localStorage }), session: JSON.stringify({ ...sessionStorage }), cookie: document.cookie, href: location.href,
    }));
    expect(JSON.stringify(stored)).not.toContain(TOKEN);
  });

  test('shows the sign-in screen when the API rejects the token', async ({ page }) => {
    await mockApi(page, { accept: false });
    const popup = await openFromEmbed(page, TOKEN);
    await expect(popup.getByRole('link', { name: 'Sign in' })).toBeVisible();
    await expect(popup.getByTestId('account-setup-set-up')).toHaveCount(0);
  });

  test('without a token the window shows the sign-in screen, and no bearer call', async ({ page }) => {
    const seen = await mockApi(page, { accept: true });
    const popup = await openFromEmbed(page, null);
    await expect(popup.getByRole('link', { name: 'Sign in' })).toBeVisible();
    expect(seen.filter((call) => call.authorization !== undefined)).toEqual([]);
    expect(seen.some((call) => call.path === '/api/account-setup/prepare')).toBe(false);
  });

  const message = 'Too many attempts in the last hour. Wait an hour, then try once more.';

  test('a spent hourly limit on the code send shows the one message and keeps the Send code button', async ({ page }) => {
    await mockApi(page, { accept: true, rateLimited: 'send' });
    const popup = await openFromEmbed(page, TOKEN);
    await popup.getByTestId('account-setup-set-up').click();
    await popup.getByTestId('account-setup-send-code').click();
    await expect(popup.getByRole('alert')).toHaveText(message);
    await expect(popup.getByTestId('account-setup-send-code')).toBeVisible();
    await expect(popup.getByText('Too many requests')).toHaveCount(0);
  });

  test('a spent hourly limit on the approval shows the one message and stays on the confirm screen', async ({ page }) => {
    await mockApi(page, { accept: true, rateLimited: 'approve' });
    const popup = await openFromEmbed(page, TOKEN);
    await popup.getByTestId('account-setup-set-up').click();
    await popup.getByTestId('account-setup-send-code').click();
    await popup.getByLabel('Code').fill('123456');
    await popup.getByRole('button', { name: 'Confirm', exact: true }).click();
    await expect(popup.getByRole('alert')).toHaveText(message);
    await expect(popup.getByTestId('account-setup-card')).toHaveAttribute('data-phase', 'confirm');
    await expect(popup.getByText('Too many requests')).toHaveCount(0);
  });
});
