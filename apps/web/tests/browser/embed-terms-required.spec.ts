// A frame on another site holds a session token and no cookie, and the Terms screen needs the cookie session.
// An account that owes the Terms and signs in through the embedded connect frame meets a refused key list.
// The frame stays on its page and shows the notice; the button opens the Terms in a window of its own; the
// frame reloads once the account has agreed. Every API call is answered by `page.route`; no API server runs.

import { test, expect, type Page } from '@playwright/test';
import { ORIGIN } from './e2e-port';

const key = { id: 'key_0', address: '0xd559ccd9eb87c530a9a349262669386de93cf412', publicKey: '0x', keyIndex: 0, label: 'Key 0', keyType: 'MANAGED', isPrimary: true, createdAt: '2026-01-01T00:00:00Z' };
const key2 = { ...key, id: 'key_1', address: '0x2222222222222222222222222222222222222222', keyIndex: 1, label: 'Key 1', isPrimary: false };

async function mockApi(page: Page, state: { agreed: boolean; statusAuthorization: Array<string | undefined> }) {
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({ json: { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'sam@example.test', name: 'Sam' } } }));
  await page.route('**/api/keys', (route) => state.agreed
    ? route.fulfill({ json: { keys: [key, key2] } })
    : route.fulfill({ status: 403, json: { error: 'terms_required' } }));
  await page.route('**/api/account/terms', (route) => {
    state.statusAuthorization.push(route.request().headers()['authorization']);
    return route.fulfill({ json: { version: '2026-11-22', effective: '2026-11-22', whatChanged: null, privacyChanged: false, requiresAcceptance: !state.agreed, previouslyAccepted: false } });
  });
}

test('a framed sign-in refused for the Terms shows the notice, opens the Terms in a window and reloads once they are agreed', async ({ page, context }) => {
  const state = { agreed: false, statusAuthorization: [] as Array<string | undefined> };
  await mockApi(page, state);
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.goto('/__parity_harness');
  await page.evaluate((o) => {
    const frame = document.createElement('iframe');
    frame.id = 'connect';
    frame.src = `/widget/embed/connect?origin=${encodeURIComponent(o)}`;
    document.body.append(frame);
  }, ORIGIN);
  const frame = page.frameLocator('#connect');

  await expect(frame.getByRole('heading', { name: 'Agree to the Terms to continue' })).toBeVisible();
  await expect(frame.getByText('OpenKey has new Terms of Service. Open them in a new window, agree, then come back here.')).toBeVisible();
  const framed = page.frames().find((f) => f.url().includes('/widget/embed/connect'));
  expect(framed?.url()).toContain('/widget/embed/connect');

  const opened = context.waitForEvent('page');
  await frame.getByRole('button', { name: 'Open the Terms' }).click();
  const terms = await opened;
  await expect(terms).toHaveURL(/\/auth\/terms/);

  // The frame watches the status with its own token, and goes on once the account has agreed.
  await expect.poll(() => state.statusAuthorization.length).toBeGreaterThan(0);
  expect(new Set(state.statusAuthorization)).toEqual(new Set(['Bearer test-session']));
  await expect(frame.getByRole('heading', { name: 'Agree to the Terms to continue' })).toBeVisible();
  state.agreed = true;
  await expect(frame.getByText('Connect with your primary key:')).toBeVisible();
});
