// TC-3333: the signed-out /delegate card offers Google and Apple next to email and passkey, and signs in with the
// popup flow so the page (and any fragment on its link) stays where it is. Every API call is answered by
// `page.route`; no API server runs. The popup is a new page of the browser context, so its route is on the context.

import { test, expect, type Page, type Route } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';

const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const jwk = encodeBase64UrlJson({ kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
const delegatePath = `/delegate?did=did:key:z6Mk&jwk=${jwk}`;

async function mock(page: Page, providers: string[]) {
  const state = { signedIn: false, keyCalls: 0 };
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/auth/get-session') {
      return json(route, 200, state.signedIn
        ? { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'new@example.test', name: 'New' } }
        : null);
    }
    if (url.pathname === '/api/auth/providers') return json(route, 200, { providers });
    if (url.pathname === '/api/keys') {
      state.keyCalls += 1;
      return json(route, 200, { keys: [] });
    }
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });
  return state;
}

// The popup's own page, as /auth/social/callback answers it: it tells its opener how the sign-in ended.
async function mockPopup(page: Page, state: { signedIn: boolean }, message: Record<string, unknown>) {
  await page.context().route('**/auth/social/callback**', (route) => {
    if (message.type === 'openkey:social:complete') state.signedIn = true;
    return route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: `<!doctype html><script>window.opener.postMessage(${JSON.stringify(message)}, location.origin); window.close();</script>`,
    });
  });
}

test('the signed-out card shows Google and Apple next to email and passkey when both are configured', async ({ page }) => {
  await mock(page, ['google', 'apple']);
  await page.goto(delegatePath);
  await expect(page.getByRole('button', { name: 'Continue with Google' })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Continue with Apple' })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Continue with email' })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Use a passkey instead' })).toBeEnabled();
});

test('the signed-out card shows no social buttons when none are configured', async ({ page }) => {
  await mock(page, []);
  await page.goto(delegatePath);
  await expect(page.getByRole('button', { name: 'Continue with email' })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Use a passkey instead' })).toBeEnabled();
  await expect(page.getByRole('button', { name: /Continue with (Google|Apple)/ })).toHaveCount(0);
});

test('a Google popup sign-in leaves this page in place and continues to the keys', async ({ page }) => {
  const state = await mock(page, ['google']);
  await mockPopup(page, state, { type: 'openkey:social:complete', sessionToken: 'popup-session' });
  await page.goto(delegatePath);
  await page.getByRole('button', { name: 'Continue with Google' }).click();
  await expect(page.getByText('Sign in to review the requested access')).toHaveCount(0);
  await expect.poll(() => state.keyCalls).toBeGreaterThan(0);
  expect(new URL(page.url()).pathname).toBe('/delegate');
});

test('a blocked popup shows the existing blocked-window line on the card', async ({ page }) => {
  await mock(page, ['google']);
  await page.addInitScript(() => { window.open = () => null; });
  await page.goto(delegatePath);
  await page.getByRole('button', { name: 'Continue with Google' }).click();
  await expect(page.getByRole('alert')).toHaveText('Your browser blocked the Google sign-in window. Allow popups, then try again.');
  await expect(page.getByRole('button', { name: 'Continue with Google' })).toBeEnabled();
});

test('a popup that sends the person back to email shows its line and keeps the card', async ({ page }) => {
  const state = await mock(page, ['google']);
  await mockPopup(page, state, { type: 'openkey:social:error', message: 'Continue with your email instead.' });
  await page.goto(delegatePath);
  await page.getByRole('button', { name: 'Continue with Google' }).click();
  await expect(page.getByRole('alert')).toHaveText('Continue with your email instead.');
  await expect(page.getByRole('button', { name: 'Continue with email' })).toBeEnabled();
  expect(new URL(page.url()).pathname).toBe('/delegate');
});
