import { expect, test, type Page } from '@playwright/test';
import { ORIGIN } from './e2e-port';

const consentPath = '/org-registration/consent';
const storageKey = 'openkey.org-registration.intent.v1';

// As in the existing browser lane, API responses here are HTTP UI fixtures, not
// authentication/proof-verification evidence. The registration endpoint only refuses.
async function fixture(page: Page, initiallySignedIn: boolean, code = 'registration_intent_future', status = 400) {
  const now = Math.floor(Date.now() / 1000);
  const claims = { registrationId: '0ad181c0-5eea-4944-80ab-65ac5c68e53d', orgId: `o${'a'.repeat(26)}`, nonce: Buffer.alloc(32, 1).toString('base64url'), handle: 'browser-fixture', displayName: 'Browser fixture', iat: now + 30, exp: now + 630 };
  const intent = `e30.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.AA`;
  const state = { signedIn: initiallySignedIn, attempts: 0 };
  const user = { id: 'browser-owner', name: 'Browser owner', email: 'browser-owner@example.test', emailVerified: true, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
  const session = { id: 'browser-session', userId: user.id, token: 'ui-fixture-only', expiresAt: new Date(Date.now() + 3_600_000).toISOString(), createdAt: user.createdAt, updatedAt: user.updatedAt };
  await page.routeWebSocket('**/*', socket => socket.close());
  await page.route('**/*', async route => {
    const request = route.request();
    const url = new URL(request.url());
    const local = url.origin === ORIGIN;
    if (!local && !['https://openkey.so', 'https://api.openkey.so'].includes(url.origin)) { await route.abort(); return; }
    if (url.pathname.startsWith('/api/')) {
      const headers = { 'access-control-allow-origin': 'https://openkey.so', 'access-control-allow-credentials': 'true', 'access-control-allow-methods': 'GET,POST,OPTIONS', 'access-control-allow-headers': 'content-type' };
      if (request.method() === 'OPTIONS') { await route.fulfill({ status: 204, headers }); return; }
      const respond = (json: unknown, responseStatus = 200) => route.fulfill({ status: responseStatus, headers, json });
      if (url.pathname === '/api/auth/get-session') { await respond(state.signedIn ? { user, session } : null); return; }
      if (url.pathname === '/api/auth/providers') { await respond({ providers: [] }); return; }
      if (url.pathname === '/api/auth/email-otp/send-verification-otp') { await respond({ success: true }); return; }
      if (url.pathname === '/api/auth/sign-in/email-otp') { state.signedIn = true; await respond({ user, token: session.token }); return; }
      if (url.pathname === '/api/auth/passkey/list-user-passkeys') { await respond([{ id: 'ui-passkey' }]); return; }
      if (url.pathname === '/api/keys') { await respond({ keys: [{ id: 'ui-personal-key' }] }); return; }
      if (url.pathname === '/api/org-keys') {
        state.attempts += 1;
        await respond({ error: 'Registration cannot start at this server time', code }, status);
        return;
      }
      await respond({}, 404); return;
    }
    if (local) { await route.continue(); return; }
    const response = await route.fetch({ url: new URL(url.pathname + url.search, ORIGIN).href, headers: { ...request.headers(), host: new URL(ORIGIN).host }, maxRedirects: 0 });
    await route.fulfill({ response });
  });
  return { intent, state, start: () => page.goto(`https://openkey.so${consentPath}#intent=${encodeURIComponent(intent)}`) };
}

test('future-dated intent stays in its tab and can be retried', async ({ page }) => {
  const flow = await fixture(page, true);
  await flow.start();
  const retry = page.getByRole('button', { name: 'Retry registration', exact: true });
  await expect(retry).toBeVisible();
  await expect.poll(() => page.evaluate(key => JSON.parse(sessionStorage.getItem(key)!).intentJws, storageKey)).toBe(flow.intent);
  await retry.click();
  await expect.poll(() => flow.state.attempts).toBe(2);
  await expect(retry).toBeVisible();
  await expect.poll(() => page.evaluate(key => JSON.parse(sessionStorage.getItem(key)!).intentJws, storageKey)).toBe(flow.intent);
});

for (const [status, code] of [[400, 'registration_intent_invalid'], [400, 'registration_tuple_mismatch'], [403, 'registration_intent_future']] as const) {
  test(`terminal ${status}/${code} does not retain a retryable intent`, async ({ page }) => {
    const flow = await fixture(page, true, code, status);
    await flow.start();
    await expect(page.getByRole('alert')).toBeVisible();
    await expect.poll(() => page.evaluate(key => sessionStorage.getItem(key), storageKey)).toBeNull();
    await expect(page.getByRole('button', { name: 'Retry registration', exact: true })).toHaveCount(0);
  });
}

test('an owner starting without a session signs in and returns to the stored consent', async ({ page }) => {
  const flow = await fixture(page, false);
  const providersLoaded = page.waitForResponse(response => new URL(response.url()).pathname === '/api/auth/providers');
  await flow.start();
  await expect(page).toHaveURL('https://openkey.so/auth/login?redirect=%2Forg-registration%2Fconsent');
  await providersLoaded;
  await page.getByPlaceholder('you@example.com').fill('browser-owner@example.test');
  await page.getByRole('button', { name: 'Continue with email', exact: true }).click();
  await page.getByPlaceholder('000000').fill('123456');
  await page.getByRole('button', { name: 'Verify and continue', exact: true }).click();
  await expect(page).toHaveURL(`https://openkey.so${consentPath}`);
  await expect(page.getByRole('button', { name: 'Retry registration', exact: true })).toBeVisible();
  await expect.poll(() => page.evaluate(key => JSON.parse(sessionStorage.getItem(key)!).intentJws, storageKey)).toBe(flow.intent);
});
