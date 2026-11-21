import { expect, test, type Page } from '@playwright/test';
import { ORIGIN } from './e2e-port';

const consentPath = '/org-registration/consent';
const storageKey = 'openkey.org-registration.intent.v1';

// As in the existing browser lane, API responses here are HTTP UI fixtures, not
// authentication/proof-verification evidence. The registration endpoint only refuses.
async function fixture(page: Page, initiallySignedIn: boolean, code = 'registration_intent_future', status = 400) {
  const now = Math.floor(Date.now() / 1000);
  const claims = { registrationId: '0ad181c0-5eea-4944-80ab-65ac5c68e53d', orgId: `o${'a'.repeat(26)}`, nonce: Buffer.alloc(32, 1).toString('base64url'), handle: 'browser-fixture', displayName: 'Browser \u202efixture', iat: now + 30, exp: now + 630 };
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
        await respond({ registrationChallenge: { challengeNonce: 'ui-only', challenge: 'ui-only', expiresAt: new Date(Date.now() + 300000).toISOString(), allowCredentials: [] } });
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

test('canonical handle is primary and the display name is isolated at 390px', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const flow = await fixture(page, true);
  await flow.start();
  await expect(page.getByRole('button', { name: 'Approve with passkey', exact: true })).toBeVisible();
  const line = page.locator('p').filter({ hasText: 'Create the owner key for' });
  await expect(line.locator('strong bdi')).toHaveText('@browser-fixture');
  await expect(line.locator('bdi')).toHaveCount(2);
  expect(await page.evaluate(() => location.hash)).toBe('');
  await page.screenshot({ path: '/tmp/tc1518-consent-390.png', fullPage: true });
});
