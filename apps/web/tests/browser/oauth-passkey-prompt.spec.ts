// TC-857: an email-OTP sign-in carrying a signed oauth_query makes the API
// answer /api/auth/sign-in/email-otp with { redirect: true, url }. The
// better-auth client's redirect plugin must not navigate before the login
// page runs its key-ensure and passkey check: accounts without a passkey see
// the "Secure your account" step first, and only afterwards follow the
// server-provided redirect (the consent page here). The consent page itself
// renders full-screen, without the account chrome. Every API call is
// answered by page.route; no API server runs.

import { test, expect, type Page, type Route } from '@playwright/test';

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

// Flat authorize params on /auth/login are equivalent to the nested
// oauth_query wrapper: safeOAuthAuthorizeQuery allowlists these keys either
// way. sig/exp/ba_iat complete the signed envelope the API verifies.
const OAUTH_PARAMS = new URLSearchParams({
  client_id: 'test-app',
  redirect_uri: 'https://app.test/callback',
  response_type: 'code',
  scope: 'openid',
  state: 'st-1',
  exp: '9999999999',
  ba_iat: '1',
  sig: 'signed',
}).toString();

const session = {
  session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() },
  user: { id: 'u', email: 'sam@example.test', name: 'Sam' },
};

async function mockOAuthSignIn(page: Page, passkeys: unknown[]) {
  const calls: string[] = [];
  // The server's redirect URL for this sign-in, echoed verbatim from the
  // oauth_query it received. Read after the sign-in response.
  let serverRedirectUrl = '';
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    calls.push(path);
    if (path === '/api/auth/get-session') return json(route, session);
    if (path === '/api/auth/providers') return json(route, { providers: [] });
    if (path === '/api/auth/email-otp/send-verification-otp') return json(route, { success: true });
    if (path === '/api/auth/sign-in/email-otp') {
      serverRedirectUrl = `${url.origin}/oauth/consent?${route.request().postDataJSON()?.oauth_query ?? ''}`;
      return json(route, { redirect: true, url: serverRedirectUrl });
    }
    if (path === '/api/keys') return json(route, { keys: [{ id: 'key-1', address: '0xabc' }] });
    if (path === '/api/auth/passkey/list-user-passkeys') return json(route, passkeys);
    if (path === '/api/auth/oauth2/public-client') return json(route, { client_name: 'Test App' });
    return json(route, { error: `unmocked ${path}` }, 404);
  });
  return { calls, serverRedirectUrl: () => serverRedirectUrl };
}

async function signInWithEmailCode(page: Page) {
  // Wait for hydration to settle: bind:value rewrites the input from state
  // when hydration lands, so a fill that races it is silently cleared and the
  // required-field submit no-ops.
  await page.waitForLoadState('networkidle');
  await page.getByLabel('Email address').fill('sam@example.test');
  await expect(page.locator('#email')).toHaveValue('sam@example.test');
  await page.getByRole('button', { name: 'Continue with email' }).click();
  await page.locator('#otp').fill('123456');
  await page.getByRole('button', { name: 'Verify and continue' }).click();
}

test('OAuth sign-in without a passkey offers creation, then Skip reaches consent', async ({ page }) => {
  const { calls, serverRedirectUrl } = await mockOAuthSignIn(page, []);
  await page.goto(`/auth/login?${OAUTH_PARAMS}`);
  await signInWithEmailCode(page);

  // The redirect plugin's navigation was vetoed: the passkey checks ran on
  // the login page and the prompt is shown instead of /oauth/consent.
  await expect(page.getByRole('heading', { name: 'Secure your account' })).toBeVisible();
  expect(page.url()).toContain('/auth/login');
  expect(calls).toContain('/api/keys');
  expect(calls).toContain('/api/auth/passkey/list-user-passkeys');

  await page.getByRole('button', { name: 'Skip for now' }).click();

  // Navigation uses the server-provided URL unchanged.
  await expect(page).toHaveURL(serverRedirectUrl());
  await expect(page.getByRole('button', { name: 'Allow', exact: true })).toBeVisible();
});

test('OAuth sign-in with an existing passkey skips the prompt and reaches consent', async ({ page }) => {
  const { serverRedirectUrl } = await mockOAuthSignIn(page, [{ id: 'passkey-1' }]);
  await page.goto(`/auth/login?${OAUTH_PARAMS}`);
  await signInWithEmailCode(page);

  await expect(page).toHaveURL(serverRedirectUrl());
  await expect(page.getByRole('heading', { name: 'Secure your account' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Allow', exact: true })).toBeVisible();
});

test('consent page renders without the account nav', async ({ page }) => {
  await mockOAuthSignIn(page, []);
  await page.goto(`/oauth/consent?${OAUTH_PARAMS}`);
  await expect(page.getByRole('button', { name: 'Allow', exact: true })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Dashboard' })).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'API keys' })).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'Admin console' })).toHaveCount(0);
});
