// TC-3232: the required Terms screen. The release (version, date, what changed) comes only from
// GET /api/account/terms; Agree records it and goes on to where the user was headed; Don't agree signs
// out. Every API call is answered by page.route; no API server runs.

import { test, expect, type Page, type Route } from '@playwright/test';

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

// The provider's signed post-login query, as it lands on /auth/terms.
const SIGNED = new URLSearchParams({
  client_id: 'test-app',
  redirect_uri: 'https://app.test/callback',
  response_type: 'code',
  scope: 'openid',
  state: 'st-1',
  exp: '9999999999',
  ba_iat: '1',
  ba_pl: '1',
  sig: 'signed',
}).toString();

const session = {
  session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() },
  user: { id: 'u', email: 'sam@example.test', name: 'Sam' },
};

const FIRST = {
  version: '2027-03-15', effective: '2027-03-15', whatChanged: null, privacyChanged: false,
  requiresAcceptance: true, previouslyAccepted: false,
};

async function mockApi(page: Page, terms: Record<string, unknown>) {
  const calls: Array<{ path: string; body: unknown }> = [];
  let accepted = false;
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const body = route.request().postDataJSON?.() ?? null;
    calls.push({ path, body });
    if (path === '/api/auth/get-session') return json(route, session);
    if (path === '/api/auth/providers') return json(route, { providers: [] });
    if (path === '/api/auth/email-otp/send-verification-otp') return json(route, { success: true });
    if (path === '/api/auth/sign-in/email-otp') return json(route, { token: 't', user: session.user });
    if (path === '/api/auth/sign-out') return json(route, { success: true });
    if (path === '/api/auth/passkey/list-user-passkeys') return json(route, []);
    if (path === '/api/auth/oauth2/public-client') return json(route, { client_name: 'Test App' });
    if (path === '/api/auth/oauth2/continue') return json(route, { redirect: true, url: `${url.origin}/oauth/consent?${SIGNED}` });
    if (path === '/api/account/terms') return json(route, accepted ? { ...terms, requiresAcceptance: false } : terms);
    if (path === '/api/account/terms/accept') {
      accepted = true;
      return json(route, { accepted: true, version: terms.version });
    }
    if (path === '/api/keys') {
      return accepted
        ? json(route, { keys: [{ id: 'key-1', address: '0xabc' }] })
        : json(route, { error: 'terms_required', terms_url: 'https://openkey.test/auth/terms' }, 403);
    }
    return json(route, { error: `unmocked ${path}` }, 404);
  });
  return calls;
}

test('a first-time account agrees, and the signed OAuth request resumes', async ({ page }) => {
  const calls = await mockApi(page, FIRST);
  await page.goto(`/auth/terms?${SIGNED}`);

  await expect(page.getByRole('heading', { name: 'Accept the Terms and Privacy Policy' })).toBeVisible();
  await expect(page.getByText('After you agree, you’ll go back to')).toContainText('Test App');
  await expect(page.getByText('Terms of Service, effective Mar 15, 2027')).toBeVisible();
  await expect(page.getByTestId('terms-what-changed')).toHaveCount(0);
  await expect(page.getByRole('link', { name: /Terms of Service/ })).toHaveAttribute('href', 'https://tinycloud.xyz/terms');
  await expect(page.getByRole('link', { name: /Privacy Policy/ })).toHaveAttribute('href', 'https://tinycloud.xyz/privacy');
  await expect(page.getByText('Signed in as sam@example.test')).toBeVisible();

  await page.getByRole('button', { name: 'Agree and continue' }).click();
  await expect(page).toHaveURL(/\/oauth\/consent\?/);
  expect(calls.find((call) => call.path === '/api/account/terms/accept')?.body).toEqual({ version: '2027-03-15' });
  expect(calls.find((call) => call.path === '/api/auth/oauth2/continue')?.body).toEqual({ postLogin: true, oauth_query: SIGNED });
});

test('an updated release shows what changed only when the API has it', async ({ page }) => {
  await mockApi(page, { ...FIRST, previouslyAccepted: true, whatChanged: 'A plain line from the release config.' });
  await page.goto('/auth/terms');
  await expect(page.getByRole('heading', { name: 'We’ve updated our Terms of Service' })).toBeVisible();
  await expect(page.getByTestId('terms-what-changed')).toHaveText('What changed: A plain line from the release config.');

  await page.unrouteAll();
  await mockApi(page, { ...FIRST, previouslyAccepted: true, effective: null });
  await page.reload();
  await expect(page.getByRole('heading', { name: 'We’ve updated our Terms of Service' })).toBeVisible();
  await expect(page.getByTestId('terms-what-changed')).toHaveCount(0);
  await expect(page.getByText(/effective/)).toHaveCount(0);
});

test('Don’t agree signs out and nothing is accepted', async ({ page }) => {
  const calls = await mockApi(page, FIRST);
  await page.goto(`/auth/terms?${SIGNED}`);
  await page.getByTestId('terms-other-options').click();
  await page.getByRole('region', { name: 'Sign out without agreeing' }).getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'You’re signed out' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', `/auth/login?${SIGNED}`);
  expect(calls.map((call) => call.path)).toContain('/api/auth/sign-out');
  expect(calls.map((call) => call.path)).not.toContain('/api/account/terms/accept');
  expect(calls.find((call) => call.path === '/api/auth/oauth2/consent')?.body).toEqual({ accept: false, oauth_query: SIGNED });
});

test('a refused API call opens the Terms, and Agree returns to the page', async ({ page }) => {
  await mockApi(page, FIRST);
  await page.goto('/dashboard');
  await expect(page).toHaveURL('/auth/terms?returnTo=%2Fdashboard');
  await page.getByRole('button', { name: 'Agree and continue' }).click();
  await expect(page).toHaveURL('/dashboard');
  await expect(page.getByText('0xabc')).toBeVisible();
});

test('signing in asks for the Terms before the passkey offer', async ({ page }) => {
  const calls = await mockApi(page, FIRST);
  await page.goto('/auth/login');
  await page.waitForLoadState('networkidle');
  await page.getByLabel('Email address').fill('sam@example.test');
  await expect(page.locator('#email')).toHaveValue('sam@example.test');
  await page.getByRole('button', { name: 'Continue with email' }).click();
  await page.locator('#otp').fill('123456');
  await page.getByRole('button', { name: 'Verify and continue' }).click();

  await expect(page.getByRole('heading', { name: 'Accept the Terms and Privacy Policy' })).toBeVisible();
  expect(calls.map((call) => call.path)).not.toContain('/api/auth/passkey/list-user-passkeys');
  await page.getByRole('button', { name: 'Agree and continue' }).click();
  await expect(page.getByRole('heading', { name: 'Secure your account' })).toBeVisible();
});
