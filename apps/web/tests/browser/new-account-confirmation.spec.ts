// TC-1114: a verified email code for an address with no account must not
// sign in. The API answers 403 NEW_ACCOUNT_CONFIRMATION_REQUIRED with a
// sign-up token; the screen asks, and only "Create a new account" posts the
// token to /api/auth/sign-up/email-otp. Every API call is answered by
// page.route; no API server runs.

import { test, expect, type Page, type Route } from '@playwright/test';

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

const EMAIL = 'newcomer@example.test';
const NEW_ACCOUNT = { code: 'NEW_ACCOUNT_CONFIRMATION_REQUIRED', message: 'No OpenKey account exists for this email.', signupToken: 'signup-token-1' };

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
  user: { id: 'u', email: EMAIL, name: '' },
};

const RETURNING = 'returning@example.test';

async function mockNewAccount(page: Page, signUp: (route: Route, body: Record<string, unknown>) => unknown) {
  const signUps: Record<string, unknown>[] = [];
  const signIns: Record<string, unknown>[] = [];
  let signedIn = false;
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    if (path === '/api/auth/get-session') return json(route, signedIn ? session : null);
    if (path === '/api/auth/providers') return json(route, { providers: [] });
    if (path === '/api/auth/email-otp/send-verification-otp') return json(route, { success: true });
    if (path === '/api/auth/sign-in/email-otp') {
      const body = route.request().postDataJSON() as Record<string, unknown>;
      signIns.push(body);
      if (body.email !== RETURNING) return json(route, NEW_ACCOUNT, 403);
      // The existing account, reached through recovery mid-OAuth.
      signedIn = true;
      return json(route, { redirect: true, url: `${url.origin}/oauth/consent?${body.oauth_query ?? ''}` });
    }
    if (path === '/api/auth/sign-up/email-otp') {
      const body = route.request().postDataJSON() as Record<string, unknown>;
      signUps.push(body);
      signedIn = true;
      return signUp(route, body);
    }
    if (path === '/api/keys') return json(route, { keys: [{ id: 'key-1', address: '0xabc' }] });
    if (path === '/api/auth/passkey/list-user-passkeys') return json(route, []);
    if (path === '/api/auth/oauth2/public-client') return json(route, { client_name: 'Test App' });
    return json(route, { error: `unmocked ${path}` }, 404);
  });
  return { signUps, signIns };
}

async function verifyOnLogin(page: Page) {
  // bind:value rewrites the input when hydration lands; wait so the fill sticks.
  await page.waitForLoadState('networkidle');
  await page.getByLabel('Email address').fill(EMAIL);
  await expect(page.locator('#email')).toHaveValue(EMAIL);
  await page.getByRole('button', { name: 'Continue with email' }).click();
  await page.locator('#otp').fill('123456');
  await page.getByRole('button', { name: 'Verify and continue' }).click();
}

test('login: an unknown email asks first, and Create carries the token and the OAuth request', async ({ page }) => {
  const { signUps } = await mockNewAccount(page, (route, body) =>
    json(route, { redirect: true, url: `${new URL(route.request().url()).origin}/oauth/consent?${body.oauth_query ?? ''}` }));
  await page.goto(`/auth/login?${OAUTH_PARAMS}`);
  await expect(page.getByText("We'll ask before creating a new account.")).toBeVisible();
  await verifyOnLogin(page);

  const confirmation = page.getByTestId('new-account-confirmation');
  await expect(confirmation).toContainText(`No OpenKey account for ${EMAIL}`);
  await expect(confirmation.getByRole('button', { name: 'Sign in with a passkey' })).toBeVisible();
  await expect(confirmation.getByRole('button', { name: 'Recover your account' })).toBeVisible();
  expect(signUps).toHaveLength(0);

  await confirmation.getByRole('button', { name: 'Create a new account' }).click();
  // The new account is offered a passkey before the OAuth redirect is followed.
  await expect(page.getByRole('heading', { name: 'Secure your account' })).toBeVisible();
  expect(signUps).toHaveLength(1);
  expect(signUps[0]).toMatchObject({ email: EMAIL, signupToken: 'signup-token-1' });
  expect(String(signUps[0]!.oauth_query)).toContain('client_id=test-app');

  await page.getByRole('button', { name: 'Skip for now' }).click();
  await expect(page).toHaveURL(/\/oauth\/consent\?/);
});

test('login: choosing another email creates nothing', async ({ page }) => {
  const { signUps } = await mockNewAccount(page, (route) => json(route, { token: 't', user: session.user }));
  await page.goto('/auth/login');
  await verifyOnLogin(page);
  await page.getByTestId('new-account-confirmation').getByRole('button', { name: 'Use a different email' }).click();
  await expect(page.getByRole('heading', { name: 'Welcome to OpenKey' })).toBeVisible();
  expect(signUps).toHaveLength(0);
});

test('login: an expired confirmation sends the user back for a new code', async ({ page }) => {
  await mockNewAccount(page, (route) => json(route, {
    code: 'INVALID_SIGNUP_TOKEN',
    message: 'This confirmation has expired. Request a new code to create your account.',
  }, 400));
  await page.goto('/auth/login');
  await verifyOnLogin(page);
  await page.getByTestId('new-account-confirmation').getByRole('button', { name: 'Create a new account' }).click();
  await expect(page.getByRole('heading', { name: 'Welcome to OpenKey' })).toBeVisible();
  await expect(page.getByRole('alert')).toContainText('This confirmation has expired');
});

test('embedded connect: an unknown email asks first, and Create carries the token', async ({ page }) => {
  const { signUps } = await mockNewAccount(page, (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', headers: { 'set-auth-token': 'session-1' }, body: JSON.stringify({ token: 'session-1', user: session.user }) }));
  await page.goto(`/widget/embed/connect?origin=${encodeURIComponent('https://app.test')}`);
  await page.waitForLoadState('networkidle');
  await expect(page.getByText("We'll ask before creating a new account.")).toBeVisible();
  await page.getByRole('button', { name: 'Continue with email' }).click();
  await page.locator('#embed-email').fill(EMAIL);
  await page.getByRole('button', { name: 'Send code' }).click();
  await page.locator('#embed-otp').fill('123456');
  await page.getByRole('button', { name: 'Verify and continue' }).click();

  const confirmation = page.getByTestId('new-account-confirmation');
  await expect(confirmation).toContainText(`No OpenKey account for ${EMAIL}`);
  await expect(page.getByRole('alert')).toHaveCount(0);
  expect(signUps).toHaveLength(0);
  expect(await page.evaluate(() => sessionStorage.getItem('openkey_session_token'))).toBeNull();

  await confirmation.getByRole('button', { name: 'Create a new account' }).click();
  await expect.poll(() => page.evaluate(() => sessionStorage.getItem('openkey_session_token'))).toBe('session-1');
  expect(signUps).toEqual([{ email: EMAIL, signupToken: 'signup-token-1' }]);
});

test('login: a created account is signed in for pages that read the session', async ({ page }) => {
  await mockNewAccount(page, (route) => json(route, { token: 't', user: session.user }));
  // Signed out, the dashboard sends the user to the login page.
  await page.goto('/dashboard');
  await expect(page).toHaveURL(/\/auth\/login/);
  await verifyOnLogin(page);
  await page.getByTestId('new-account-confirmation').getByRole('button', { name: 'Create a new account' }).click();
  await page.getByRole('button', { name: 'Skip for now' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  // A stale signed-out session store would bounce straight back to login.
  await page.waitForTimeout(1000);
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByRole('heading', { name: 'Welcome to OpenKey' })).toHaveCount(0);
});

test('login: recovering an existing account mid-OAuth continues the authorize request', async ({ page }) => {
  const { signUps, signIns } = await mockNewAccount(page, (route) => json(route, { token: 't', user: session.user }));
  await page.goto(`/auth/login?${OAUTH_PARAMS}`);
  await verifyOnLogin(page);
  await page.getByTestId('new-account-confirmation').getByRole('button', { name: 'Recover your account' }).click();
  await expect(page).toHaveURL(/\/auth\/recover\?oauth_query=/);

  await page.waitForLoadState('networkidle');
  await page.locator('#email').fill(RETURNING);
  await expect(page.locator('#email')).toHaveValue(RETURNING);
  await page.getByRole('button', { name: 'Send recovery code' }).click();
  await page.locator('#otp').fill('123456');
  await page.getByRole('button', { name: 'Verify' }).click();
  // Recovery still offers a new passkey before the authorize request resumes.
  await page.getByRole('button', { name: 'Skip this step' }).click();
  await expect(page).toHaveURL(/\/oauth\/consent\?.*client_id=test-app/);
  expect(String(signIns.at(-1)?.oauth_query)).toContain('client_id=test-app');
  expect(signUps).toHaveLength(0);
});

test('native login: the new-account choice includes recovery for the same request', async ({ page }) => {
  await mockNewAccount(page, (route) => json(route, { token: 't', user: session.user }));
  const native = new URLSearchParams({
    response_type: 'code',
    client_id: 'exo-native',
    redirect_uri: 'xyz.tinycloud.exo://callback',
    scope: 'openid',
    state: 'st-1',
    tinycloud_request: 'req-1',
    login_method: 'email',
    login_hint: EMAIL,
    exp: '9999999999',
    ba_iat: '1',
    sig: 'signed',
  }).toString();
  await page.goto(`/auth/login?${native}`);
  await expect(page.getByText('We sent a 6-digit code to')).toBeVisible();
  await page.locator('#otp').fill('123456');

  await expect(page.getByText(`No OpenKey account for ${EMAIL}.`)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Create a new account' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign in with a passkey' })).toBeVisible();
  await page.getByRole('button', { name: 'Recover your account' }).click();
  await expect(page).toHaveURL(/\/auth\/recover\?oauth_query=.*tinycloud_request%3Dreq-1/);
});
