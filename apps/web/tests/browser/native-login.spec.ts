// Native mode (TC-941): the signed authorize query carries `tinycloud_request`,
// so /auth/login renders the branded full-bleed sheet. Every API call is
// answered by page.route; no API server runs.

import { test, expect, type Page, type Route } from '@playwright/test';

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

const EXO_BRANDING = {
  clientId: 'exo-native',
  name: 'Exo',
  icon: 'https://tinycloud.chat/icons/pwa-512.png',
  organization: 'TinyCloud Labs',
  theme: { backgroundColor: '#09090B', accentColor: '#FAFAFA' },
};

const signedQuery = (extra: Record<string, string> = {}) =>
  new URLSearchParams({
    response_type: 'code',
    client_id: 'exo-native',
    redirect_uri: 'xyz.tinycloud.exo://callback',
    scope: 'openid',
    state: 'st-1',
    tinycloud_request: 'req-1',
    ...extra,
    exp: '9999999999',
    ba_iat: '1',
    sig: 'signed',
  }).toString();

const noSession = null;
const session = {
  session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() },
  user: { id: 'u', email: 'sam@example.test', name: 'Sam' },
};

interface Mock {
  calls: Array<{ path: string; body: any }>;
  count: (path: string) => number;
}

async function mockApi(
  page: Page,
  options: { session?: unknown; branding?: (route: Route) => Promise<void> | void; providers?: string[] } = {},
): Promise<Mock> {
  const calls: Mock['calls'] = [];
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = route.request().method() === 'POST' ? route.request().postDataJSON() : null;
    calls.push({ path, body });
    if (path === '/api/auth/get-session') return json(route, options.session ?? null);
    if (path === '/api/auth/providers') return json(route, { providers: options.providers ?? [] });
    if (path === '/api/oauth/tinycloud/clients/exo-native/branding') {
      return options.branding ? options.branding(route) : json(route, EXO_BRANDING);
    }
    if (path === '/api/auth/email-otp/send-verification-otp') return json(route, { success: true });
    if (path === '/api/auth/sign-in/email-otp') {
      return json(route, { redirect: true, url: 'https://app.test/done?code=abc' });
    }
    if (path === '/api/keys') return json(route, { keys: [{ id: 'key-1', address: '0xabc' }] });
    if (path === '/api/auth/sign-in/social') {
      return json(route, { url: 'https://accounts.google.com/o/oauth2/v2/auth?client_id=x', redirect: false });
    }
    return json(route, { error: `unmocked ${path}` }, 404);
  });
  await page.route('https://app.test/**', (route) => route.fulfill({ status: 200, contentType: 'text/html', body: '<p>app</p>' }));
  await page.route('https://accounts.google.com/**', (route) => route.fulfill({ status: 200, contentType: 'text/html', body: '<p>google</p>' }));
  await page.route('https://tinycloud.chat/**', (route) => route.fulfill({ status: 200, contentType: 'image/svg+xml', body: '<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"/>' }));
  return { calls, count: (path) => calls.filter((call) => call.path === path).length };
}

const SEND = '/api/auth/email-otp/send-verification-otp';

test.describe('native login', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('email + hint sends one code, even after a reload, and shows the code step', async ({ page }) => {
    const api = await mockApi(page);
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email', login_hint: 'Sam@Example.test' })}`);

    await expect(page.getByRole('heading', { name: 'Sign in to Exo' })).toBeVisible();
    await expect(page.getByText('We sent a 6-digit code to')).toBeVisible();
    await expect(page.getByText('sam@example.test', { exact: true })).toBeVisible();
    await expect.poll(() => api.count(SEND)).toBe(1);
    expect(api.calls.find((call) => call.path === SEND)!.body).toMatchObject({ email: 'sam@example.test', type: 'sign-in' });
    await expect(page.getByRole('button', { name: 'Use a different email' })).toBeVisible();
    await expect(page.getByText('Secured by OpenKey · openkey.so')).toBeVisible();

    await page.reload();
    await expect(page.getByText('We sent a 6-digit code to')).toBeVisible();
    await page.waitForLoadState('networkidle');
    expect(api.count(SEND)).toBe(1);
  });

  test('a hint without a method behaves like the email method', async ({ page }) => {
    const api = await mockApi(page);
    await page.goto(`/auth/login?${signedQuery({ login_hint: 'sam@example.test' })}`);
    await expect(page.getByText('We sent a 6-digit code to')).toBeVisible();
    await expect.poll(() => api.count(SEND)).toBe(1);
  });

  test('"Use a different email" returns to the email step with an empty field and does not send again', async ({ page }) => {
    const api = await mockApi(page);
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email', login_hint: 'sam@example.test' })}`);
    await expect.poll(() => api.count(SEND)).toBe(1);
    await page.getByRole('button', { name: 'Use a different email' }).click();
    await expect(page.locator('#email')).toHaveValue('');
    expect(api.count(SEND)).toBe(1);
  });

  test('email without a hint starts on the email step and sends nothing', async ({ page }) => {
    const api = await mockApi(page);
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email' })}`);
    await expect(page.locator('#email')).toBeVisible();
    await page.waitForLoadState('networkidle');
    expect(api.count(SEND)).toBe(0);
  });

  test('a correct code continues to the app and never offers passkey enrolment', async ({ page }) => {
    const api = await mockApi(page);
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email', login_hint: 'sam@example.test' })}`);
    await page.waitForLoadState('networkidle');
    await page.locator('#otp').fill('123456');
    await page.getByRole('button', { name: 'Continue', exact: true }).click();

    await page.waitForURL('https://app.test/done?code=abc');
    expect(api.calls.find((call) => call.path === '/api/auth/sign-in/email-otp')!.body).toMatchObject({
      email: 'sam@example.test',
      otp: '123456',
    });
    expect(api.calls.some((call) => call.path.includes('passkey'))).toBe(false);
  });

  test('passkey method shows one button and makes no WebAuthn call until it is pressed', async ({ page }) => {
    await page.addInitScript(() => {
      (window as any).__credentialCalls = 0;
      const original = navigator.credentials?.get?.bind(navigator.credentials);
      if (navigator.credentials) {
        navigator.credentials.get = (...args) => {
          (window as any).__credentialCalls++;
          return original ? original(...args) : Promise.reject(new Error('no credentials'));
        };
      }
    });
    const api = await mockApi(page);
    await page.goto(`/auth/login?${signedQuery({ login_method: 'passkey' })}`);

    await expect(page.getByRole('button', { name: 'Continue with passkey' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Use email instead' })).toBeVisible();
    await page.waitForLoadState('networkidle');
    expect(await page.evaluate(() => (window as any).__credentialCalls)).toBe(0);
    expect(api.calls.some((call) => call.path.includes('passkey'))).toBe(false);

    await page.getByRole('button', { name: 'Use email instead' }).click();
    await expect(page.locator('#email')).toBeVisible();
  });

  test('google redirects the whole window and keeps the native query out of the social request body', async ({ page }) => {
    const api = await mockApi(page);
    const query = signedQuery({ login_method: 'google' });
    await page.goto(`/auth/login?${query}`);
    await page.waitForURL('https://accounts.google.com/**');

    const request = api.calls.find((call) => call.path === '/api/auth/sign-in/social')!;
    expect(request.body.provider).toBe('google');
    expect(request.body.callbackURL).toBe(`http://localhost:5779/auth/login?${query}`);
    expect(request.body.errorCallbackURL).toBe(`http://localhost:5779/auth/login?${query}&native_social_error=1`);
    expect(request.body.disableRedirect).toBe(true);
    expect(JSON.stringify(request.body)).not.toContain('additionalData');
    expect(JSON.stringify(request.body)).not.toContain('tinycloud_request=req-1&client_id');
    expect(request.body.additionalData).toBeUndefined();
  });

  test('returning from google with a session re-enters authorize once and does not loop', async ({ page }) => {
    const query = signedQuery({ login_method: 'google' });
    let authorizeHits = 0;
    const api = await mockApi(page, { session });
    await page.route('**/api/auth/oauth2/authorize**', (route) => {
      authorizeHits++;
      return route.fulfill({ status: 302, headers: { Location: `/auth/login?${query}` } });
    });
    await page.goto(`/auth/login?${query}`);
    await expect(page.locator('#email')).toBeVisible();
    await page.waitForLoadState('networkidle');
    expect(authorizeHits).toBe(1);
    expect(api.count('/api/auth/sign-in/social')).toBe(0);
    expect(api.count(SEND)).toBe(0);
  });

  test('the google error return shows the email step with a calm message and starts nothing', async ({ page }) => {
    const api = await mockApi(page, { providers: ['google'] });
    await page.goto(`/auth/login?${signedQuery({ login_method: 'google' })}&native_social_error=1&error=access_denied`);
    await expect(page.locator('#email')).toBeVisible();
    await expect(page.getByRole('alert')).toHaveText('Google sign-in did not finish. Continue with your email instead.');
    await page.waitForLoadState('networkidle');
    expect(api.count('/api/auth/sign-in/social')).toBe(0);
  });

  test('no method shows the email step with google and passkey as secondary options', async ({ page }) => {
    await mockApi(page, { providers: ['google'] });
    await page.goto(`/auth/login?${signedQuery()}`);
    await expect(page.locator('#email')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Continue with Google' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Use a passkey' })).toBeVisible();
  });

  test('applies the client branding and has no TEE footer or key logo', async ({ page }) => {
    await mockApi(page);
    await page.goto(`/auth/login?${signedQuery()}`);
    await expect(page.getByRole('heading', { name: 'Sign in to Exo' })).toBeVisible();
    await expect(page.locator('img[src="https://tinycloud.chat/icons/pwa-512.png"]')).toBeVisible();

    const shell = page.locator('[data-native-shell]');
    await expect(shell).toHaveCSS('background-color', 'rgb(9, 9, 11)');
    await expect(page.getByRole('button', { name: 'Continue', exact: true })).toHaveCSS('background-color', 'rgb(250, 250, 250)');
    await expect(page.locator('meta[name="color-scheme"]')).toHaveAttribute('content', 'dark');
    await expect(page.getByText(/TEE|attested/i)).toHaveCount(0);

    const box = await page.getByRole('button', { name: 'Continue', exact: true }).boundingBox();
    expect(box!.height).toBeGreaterThanOrEqual(48);
  });

  test('a light brand background gets dark text, and an invalid colour is ignored', async ({ page }) => {
    await mockApi(page, {
      branding: (route) => json(route, { ...EXO_BRANDING, theme: { backgroundColor: '#F4F4F5', accentColor: 'red;}body{display:none' } }),
    });
    await page.goto(`/auth/login?${signedQuery()}`);
    await expect(page.locator('[data-native-shell]')).toHaveCSS('background-color', 'rgb(244, 244, 245)');
    await expect(page.getByRole('heading', { name: 'Sign in to Exo' })).toHaveCSS('color', 'rgb(9, 9, 11)');
    await expect(page.getByRole('button', { name: 'Continue', exact: true })).toHaveCSS('background-color', 'rgb(250, 250, 250)');
    await expect(page.locator('body')).not.toHaveCSS('display', 'none');
  });

  test('when branding fails the same dark shell shows OpenKey and the flow still works', async ({ page }) => {
    const errors: string[] = [];
    page.on('console', (message) => { if (message.type() === 'error') errors.push(message.text()); });
    const api = await mockApi(page, { branding: (route) => json(route, { error: 'boom' }, 500) });
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email', login_hint: 'sam@example.test' })}`);
    await expect(page.getByRole('heading', { name: 'Sign in to OpenKey' })).toBeVisible();
    await expect(page.locator('[data-native-shell]')).toHaveCSS('background-color', 'rgb(9, 9, 11)');
    await expect(page.locator('[data-native-shell]')).toHaveAttribute('data-branding', 'unavailable');
    await expect(page.getByText('We sent a 6-digit code to')).toBeVisible();
    expect(api.count(SEND)).toBe(1);
    expect(errors.some((text) => text.includes('Failed to load client branding'))).toBe(true);
  });

  test('a sign-in failure is shown in the native sheet', async ({ page }) => {
    await mockApi(page);
    await page.route('**/api/auth/sign-in/email-otp', (route) => json(route, { message: 'Invalid OTP', code: 'INVALID_OTP' }, 400));
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email', login_hint: 'sam@example.test' })}`);
    await page.waitForLoadState('networkidle');
    await page.locator('#otp').fill('000000');
    await page.getByRole('button', { name: 'Continue', exact: true }).click();
    await expect(page.getByRole('alert')).toBeVisible();
  });
});
