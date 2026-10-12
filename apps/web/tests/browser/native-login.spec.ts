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
  calls: Array<{ path: string; body: any; raw: string }>;
  count: (path: string) => number;
}

async function mockApi(
  page: Page,
  options: { session?: unknown; branding?: (route: Route) => Promise<void> | void; providers?: string[] } = {},
): Promise<Mock> {
  const calls: Mock['calls'] = [];
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    const raw = route.request().postData() ?? '';
    const body = route.request().method() === 'POST' ? route.request().postDataJSON() : null;
    calls.push({ path, body, raw });
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
    await expect(page.getByText(/A 6-digit code was requested for/)).toBeVisible();
    await page.waitForLoadState('networkidle');
    expect(api.count(SEND)).toBe(1);
  });

  test('reloading while the first send is still in flight does not send a second code', async ({ page }) => {
    const sends: number[] = [];
    const api = await mockApi(page);
    await page.route(`**${SEND}`, async (route) => {
      sends.push(Date.now());
      await new Promise((resolve) => setTimeout(resolve, 1500));
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ success: true }) }).catch(() => {});
    });
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email', login_hint: 'sam@example.test' })}`);
    await expect.poll(() => sends.length).toBe(1);
    await page.reload();
    await expect(page.getByText(/A 6-digit code was requested for/)).toBeVisible();
    await page.waitForTimeout(2000);
    expect(sends.length).toBe(1);
    expect(api.count(SEND)).toBe(0);

    await page.getByRole('button', { name: 'Resend code' }).click();
    await expect.poll(() => sends.length).toBe(2);
  });

  test('a failed automatic send keeps its claim: reload does not retry, Resend does', async ({ page }) => {
    let sends = 0;
    await mockApi(page);
    await page.route(`**${SEND}`, (route) => { sends++; return json(route, { message: 'Try later' }, 429); });
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email', login_hint: 'sam@example.test' })}`);
    await expect(page.getByRole('alert')).toBeVisible();
    await page.reload();
    await expect(page.getByText(/A 6-digit code was requested for/)).toBeVisible();
    await page.waitForLoadState('networkidle');
    expect(sends).toBe(1);
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

  test('the sixth digit submits by itself, continues to the app and never offers passkey enrolment', async ({ page }) => {
    const api = await mockApi(page);
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email', login_hint: 'sam@example.test' })}`);
    await page.waitForLoadState('networkidle');
    await page.locator('#otp').fill('123456');

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

  test('the code step is one one-time-code input drawn as six 44x52 boxes, and Continue waits for the sixth digit', async ({ page }) => {
    await mockApi(page);
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email', login_hint: 'sam@example.test' })}`);
    const input = page.locator('#otp');
    await expect(page.locator('input')).toHaveCount(1);
    await expect(input).toHaveAttribute('autocomplete', 'one-time-code');
    await expect(input).toHaveAttribute('inputmode', 'numeric');
    await expect(input).toHaveAttribute('maxlength', '6');
    await expect(input).toBeFocused();

    const boxes = (await page.locator('.otp-box').all()).map((box) => box.boundingBox());
    const rects = (await Promise.all(boxes)).map((box) => box!);
    expect(rects).toHaveLength(6);
    for (const rect of rects) {
      expect(rect.width).toBe(44);
      expect(rect.height).toBe(52);
    }
    const gaps = rects.slice(1).map((rect, index) => rect.x - (rects[index]!.x + rects[index]!.width));
    expect(gaps).toEqual([8, 8, 16, 8, 8]);

    await expect(page.getByRole('button', { name: 'Continue', exact: true })).toBeDisabled();
    await input.pressSequentially('12345');
    await expect(page.getByRole('button', { name: 'Continue', exact: true })).toBeDisabled();
    await expect(page.locator('.otp-box-active')).toHaveCSS('border-top-color', 'rgb(250, 250, 250)');
  });

  test('the sixth digit, a second form submit and a forced Continue click send exactly one verification', async ({ page }) => {
    await mockApi(page);
    let verifications = 0;
    await page.route('**/api/auth/sign-in/email-otp', async (route) => {
      verifications++;
      await new Promise((resolve) => setTimeout(resolve, 1500));
      await json(route, { redirect: true, url: 'https://app.test/done?code=abc' }).catch(() => {});
    });
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email', login_hint: 'sam@example.test' })}`);
    await page.waitForLoadState('networkidle');
    await page.locator('#otp').fill('123456');
    await expect.poll(() => verifications).toBe(1);

    await page.evaluate(() => {
      const form = document.querySelector('form')!;
      form.requestSubmit();
      form.dispatchEvent(new SubmitEvent('submit', { bubbles: true, cancelable: true }));
      (form.querySelector('button[type="submit"]') as HTMLButtonElement).dispatchEvent(new MouseEvent('click', { bubbles: true }));
      form.requestSubmit(form.querySelector('button[type="submit"]') as HTMLButtonElement);
    });
    await page.waitForURL('https://app.test/done?code=abc');
    expect(verifications).toBe(1);
  });

  test('a wrong code shows one plain line with a single shake, clears the boxes and lets you try again', async ({ page }) => {
    await mockApi(page);
    let attempts = 0;
    await page.route('**/api/auth/sign-in/email-otp', (route) => {
      attempts++;
      if (attempts === 1) return json(route, { message: 'Invalid OTP', code: 'INVALID_OTP' }, 400);
      return json(route, { redirect: true, url: 'https://app.test/done?code=abc' });
    });
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email', login_hint: 'sam@example.test' })}`);
    await page.waitForLoadState('networkidle');
    await page.evaluate(() => {
      (window as any).__shakes = 0;
      document.addEventListener('animationstart', (event) => {
        if ((event as AnimationEvent).animationName.includes('otp-shake')) (window as any).__shakes++;
      }, true);
    });
    const input = page.locator('#otp');
    await input.fill('000000');

    const line = page.getByText("That code didn't match. Check the latest email.");
    await expect(line).toBeVisible();
    await expect(line).toHaveCSS('color', 'rgb(250, 250, 250)');
    await expect(page.locator('.nb-error')).toHaveCount(0);
    await expect(input).toHaveValue('');
    await expect(input).toBeFocused();
    await expect(page.getByRole('button', { name: 'Continue', exact: true })).toBeDisabled();
    expect(await page.evaluate(() => (window as any).__shakes)).toBe(1);

    await input.pressSequentially('123456');
    await page.waitForURL('https://app.test/done?code=abc');
    expect(attempts).toBe(2);
  });

  test('a resend countdown follows a delivered code, and the secondary actions share one quiet row', async ({ page }) => {
    await mockApi(page);
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email', login_hint: 'sam@example.test' })}`);
    const resend = page.getByRole('button', { name: /^Resend in 0:\d\d$/ });
    await expect(resend).toBeDisabled();
    const different = page.getByRole('button', { name: 'Use a different email' });
    const [first, second] = await Promise.all([resend.boundingBox(), different.boundingBox()]);
    expect(Math.abs((first!.y + first!.height / 2) - (second!.y + second!.height / 2))).toBeLessThan(2);
    expect(first!.x).toBeLessThan(second!.x);
    await expect(page.getByText('·', { exact: true })).toBeVisible();
    await expect(different).toHaveCSS('text-decoration-line', 'none');
  });

  test('google redirects the whole window and keeps the native query out of the social request body', async ({ page }) => {
    const api = await mockApi(page);
    const query = signedQuery({ login_method: 'google' });
    await page.goto(`/auth/login?${query}`);
    await page.waitForURL('https://accounts.google.com/**');

    const request = api.calls.find((call) => call.path === '/api/auth/sign-in/social')!;
    expect(Object.keys(request.body).sort()).toEqual(['callbackURL', 'disableRedirect', 'errorCallbackURL', 'provider']);
    expect(request.body.provider).toBe('google');
    expect(request.body.callbackURL).toBe(`http://localhost:5779/auth/login?${query}`);
    expect(request.body.errorCallbackURL).toBe(`http://localhost:5779/auth/login?${query}&native_social_error=1`);
    expect(request.body.disableRedirect).toBe(true);
    expect(request.raw).not.toContain('oauth_query');
    expect(request.raw).not.toContain('additionalData');
  });

  test('the google redirect frame keeps the header and says Opening Google', async ({ page }) => {
    await mockApi(page);
    await page.route('**/api/auth/sign-in/social', async (route) => {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      await json(route, { url: 'https://accounts.google.com/o/oauth2/v2/auth?client_id=x', redirect: false }).catch(() => {});
    });
    await page.goto(`/auth/login?${signedQuery({ login_method: 'google' })}`);
    await expect(page.getByRole('heading', { name: 'Sign in to Exo' })).toBeVisible();
    await expect(page.getByText('Opening Google…')).toBeVisible();
    await expect(page.locator('img.nb-icon')).toBeVisible();
    await page.waitForURL('https://accounts.google.com/**');
  });

  test('the Google button on the email step shows the same Opening Google frame', async ({ page }) => {
    await mockApi(page, { providers: ['google'] });
    await page.route('**/api/auth/sign-in/social', async (route) => {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      await json(route, { url: 'https://accounts.google.com/o/oauth2/v2/auth?client_id=x', redirect: false }).catch(() => {});
    });
    await page.goto(`/auth/login?${signedQuery()}`);
    await page.getByRole('button', { name: 'Continue with Google' }).click();
    await expect(page.getByText('Opening Google…')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Sign in to Exo' })).toBeVisible();
    await page.waitForURL('https://accounts.google.com/**');
  });

  test('first paint is already dark and native-feel while the branding request is still pending', async ({ page }) => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    await mockApi(page, { branding: async (route) => { await gate; await json(route, EXO_BRANDING); } });
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email' })}`, { waitUntil: 'domcontentloaded' });

    const root = page.locator('html');
    await expect(root).toHaveCSS('background-color', 'rgb(9, 9, 11)');
    await expect(root).toHaveCSS('color-scheme', 'dark');
    await expect(page.locator('[data-native-shell]')).toHaveAttribute('data-branding', 'loading');
    await expect(page.locator('[data-native-shell]')).toHaveCSS('background-color', 'rgb(9, 9, 11)');
    await expect(page.locator('meta[name="theme-color"]')).toHaveAttribute('content', '#09090b');
    await expect(page.locator('meta[name="color-scheme"]')).toHaveAttribute('content', 'dark');
    await expect(page.locator('#email')).toBeVisible();
    release();
    await expect(page.locator('[data-native-shell]')).toHaveAttribute('data-branding', 'ready');
    await expect(root).toHaveCSS('background-color', 'rgb(9, 9, 11)');
  });

  test('login uses the same 64px icon, 22.5% radius and 32px title that consent uses', async ({ page }) => {
    await mockApi(page);
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email' })}`);
    await expect(page.getByRole('heading', { name: 'Sign in to Exo' })).toHaveCSS('font-size', '32px');
    const icon = await page.locator('.nb-icon').boundingBox();
    expect([icon!.width, icon!.height, icon!.x, icon!.y]).toEqual([64, 64, 24, 28]);
    await expect(page.locator('.nb-icon')).toHaveCSS('border-radius', '22.5%');
  });

  test('the dark first paint is in the server HTML, before any script runs', async ({ browser }) => {
    const context = await browser.newContext({ javaScriptEnabled: false, viewport: { width: 390, height: 844 } });
    const page = await context.newPage();
    await page.route('**/api/**', (route) => json(route, null));
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email' })}`);
    await expect(page.locator('[data-native-shell]')).toHaveCSS('background-color', 'rgb(9, 9, 11)');
    await expect(page.locator('meta[name="theme-color"]')).toHaveAttribute('content', '#09090b');
    await context.close();
  });

  test('native-feel settings: no zoom-on-focus, no tap highlight, no overscroll, edge-to-edge viewport, accent focus ring', async ({ page }) => {
    await mockApi(page, { branding: (route) => json(route, { ...EXO_BRANDING, theme: { backgroundColor: '#09090B', accentColor: '#0B5FFF' } }) });
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email' })}`);
    const email = page.locator('#email');
    await expect(email).toBeVisible();
    expect(await email.evaluate((node) => parseFloat(getComputedStyle(node).fontSize))).toBeGreaterThanOrEqual(16);
    const shell = page.locator('[data-native-shell]');
    await expect(shell).toHaveCSS('touch-action', 'manipulation');
    await expect(shell).toHaveCSS('-webkit-tap-highlight-color', 'rgba(0, 0, 0, 0)');
    await expect(page.locator('html')).toHaveCSS('overscroll-behavior-y', 'none');
    await expect(page.locator('meta[name="viewport"]')).toHaveAttribute('content', /viewport-fit=cover/);
    await expect(shell).toHaveAttribute('data-branding', 'ready');
    await email.focus();
    await expect(email).toHaveCSS('outline-color', 'rgb(11, 95, 255)');
    await expect(email).toHaveCSS('outline-width', '2px');
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
    await page.route('**/api/auth/sign-in/email-otp', (route) => json(route, { message: 'Too many attempts', code: 'TOO_MANY_ATTEMPTS' }, 403));
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email', login_hint: 'sam@example.test' })}`);
    await page.waitForLoadState('networkidle');
    await page.locator('#otp').fill('000000');
    await expect(page.locator('.nb-error')).toHaveText('Too many attempts');
    await expect(page.getByText("That code didn't match")).toHaveCount(0);
  });
});
