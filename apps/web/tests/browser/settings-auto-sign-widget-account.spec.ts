// TC-2355: an account created through the widget's email-code sign-up leaves its session token in the tab. Opening
// openkey.so's settings in that same tab must still let the owner turn Auto-Sign off: the change is a cookie-session
// request. The mocked API answers like the real one: any request carrying an Authorization header that changes a
// signing control is refused with 403 "Bearer tokens cannot change TinyCloud signing controls".

import { test, expect, type Page, type Route } from '@playwright/test';

const json = (route: Route, body: unknown, status = 200, headers: Record<string, string> = {}) =>
  route.fulfill({ status, contentType: 'application/json', headers, body: JSON.stringify(body) });

const EMAIL = 'widget-owner@example.test';
const session = {
  session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() },
  user: { id: 'u', email: EMAIL, name: '' },
};

type Patch = { authorization: string | undefined; credentials: boolean };

async function mockApi(page: Page) {
  const state = { signedIn: false, autoSign: true, patches: [] as Patch[], reads: [] as Array<string | undefined> };
  await page.route('**/api/**', (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const authorization = request.headers()['authorization'];
    if (path === '/api/auth/get-session') return json(route, state.signedIn ? session : null);
    if (path === '/api/auth/providers') return json(route, { providers: [] });
    if (path === '/api/auth/email-otp/send-verification-otp') return json(route, { success: true });
    if (path === '/api/auth/sign-in/email-otp') {
      return json(route, { code: 'NEW_ACCOUNT_CONFIRMATION_REQUIRED', message: 'No OpenKey account exists for this email.', signupToken: 'signup-1' }, 403);
    }
    if (path === '/api/auth/sign-up/email-otp') {
      state.signedIn = true;
      return json(route, { token: 'tok-widget', ...session }, 200, { 'set-auth-token': 'tok-widget' });
    }
    if (path === '/api/account/auto-sign' && request.method() === 'GET') {
      state.reads.push(authorization);
      return json(route, { autoSignEnabled: state.autoSign });
    }
    if (path === '/api/account/auto-sign' && request.method() === 'PATCH') {
      state.patches.push({ authorization, credentials: !authorization });
      if (authorization) return json(route, { error: 'Bearer tokens cannot change TinyCloud signing controls' }, 403);
      state.autoSign = (request.postDataJSON() as { autoSignEnabled: boolean }).autoSignEnabled;
      return json(route, { autoSignEnabled: state.autoSign });
    }
    if (path === '/api/keys') return json(route, { keys: [] });
    if (path.startsWith('/api/auth/passkey/list-user-passkeys')) return json(route, []);
    return json(route, { error: `unmocked ${path}` }, 404);
  });
  return state;
}

async function createAccountInTheWidget(page: Page) {
  await page.goto('/widget/embed/connect');
  await page.getByRole('button', { name: 'Continue with email' }).click();
  await page.getByLabel('Email address').fill(EMAIL);
  await page.getByRole('button', { name: 'Send code' }).click();
  await page.getByLabel('Verification code').fill('123456');
  await page.getByRole('button', { name: 'Verify and continue' }).click();
  await page.getByRole('button', { name: 'Create a new account' }).click();
  await expect.poll(() => page.evaluate(() => sessionStorage.getItem('openkey_session_token'))).toBe('tok-widget');
}

test('a widget-created account turns Auto-Sign off on openkey.so from the same tab', async ({ page }) => {
  const api = await mockApi(page);
  await createAccountInTheWidget(page);

  await page.goto('/dashboard/settings');
  const toggle = page.getByRole('switch', { name: 'Toggle Auto-Sign' });
  await expect(toggle).toHaveAttribute('aria-checked', 'true');
  await toggle.click();

  await expect(toggle).toHaveAttribute('aria-checked', 'false');
  await expect(page.getByText('Disabled', { exact: true })).toBeVisible();
  await expect(page.getByText('Bearer tokens cannot change TinyCloud signing controls')).toHaveCount(0);
  expect(api.patches).toEqual([{ authorization: undefined, credentials: true }]);
  expect(api.autoSign).toBe(false);
});
