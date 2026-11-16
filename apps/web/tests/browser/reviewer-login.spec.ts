// App-review sign-in (TC-2775): the review-code step is reachable only inside an OAuth authorize
// flow, because the API refuses review sign-in without a signed authorize query. Every API call
// is answered by page.route; no API server runs.

import { test, expect, type Page, type Route } from '@playwright/test';

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

const SEND = '/api/auth/email-otp/send-verification-otp';
const SIGN_IN = '/api/auth/sign-in/reviewer';
const REVIEW_ACCOUNT = 'openai-review@tinycloud.xyz';
const REVIEW_CODE = 'r'.repeat(43);

const oauthQuery = new URLSearchParams({
  response_type: 'code',
  client_id: 'chatgpt-connector',
  redirect_uri: 'https://chatgpt.com/connector_platform_oauth_redirect',
  scope: 'openid email offline_access tinycloud:mcp',
  state: 'st-1',
  code_challenge: 'challenge',
  code_challenge_method: 'S256',
  resource: 'https://mcp.tinycloud.xyz/chatgpt/mcp',
  exp: '9999999999',
  ba_iat: '1',
  sig: 'signed',
}).toString();

async function mockApi(page: Page) {
  const calls: Array<{ path: string; body: any }> = [];
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = route.request().method() === 'POST' ? route.request().postDataJSON() : null;
    calls.push({ path, body });
    if (path === '/api/auth/get-session') return json(route, null);
    if (path === '/api/auth/providers') return json(route, { providers: [] });
    if (path === SEND) return json(route, { success: true });
    if (path === SIGN_IN) {
      return body?.code === REVIEW_CODE
        ? json(route, { redirect: true, url: 'https://app.test/done?code=abc' })
        : json(route, { code: 'REVIEWER_SIGN_IN_REFUSED', message: 'refused' }, 403);
    }
    return json(route, { error: `unmocked ${path}` }, 404);
  });
  await page.route('https://app.test/**', (route) => route.fulfill({ status: 200, contentType: 'text/html', body: '<p>app</p>' }));
  return { calls, count: (path: string) => calls.filter((call) => call.path === path).length };
}

test.describe('app-review sign-in', () => {
  test('a plain sign-in page offers no review code and explains a reserved address', async ({ page }) => {
    const api = await mockApi(page);
    await page.goto('/auth/login');
    await expect(page.getByRole('heading', { name: 'Welcome to OpenKey' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Continue with email' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Use a review code' })).toHaveCount(0);

    await page.getByLabel('Email address').fill('OpenAI-Review@TinyCloud.xyz');
    await page.getByRole('button', { name: 'Continue with email' }).click();
    await expect(page.getByRole('alert')).toContainText("Review accounts sign in from the app's own connect window");
    await expect(page.getByRole('heading', { name: 'App review sign-in' })).toHaveCount(0);
    expect(api.count(SEND)).toBe(0);
    expect(api.count(SIGN_IN)).toBe(0);
  });

  test('inside an OAuth flow the review-code link opens the step and signs in with the authorize query', async ({ page }) => {
    const api = await mockApi(page);
    await page.goto(`/auth/login?${oauthQuery}`);
    await page.getByRole('button', { name: 'Use a review code' }).click();
    await expect(page.getByRole('heading', { name: 'App review sign-in' })).toBeVisible();

    await page.getByLabel('Review account').fill(REVIEW_ACCOUNT);
    await page.getByLabel('Review code').fill('wrong');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByRole('alert')).toContainText("Couldn't sign in with those details");

    await page.getByLabel('Review code').fill(REVIEW_CODE);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.waitForURL('https://app.test/done?code=abc');
    const signIn = api.calls.filter((call) => call.path === SIGN_IN).at(-1)!;
    expect(signIn.body.email).toBe(REVIEW_ACCOUNT);
    expect(signIn.body.code).toBe(REVIEW_CODE);
    const sent = new URLSearchParams(signIn.body.oauth_query);
    expect(sent.get('client_id')).toBe('chatgpt-connector');
    expect(sent.get('sig')).toBe('signed');
    expect(api.count(SEND)).toBe(0);
  });

  test('inside an OAuth flow a typed reserved address reaches the review-code step without sending a code', async ({ page }) => {
    const api = await mockApi(page);
    await page.goto(`/auth/login?${oauthQuery}`);
    await page.getByLabel('Email address').fill(' OpenAI-Review@tinycloud.xyz');
    await page.getByRole('button', { name: 'Continue with email' }).click();
    await expect(page.getByRole('heading', { name: 'App review sign-in' })).toBeVisible();
    await expect(page.getByLabel('Review code')).toBeVisible();
    expect(api.count(SEND)).toBe(0);
  });
});
