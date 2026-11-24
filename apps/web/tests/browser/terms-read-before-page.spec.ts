// A window's page is held behind the Terms gate's spinner until GET /api/account/terms answers: a reload with the session
// still pending makes no account call and the pop-up posts no `openkey:ready` before the read, and the page's calls go
// out after an account that has agreed is read. The suite's dev server runs as a build with a Terms release
// (playwright.config.ts). Every API call is answered by page.route; no API server runs.

import { test, expect, type Page, type Route } from '@playwright/test';
import { TERMS_ACCEPTED } from './terms-fixtures';

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

const SESSION = {
  session: { id: 'terms-read-session', userId: 'terms-read-user', expiresAt: new Date(Date.now() + 3_600_000).toISOString() },
  user: { id: 'terms-read-user', email: 'terms-read@example.test' },
};

/**
 * Answers the API with the session held until `releaseSession()` and the Terms status held until `answerTerms(status)`.
 * `accountCalls` lists every other API request, in order.
 */
async function hold(page: Page) {
  const session = Promise.withResolvers<void>();
  const terms = Promise.withResolvers<unknown>();
  const accountCalls: string[] = [];
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') {
      await session.promise;
      return json(route, SESSION);
    }
    if (path === '/api/account/terms') return json(route, await terms.promise);
    accountCalls.push(`${route.request().method()} ${path}`);
    return json(route, { keys: [], leases: [] });
  });
  return { accountCalls, releaseSession: () => session.resolve(), answerTerms: (status: unknown) => terms.resolve(status) };
}

test('a reload of the dashboard with the session pending makes no account call before the Terms read resolves', async ({ page }) => {
  const { accountCalls, releaseSession, answerTerms } = await hold(page);
  await page.goto('/dashboard');
  await expect(page.getByTestId('terms-checking')).toBeVisible();

  releaseSession();
  await expect(page.getByTestId('terms-checking')).toBeVisible();
  await page.waitForTimeout(500);
  expect(accountCalls).toEqual([]);
  await expect(page.locator('header')).toHaveCount(0);

  answerTerms(TERMS_ACCEPTED);
  await expect(page.locator('header').getByRole('link', { name: 'Dashboard' })).toBeVisible();
  await expect.poll(() => accountCalls.includes('GET /api/keys')).toBe(true);
  await expect(page.getByTestId('terms-checking')).toHaveCount(0);
});

test('the connect pop-up posts openkey:ready and loads its keys only after the Terms read resolves', async ({ page }) => {
  await page.addInitScript(() => {
    const posts: unknown[] = [];
    (window as unknown as { __posts: unknown[] }).__posts = posts;
    Object.defineProperty(window, 'opener', { value: { postMessage: (data: unknown) => posts.push(data) }, configurable: true });
  });
  const ready = () => page.evaluate(() => (window as unknown as { __posts: Array<{ type?: string }> }).__posts.filter((post) => post.type === 'openkey:ready').length);
  const { accountCalls, releaseSession, answerTerms } = await hold(page);
  await page.goto(`/widget/connect?origin=${encodeURIComponent('https://cli.tinycloud.xyz')}`);
  await expect(page.getByTestId('terms-checking')).toBeVisible();
  expect(await ready()).toBe(0);

  releaseSession();
  await page.waitForTimeout(500);
  await expect(page.getByTestId('terms-checking')).toBeVisible();
  expect(await ready()).toBe(0);
  expect(accountCalls).toEqual([]);

  answerTerms(TERMS_ACCEPTED);
  await expect.poll(ready).toBe(1);
  await expect.poll(() => accountCalls).toEqual(['GET /api/keys']);
});

test('an account that owes the Terms gets the Terms and the pop-up makes no account call', async ({ page }) => {
  const { accountCalls, releaseSession, answerTerms } = await hold(page);
  await page.goto(`/widget/connect?origin=${encodeURIComponent('https://cli.tinycloud.xyz')}`);
  releaseSession();
  answerTerms({ ...TERMS_ACCEPTED, requiresAcceptance: true, previouslyAccepted: false });
  await expect(page.getByRole('heading', { name: 'Accept the Terms and Privacy Policy' })).toBeVisible();
  await page.waitForTimeout(500);
  expect(accountCalls).toEqual([]);
});
