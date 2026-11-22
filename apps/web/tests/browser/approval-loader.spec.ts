// TC-3441 T1: one loader from first paint until there is something to read. Every phase of the page is listed,
// the lit one follows progress, and the card keeps its height. The sign-in card never draws before the
// session answer.
// With a Terms release ('on', the suite's build) the root layout's Terms gate holds the page, with its spinner, while the
// session is read, so the page's own loader starts once the session has answered; with no release ('off') the page's
// loader runs from first paint.
import { test, expect, type Page } from '@playwright/test';
import { delegateLink, mockApi, preparedLink, revokeLink } from './approval-end-pages-fixtures';

const deferred = () => Promise.withResolvers<void>();

const lit = (page: Page) => page.locator('[role="status"] [aria-current="step"]');
const cardHeight = async (page: Page) => (await page.getByRole('main').boundingBox())!.height;
const gateSpinner = (page: Page) => page.getByTestId('terms-checking');

for (const release of ['on', 'off'] as const) {
  test.describe(`with ${release === 'on' ? 'a' : 'no'} Terms release`, () => {
    test.beforeEach(({ page }) => page.addInitScript((mode) => sessionStorage.setItem('openkey_dev_terms_release', mode), release));

    test('the delegate page lists its phases, lights the one in progress, and keeps one card height', async ({ page }) => {
      await page.setViewportSize({ width: 1280, height: 900 });
      const session = deferred();
      const keys = deferred();
      await mockApi(page, { signedIn: true, sessionHeld: session.promise, keysHeld: keys.promise });
      await page.goto(delegateLink);

      if (release === 'on') {
        await expect(gateSpinner(page)).toBeVisible();
        await expect(page.getByRole('link', { name: 'Continue with email' })).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'Use a passkey instead' })).toHaveCount(0);
        session.resolve();
        await expect(lit(page)).toHaveText('Loading your keys');
        await expect(page.locator('[role="status"] li')).toHaveText(['Checking your OpenKey account', 'Loading your keys', 'Preparing the request']);
        return;
      }

      await expect(page.getByRole('heading', { level: 1, name: 'Opening your request' })).toBeVisible();
      const phases = page.locator('[role="status"] li');
      await expect(phases).toHaveText(['Checking your OpenKey account', 'Loading your keys', 'Preparing the request']);
      await expect(lit(page)).toHaveText('Checking your OpenKey account');
      await expect(page.getByRole('link', { name: 'Continue with email' })).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Use a passkey instead' })).toHaveCount(0);
      const first = await cardHeight(page);

      session.resolve();
      await expect(lit(page)).toHaveText('Loading your keys');
      expect(await cardHeight(page)).toBe(first);
    });

    test('with no session, the sign-in card appears only after the session answer', async ({ page }) => {
      const session = deferred();
      await mockApi(page, { signedIn: false, sessionHeld: session.promise });
      await page.goto(delegateLink);
      if (release === 'on') await expect(gateSpinner(page)).toBeVisible();
      else await expect(page.getByRole('heading', { level: 1, name: 'Opening your request' })).toBeVisible();
      await expect(page.getByRole('heading', { name: 'Sign in to review this request' })).toHaveCount(0);
      session.resolve();
      await expect(page.getByRole('heading', { level: 1, name: 'Sign in to review this request' })).toBeVisible();
      await expect(page.getByRole('heading', { name: 'Opening your request' })).toHaveCount(0);
    });

    for (const [name, link] of [['prepared sign-in', preparedLink()], ['revoke', revokeLink()]] as const) {
      test(`the ${name} page loads with the same loader`, async ({ page }) => {
        const session = deferred();
        await mockApi(page, { signedIn: true, sessionHeld: session.promise });
        await page.goto(link);
        if (release === 'on') {
          await expect(gateSpinner(page)).toBeVisible();
        } else {
          await expect(page.getByRole('heading', { level: 1, name: 'Opening your request' })).toBeVisible();
          await expect(page.locator('[role="status"] li')).toHaveText(['Checking your OpenKey account', 'Loading the request']);
          await expect(lit(page)).toHaveText('Checking your OpenKey account');
        }
        await expect(page.getByRole('button', { name: 'Use a passkey instead' })).toHaveCount(0);
      });
    }
  });
}
