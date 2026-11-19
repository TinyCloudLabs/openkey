// TC-3441 T2: one sign-in card on the delegate page and on the prepared sign-in and revoke pages. Google and
// Apple sign in through a popup, the card shows the window's state, and a 401 on Approve brings the card back
// with its own heading. Nothing is claimed while the card is showing.
import { test, expect, type Page } from '@playwright/test';
import { approvalLink, delegateLink, mockApi, mockPopup, preparedLink, revokeLink } from './approval-end-pages-fixtures';

const cardPages = [
  { name: 'the prepared sign-in page', url: preparedLink(), cancelShown: true },
  { name: 'the revoke page', url: revokeLink(), cancelShown: true },
  { name: 'the delegate page', url: delegateLink, cancelShown: false },
];

const heading = (page: Page, name: string) => page.getByRole('heading', { level: 1, name });

for (const target of cardPages) {
  test.describe(target.name, () => {
    test('signed out, shows the card with four ways in and claims nothing', async ({ page }) => {
      const mocked = await mockApi(page, { signedIn: false });
      await page.goto(target.url);
      await expect(heading(page, 'Sign in to review this request')).toBeVisible();
      await expect(page.getByText('Signing in doesn’t approve anything. You review the request next.')).toBeVisible();
      await expect(page.getByRole('link', { name: 'Continue with email' })).toBeEnabled();
      await expect(page.getByRole('button', { name: 'Continue with Google' })).toBeEnabled();
      await expect(page.getByRole('button', { name: 'Continue with Apple' })).toBeEnabled();
      await expect(page.getByRole('button', { name: 'Use a passkey instead' })).toBeEnabled();
      await expect(page.getByRole('link', { name: 'Create an account' })).toBeVisible();
      await expect(page.getByRole('link', { name: 'Recover account' })).toBeVisible();
      await expect(page.getByRole('button', { name: 'Cancel this request' })).toHaveCount(target.cancelShown ? 1 : 0);
      expect(mocked.claims).toBe(0);
      expect(mocked.revokeClaims).toBe(0);
    });

    test('while the Google window is open, the card says so and "Sign in another way" closes it without an error', async ({ page }) => {
      const mocked = await mockApi(page, { signedIn: false });
      await mockPopup(page, mocked, { type: 'stay' });
      await page.goto(target.url);
      const opened = page.waitForEvent('popup');
      await page.getByRole('button', { name: 'Continue with Google' }).click();
      const popup = await opened;

      await expect(heading(page, 'Finish signing in with Google')).toBeVisible();
      await expect(page.getByText('Google opened in a small window. This page is waiting and will carry on by itself when you’re done.')).toBeVisible();
      await expect(page.getByText('Waiting for Google…')).toBeVisible();
      await expect(page.getByRole('button', { name: 'Show the Google window again' })).toBeVisible();

      await page.getByRole('button', { name: 'Sign in another way' }).click();
      await expect.poll(() => popup.isClosed()).toBe(true);
      await expect(heading(page, 'Sign in to review this request')).toBeVisible();
      await expect(page.getByRole('alert')).toHaveCount(0);
      expect(mocked.claims).toBe(0);
    });

    test('a window closed before the end shows that the sign-in was cancelled and the request is still here', async ({ page }) => {
      const mocked = await mockApi(page, { signedIn: false });
      await mockPopup(page, mocked, { type: 'close' });
      await page.goto(target.url);
      await page.getByRole('button', { name: 'Continue with Google' }).click();
      await expect(page.getByRole('alert')).toHaveText('Google sign-in was cancelled. Your request is still here.');
      await expect(page.getByRole('button', { name: 'Continue with Google' })).toBeEnabled();
    });

    test('a blocked window shows the blocked line on the card', async ({ page }) => {
      await mockApi(page, { signedIn: false });
      await page.addInitScript(() => { window.open = () => null; });
      await page.goto(target.url);
      await page.getByRole('button', { name: 'Continue with Apple' }).click();
      await expect(page.getByRole('alert')).toHaveText('Your browser blocked the Apple sign-in window. Allow popups, then try again.');
    });
  });
}

for (const target of cardPages.filter((candidate) => candidate.cancelShown)) {
  test.describe(`${target.name}, after signing in inside this tab`, () => {
    test('a finished Google sign-in says "You’re signed in" and claims only after "Review the request"', async ({ page }) => {
      const mocked = await mockApi(page, { signedIn: false });
      await mockPopup(page, mocked, { type: 'complete' });
      await page.goto(target.url);
      await page.getByRole('button', { name: 'Continue with Google' }).click();
      await expect(heading(page, 'You’re signed in')).toBeVisible();
      await expect(page.getByText('Carry on to review the request. Nothing is approved until you say so.')).toBeVisible();
      expect(mocked.claims).toBe(0);
      expect(mocked.revokeClaims).toBe(0);
      await page.getByRole('button', { name: 'Review the request' }).click();
      if (target.url === preparedLink()) await expect.poll(() => mocked.claims).toBe(1);
      else await expect.poll(() => mocked.claims + mocked.revokeClaims).toBeGreaterThan(0);
      await expect(heading(page, 'You’re signed in')).toHaveCount(0);
    });

    test('"Cancel this request" ends it with "Cancelled. Nothing was approved." and claims nothing', async ({ page }) => {
      const mocked = await mockApi(page, { signedIn: false });
      await page.goto(target.url);
      await page.getByRole('button', { name: 'Cancel this request' }).click();
      await expect(heading(page, 'Cancelled. Nothing was approved.')).toBeVisible();
      expect(mocked.claims).toBe(0);
      expect(mocked.revokeClaims).toBe(0);
      await expect(page.getByRole('button', { name: 'Continue with Google' })).toHaveCount(0);
    });
  });
}

test('a 401 on Approve brings the card back with "You were signed out"', async ({ page }) => {
  await mockApi(page, { signedIn: true, approveReply: { status: 401, body: { code: 'session_required', error: 'Authentication required' } } });
  await page.goto(approvalLink);
  const approve = page.getByRole('button', { name: 'Approve', exact: true });
  await expect(approve).toBeEnabled();
  await approve.click();
  await expect(heading(page, 'You were signed out')).toBeVisible();
  await expect(page.getByText('Your OpenKey session ended before the approval went through. Sign in again and you’ll come straight back to this request.')).toBeVisible();
  await expect(page.getByRole('alert')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Use a passkey instead' })).toBeEnabled();
  await expect(page.getByRole('link', { name: 'Continue with email' })).toBeEnabled();
});
