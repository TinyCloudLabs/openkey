// TC-3441 T0: every approval page sits in one frame: brand row, an account chip (only when signed in), a
// three-step progress list, the page, the footer.
import { test, expect, type Page } from '@playwright/test';
import { DEVICE_LINK, delegateLink, mockApi, mockDeviceLookup, ownerEmail, preparedLink, revokeLink } from './approval-end-pages-fixtures';

const pages = [
  { name: 'the delegate page', url: delegateLink },
  { name: 'the prepared sign-in page', url: preparedLink() },
  { name: 'the revoke page', url: revokeLink() },
  { name: 'the device page', url: DEVICE_LINK },
];

async function open(page: Page, url: string, signedIn: boolean) {
  const mocked = await mockApi(page, { signedIn });
  await mockDeviceLookup(page);
  await page.goto(url);
  return mocked;
}

for (const width of [390, 1280]) {
  for (const target of pages) {
    test(`${target.name} at ${width}px: one heading, a three-step list, no sideways scroll`, async ({ page }) => {
      await page.setViewportSize({ width, height: 844 });
      await open(page, target.url, false);
      await expect(page.getByRole('main').getByRole('heading', { level: 1 })).toHaveCount(1);
      const steps = page.getByRole('list', { name: 'Progress' }).getByRole('listitem');
      await expect(steps).toHaveCount(3);
      await expect(steps.nth(0)).toHaveText('Sign in');
      await expect(steps.nth(1)).toHaveText('Review');
      await expect(page.getByText('Protected by TEE hardware security')).toBeVisible();
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      expect(overflow).toBeLessThanOrEqual(0);
    });
  }
}

test('the account chip is hidden while signed out', async ({ page }) => {
  await open(page, delegateLink, false);
  await expect(page.getByRole('link', { name: 'Continue with email' })).toBeVisible();
  await expect(page.locator('[data-account-menu]')).toHaveCount(0);
});

test('signed in, the chip shows the account and "Sign out" brings the sign-in card back with the link kept', async ({ page }) => {
  const mocked = await open(page, delegateLink, true);
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
  const chip = page.locator('[data-account-menu] button').first();
  await expect(chip).toContainText(ownerEmail);
  await expect(page.getByRole('button', { name: 'Sign out' })).toHaveCount(0);
  await chip.click();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Sign in to review this request' })).toBeVisible();
  expect(mocked.signedIn).toBe(false);
  expect(page.url()).toContain(delegateLink);
  await expect(page.locator('[data-account-menu]')).toHaveCount(0);
});

test('the device page has no OpenKey Account header', async ({ page }) => {
  await open(page, DEVICE_LINK, false);
  await expect(page.getByRole('heading', { level: 1, name: 'Review a sign-in request' })).toBeVisible();
  await expect(page.getByText('OpenKey Account')).toHaveCount(0);
});
