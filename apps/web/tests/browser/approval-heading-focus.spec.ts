// TC-3441 T0: on a new end state focus moves to the h1, so a screen reader reads it. No key reaches that heading,
// so it draws no focus ring.
import { test, expect } from '@playwright/test';
import { mockApi, preparedLink } from './approval-end-pages-fixtures';

test('the sign-in heading takes focus without a focus ring, and so does the cancelled heading', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockApi(page, { signedIn: false });
  await page.goto(preparedLink());

  const signIn = page.getByRole('heading', { level: 1, name: 'Sign in to review this request' });
  await expect(signIn).toBeFocused();
  await expect(signIn).toHaveAttribute('tabindex', '-1');
  await expect(signIn).toHaveCSS('outline-style', 'none');

  await page.getByRole('button', { name: 'Cancel this request' }).click();
  const cancelled = page.getByRole('heading', { level: 1, name: 'Cancelled. Nothing was approved.' });
  await expect(cancelled).toBeFocused();
  await expect(cancelled).toHaveCSS('outline-style', 'none');
});
