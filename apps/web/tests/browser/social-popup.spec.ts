// TC-3441 T7: the small Google or Apple window sits in the approval frame, without the three steps or the account
// chip, and says how it is doing in a heading. Every API call is answered by `page.route`; no API server runs.
import { test, expect, type Page } from '@playwright/test';
import { ORIGIN } from './e2e-port';

test.use({ viewport: { width: 390, height: 844 } });

async function noApi(page: Page) {
  await page.context().route('**/api/**', (route) =>
    route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: 'unmocked' }) }));
}

/** A page of OpenKey's origin that opens the window and keeps every message the window sends it. */
async function openFromOpener(page: Page, path: string): Promise<Page> {
  await page.route(`${ORIGIN}/popup-opener`, (route) => route.fulfill({
    status: 200,
    contentType: 'text/html',
    body: `<!doctype html><button id="go">Open</button><script>
      window.messages = [];
      addEventListener('message', (event) => { if (event.origin === location.origin) window.messages.push(event.data); });
      document.getElementById('go').onclick = () => window.open(${JSON.stringify(path)}, 'social', 'popup');
    </script>`,
  }));
  await page.goto(`${ORIGIN}/popup-opener`);
  const opened = page.waitForEvent('popup');
  await page.locator('#go').click();
  const popup = await opened;
  await popup.setViewportSize({ width: 390, height: 844 });
  return popup;
}

test('a window with no opener says it lost its link, offers to close, and has no steps or account chip', async ({ page }) => {
  await noApi(page);
  await page.goto('/auth/social/callback');
  const heading = page.getByRole('heading', { level: 1, name: 'This window lost its link to OpenKey' });
  await expect(heading).toBeVisible();
  await expect(heading).toBeFocused();
  await expect(page.getByText('Close it and press the sign-in button again.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Close this window' })).toBeVisible();
  await expect(page.getByRole('list', { name: 'Progress' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /@/ })).toHaveCount(0);
  await expect(page.getByRole('heading', { level: 1 })).toHaveCount(1);
  expect(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)).toBe(false);
});

test('a Google return with an error code names Google in the heading and tells the opener as before', async ({ page }) => {
  await noApi(page);
  const popup = await openFromOpener(page, '/auth/social/callback?via=google&error=server_error');
  await expect(popup.getByRole('heading', { level: 1, name: 'Google sign-in didn’t finish' })).toBeVisible();
  await expect(popup.getByText('Google could not complete sign-in. Please try again.')).toBeVisible();
  await expect(popup.getByRole('button', { name: 'Close this window' })).toBeVisible();
  await expect(popup.getByRole('list', { name: 'Progress' })).toHaveCount(0);
  await expect.poll(() => page.evaluate(() => Reflect.get(window, 'messages')))
    .toEqual([{ type: 'openkey:social:error', message: 'Google could not complete sign-in. Please try again.' }]);

  const closed = popup.waitForEvent('close');
  await popup.getByRole('button', { name: 'Close this window' }).click();
  await closed;
});

test('while it starts the provider, the window says so in its heading', async ({ page }) => {
  await noApi(page);
  // The provider start never answers, so the window stays at work.
  await page.context().route('**/api/auth/sign-in/social', () => {});
  const popup = await openFromOpener(page, '/auth/social/callback?provider=google');
  await expect(popup.getByRole('heading', { level: 1, name: 'Connecting to Google…' })).toBeVisible();
  await expect(popup.getByText('This window will close by itself.')).toBeVisible();
  await expect(popup.getByRole('list', { name: 'Progress' })).toHaveCount(0);
});
