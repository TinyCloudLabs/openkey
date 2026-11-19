// The account header's three nav items must all be fully visible at phone width (390 px): none clipped at the
// right edge, no sideways scroll. Layout only.
import { test, expect } from '@playwright/test';

test.use({ viewport: { width: 390, height: 844 } });

test('the account header shows every nav item in full at 390 px, with no sideways scroll', async ({ page }) => {
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    return route.fulfill({ json: path === '/api/auth/get-session'
      ? { session: { id: 'header-session', userId: 'header-admin', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'header-admin', email: 'admin@example.test' } }
      : { organizations: [{ id: 'header-organization', role: 'ADMIN' }] } });
  });
  await page.goto('/device');
  const header = page.locator('header');
  await expect(header.getByRole('link', { name: 'Dashboard' })).toBeVisible();
  const links = [
    header.getByRole('link', { name: 'Dashboard' }),
    header.getByRole('link', { name: 'API keys' }),
    header.getByRole('link', { name: 'OpenKey Admin console' }),
  ];
  for (const link of links) await expect(link).toBeVisible();
  const measured = await page.evaluate(() => {
    const view = document.documentElement.clientWidth;
    const clip = (element: Element) => {
      // The part of the link that is actually painted: its box limited by every clipping ancestor.
      let box = element.getBoundingClientRect();
      for (let parent = element.parentElement; parent; parent = parent.parentElement) {
        const overflow = getComputedStyle(parent).overflowX;
        if (overflow !== 'visible') {
          const parentBox = parent.getBoundingClientRect();
          box = new DOMRect(Math.max(box.left, parentBox.left), box.top, Math.min(box.right, parentBox.right) - Math.max(box.left, parentBox.left), box.height);
        }
      }
      return box;
    };
    const items = [...document.querySelectorAll('header nav a')].map((a) => {
      const full = a.getBoundingClientRect();
      const painted = clip(a);
      return { text: (a.textContent ?? '').trim(), left: full.left, right: full.right, paintedWidth: painted.width, fullWidth: full.width };
    });
    return { view, scrollWidth: document.documentElement.scrollWidth, items };
  });
  expect(measured.scrollWidth).toBeLessThanOrEqual(measured.view);
  for (const item of measured.items) {
    expect(item.left, `${item.text} left edge`).toBeGreaterThanOrEqual(0);
    expect(item.right, `${item.text} right edge`).toBeLessThanOrEqual(measured.view);
    expect(item.paintedWidth, `${item.text} fully painted`).toBeGreaterThanOrEqual(item.fullWidth - 0.5);
  }
  await page.screenshot({ path: test.info().outputPath('account-header-390.png') });
});
