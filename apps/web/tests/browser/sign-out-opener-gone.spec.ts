import { test, expect } from '@playwright/test';
import { ORIGIN } from './e2e-port';

test('confirmed popup sign-out revokes even after losing its opener', async ({ page, context }) => {
  let revoked = false;
  let verified = false;
  await context.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/sign-out') {
      revoked = true;
      await route.fulfill({ json: { success: true } });
    } else if (path === '/api/auth/get-session') {
      if (revoked) verified = true;
      await route.fulfill({ json: revoked ? null : { session: { token: 'synthetic-session' } } });
    } else {
      await route.abort();
    }
  });
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    window.addEventListener('message', event => {
      if (event.origin === window.location.origin && event.data?.type === 'openkey:ready') {
        (event.source as Window).postMessage({
          type: 'openkey:sign-out:request', requestId: 'opener-gone', protocolVersion: 1,
        }, event.origin);
      }
    });
  });
  const opened = page.waitForEvent('popup');
  await page.evaluate(url => window.open(url), `${ORIGIN}/widget/sign-out?origin=${encodeURIComponent(ORIGIN)}`);
  const popup = await opened;
  await popup.getByRole('button', { name: 'Sign out', exact: true }).waitFor();
  await popup.evaluate(() => { window.opener = null; });
  const closed = popup.waitForEvent('close');
  await popup.getByRole('button', { name: 'Sign out', exact: true }).click();
  await closed;
  expect(revoked).toBe(true);
  expect(verified).toBe(true);
});
