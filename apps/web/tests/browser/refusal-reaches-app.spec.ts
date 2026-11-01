// TC-2291: when the server refuses a sign-in (403 app_key_grant_refused), the app's request is rejected with
// the server's words, the page keeps showing them, and Approve is off (retrying cannot succeed). A server error
// is not a refusal: nothing is sent to the app and Approve stays available. Both widget pages are covered.
import { test, expect } from '@playwright/test';
import { EXPLORER_PERMISSION_POPUP_REQUEST } from '../../../../packages/capability-review/test/fixtures/index';
import { HOST } from './e2e-port';

const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const siwe = EXPLORER_PERMISSION_POPUP_REQUEST.replace(/^explorer\.tinycloud\.xyz/, HOST);
const WORDS = 'This site is not allowed in this test.';

const responses = (page: import('@playwright/test').Page) => page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string; success?: boolean; error?: { code: string; message: string } }> }).received.filter((m) => m.type === 'openkey:sign:response'));

for (const route of ['/widget/embed/sign', '/widget/sign']) {
  async function open(page: import('@playwright/test').Page, prepareStatus: number, prepareBody: unknown) {
    await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
    await page.route('**/api/keys/**', (r) => r.fulfill({ json: { key: { id: 'selected-key', address, publicKey: '0x02', keyIndex: 0, label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z' } } }));
    await page.route('**/api/auth/get-session**', (r) => r.fulfill({ json: { session: { id: 'test-session' }, user: { id: 'test-user' } } }));
    await page.route('**/api/delegate/authorize-sign-prepare', (r) => r.fulfill({ status: prepareStatus, json: prepareBody }));
    await page.goto('/__parity_harness');
    await page.evaluate((path) => {
      const iframe = document.createElement('iframe');
      iframe.id = 'sign';
      iframe.style.cssText = 'width:390px;height:844px;border:0';
      iframe.src = `${path}?origin=${encodeURIComponent(location.origin)}&requestId=refused-1&protocolVersion=1&keyId=selected-key`;
      const w = window as unknown as Window & { received: Array<{ type: string; success?: boolean; error?: { code: string; message: string } }> };
      w.received = [];
      window.addEventListener('message', (event) => {
        if (event.source === iframe.contentWindow && event.origin === location.origin) w.received.push(event.data);
      });
      document.body.append(iframe);
    }, route);
    await expect.poll(() => page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string }> }).received.some((m) => m.type === 'openkey:ready'))).toBe(true);
    await page.evaluate((message) => {
      document.querySelector<HTMLIFrameElement>('#sign')?.contentWindow?.postMessage(
        { type: 'openkey:sign:request', requestId: 'refused-1', protocolVersion: 1, authorizationProtocolVersion: 1, keyId: 'selected-key', jwk: { kty: 'EC' }, message },
        location.origin,
      );
    }, siwe);
    return page.frameLocator('#sign');
  }

  test(`${route}: a 403 refusal rejects the app's request with the server's words and turns Approve off`, async ({ page }) => {
    const frame = await open(page, 403, { error: WORDS, code: 'app_key_grant_refused' });
    await frame.getByRole('button', { name: 'Approve', exact: true }).click();
    await expect.poll(() => responses(page)).toEqual([expect.objectContaining({ success: false, error: { code: 'UNKNOWN', message: WORDS } })]);
    await expect(frame.getByText(WORDS)).toBeVisible();
    await expect(frame.getByRole('button', { name: 'Approve', exact: true })).toBeDisabled();
  });

  test(`${route}: a server error is not a refusal: the app hears nothing and Approve stays available`, async ({ page }) => {
    const frame = await open(page, 503, { error: 'Try again later.', code: 'app_key_grant_refused' });
    await frame.getByRole('button', { name: 'Approve', exact: true }).click();
    await expect(frame.getByRole('alert')).toContainText('Try again later.');
    await expect(frame.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
    expect(await responses(page)).toEqual([]);
  });
}

