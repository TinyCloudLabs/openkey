// TC-2272: on the embedded SDK sign-in, the expiry control shows only when the app's request opts in with
// `expiryChangeable: true` (an SDK that accepts a different signed expiry). Without it there is no control
// and the preview request carries no expiry, so the app's own expiry is signed.

import { test, expect, type Page } from '@playwright/test';
import { HOST } from './e2e-port';
import { EXPLORER_PERMISSION_POPUP_REQUEST } from '../../../../packages/capability-review/test/fixtures/index';

const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const siwe = EXPLORER_PERMISSION_POPUP_REQUEST.replace(/^explorer\.tinycloud\.xyz/, HOST);

async function open(page: Page, request: Record<string, unknown>) {
  const previews: Array<Record<string, unknown>> = [];
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.route('**/api/keys/**', (route) => route.fulfill({ json: { key: {
    id: 'selected-key', address, publicKey: '0x02', keyIndex: 0, label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z',
  } } }));
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({ json: { session: { id: 'test-session' }, user: { id: 'test-user' } } }));
  await page.route('**/api/delegate/authorize-sign-prepare', (route) => route.fulfill({ json: { authorizationContextToken: 'context-token' } }));
  await page.route('**/api/delegate/authorize-sign-preview', async (route) => {
    const body = route.request().postDataJSON() as Record<string, unknown>;
    previews.push(body);
    const ids = body.selectedActionIds as string[];
    const permissions = ids.map((id) => {
      const [service, space, path, ability] = id.split('\0');
      return { service, space, path, actions: [ability] };
    });
    await route.fulfill({ json: { signedMessage: siwe, previewApprovalToken: 'preview-token', selectedActionKeys: ids, permissions } });
  });
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const iframe = document.createElement('iframe');
    iframe.id = 'sign';
    iframe.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=optin&protocolVersion=2&keyId=selected-key`;
    (window as unknown as { received: unknown[] }).received = [];
    window.addEventListener('message', (event) => {
      if (event.source === iframe.contentWindow) (window as unknown as { received: unknown[] }).received.push(event.data);
    });
    document.body.append(iframe);
  });
  await expect.poll(() => page.evaluate(() => (window as unknown as { received: Array<{ type: string }> }).received.some((m) => m.type === 'openkey:ready'))).toBe(true);
  await page.evaluate(({ message, request }) => {
    document.querySelector<HTMLIFrameElement>('#sign')?.contentWindow?.postMessage(
      { type: 'openkey:sign:request', requestId: 'optin', protocolVersion: 2, authorizationProtocolVersion: 1, keyId: 'selected-key', jwk: { kty: 'EC' }, message, ...request },
      location.origin,
    );
  }, { message: siwe, request });
  const frame = page.frameLocator('#sign');
  await expect(frame.getByRole('dialog')).toContainText('Requested by');
  return { frame, previews };
}

async function approveOnce(page: Page, frame: ReturnType<Page['frameLocator']>) {
  await expect.poll(() => page.evaluate(() => (window as unknown as { received: Array<{ type: string }> }).received.some((m) => m.type === 'openkey:resize'))).toBe(true);
  const resize = await page.evaluate(() => (window as unknown as { received: Array<{ type: string; height: number; layoutId: number }> }).received.filter((m) => m.type === 'openkey:resize').at(-1)!);
  await page.evaluate(({ height, layoutId }) => {
    const iframe = document.querySelector<HTMLIFrameElement>('#sign');
    const h = Math.min(height, Math.floor(window.innerHeight * 0.85));
    if (iframe) iframe.style.height = `${h}px`;
    iframe?.contentWindow?.postMessage({ type: 'openkey:layout-applied', requestId: 'optin', protocolVersion: 2, height: h, layoutId }, location.origin);
  }, resize);
  const approve = frame.getByRole('button', { name: 'Approve', exact: true });
  await expect(approve).toBeEnabled();
  await approve.click();
}

test('without the opt-in there is no expiry control and the preview asks for no expiry', async ({ page }) => {
  const { frame, previews } = await open(page, {});
  await expect(frame.locator('.expiry')).toHaveCount(0);
  await approveOnce(page, frame);
  await expect.poll(() => previews.length).toBe(1);
  expect(previews[0]).not.toHaveProperty('expirationTime');
});

test('an opt-in of anything but true shows no control', async ({ page }) => {
  const { frame } = await open(page, { expiryChangeable: 'true' });
  await expect(frame.locator('.expiry')).toHaveCount(0);
});

test('with the opt-in the control shows, and a changed expiry is what the preview asks the server to sign', async ({ page }) => {
  const { frame, previews } = await open(page, { expiryChangeable: true });
  await expect(frame.locator('.expiry-line')).toHaveText(/Approval expires:\s*7d\s*\(Change\)/);
  await frame.getByRole('button', { name: '(Change)' }).click();
  await frame.getByLabel('Or type a time').fill('90m');
  await frame.getByLabel('Or type a time').press('Enter');
  await expect(frame.locator('.expiry-line')).toHaveText(/90m/);
  const before = Date.now();
  await approveOnce(page, frame);
  await expect.poll(() => previews.length).toBe(1);
  const asked = Date.parse(String(previews[0]!.expirationTime));
  expect(asked).toBeGreaterThanOrEqual(before + 90 * 60_000 - 1000);
  expect(asked).toBeLessThanOrEqual(Date.now() + 90 * 60_000 + 1000);
  expect(String(previews[0]!.expirationTime)).toBe(new Date(asked).toISOString());
});
