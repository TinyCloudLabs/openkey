import { test, expect } from '@playwright/test';

const address = '0x1111111111111111111111111111111111111111';

test('failed selected-key read shows a stable cancellable error in the v2 iframe', async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.route('**/api/keys/**', (route) => route.fulfill({ status: 404, json: { error: 'Key not found' } }));
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({ json: { session: { id: 'test-session' }, user: { id: 'test-user' } } }));
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const iframe = document.createElement('iframe');
    iframe.id = 'sign-v2';
    iframe.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=phase-1&protocolVersion=2&keyId=selected-key`;
    (window as unknown as Window & { received: Array<{ type: string; height?: number; layoutId?: number; requestId?: string; success?: boolean }> }).received = [];
    window.addEventListener('message', (event) => {
      if (event.source === iframe.contentWindow && event.origin === location.origin) {
        (window as unknown as Window & { received: Array<{ type: string }> }).received.push(event.data);
      }
    });
    document.body.append(iframe);
  });
  await expect.poll(() => page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string; requestId?: string }> }).received.some(m => m.type === 'openkey:ready' && m.requestId === 'phase-1'))).toBe(true);
  const frame = page.frameLocator('#sign-v2');
  await expect(frame.getByText('Selected key could not be loaded.')).toBeVisible();
  await page.evaluate((address) => {
    document.querySelector<HTMLIFrameElement>('#sign-v2')?.contentWindow?.postMessage({
      type: 'openkey:sign:request', requestId: 'phase-1', protocolVersion: 2, keyId: 'selected-key',
      message: `localhost:5779 wants you to sign in with your Ethereum account:\n${address}\n\nSign in\n\nURI: http://localhost:5779\nVersion: 1\nChain ID: 1\nNonce: 12345678\nIssued At: 2026-10-15T00:00:00.000Z`,
    }, location.origin);
  }, address);
  await expect(frame.getByRole('button', { name: 'Cancel' })).toBeVisible();
  await expect.poll(() => page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string }> }).received.some(m => m.type === 'openkey:resize'))).toBe(true);
  await frame.getByRole('button', { name: 'Cancel' }).click();
  await expect.poll(() => page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string; success?: boolean }> }).received.some(m => m.type === 'openkey:sign:response' && m.success === false))).toBe(true);
});

test('v2 sign-in form can be measured and revealed when the embedded session is absent', async ({ page }) => {
  await page.route('**/api/auth/providers', (route) => route.fulfill({ json: { providers: [] } }));
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({ json: null }));
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const iframe = document.createElement('iframe');
    iframe.id = 'sign-v2';
    iframe.style.visibility = 'hidden';
    iframe.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=phase-auth&protocolVersion=2&keyId=selected-key`;
    (window as unknown as Window & { received: unknown[] }).received = [];
    window.addEventListener('message', (event) => {
      if (event.source === iframe.contentWindow && event.origin === location.origin) {
        (window as unknown as Window & { received: unknown[] }).received.push(event.data);
      }
    });
    document.body.append(iframe);
  });
  await expect.poll(() => page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string }> }).received.some(m => m.type === 'openkey:ready'))).toBe(true);
  await page.evaluate((address) => {
    document.querySelector<HTMLIFrameElement>('#sign-v2')?.contentWindow?.postMessage({
      type: 'openkey:sign:request', requestId: 'phase-auth', protocolVersion: 2, keyId: 'selected-key',
      message: `localhost:5779 wants you to sign in with your Ethereum account:\n${address}\n\nSign in\n\nURI: http://localhost:5779\nVersion: 1\nChain ID: 1\nNonce: 12345678\nIssued At: 2026-10-15T00:00:00.000Z`,
    }, location.origin);
  }, address);
  await expect.poll(() => page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string }> }).received.some(m => m.type === 'openkey:resize'))).toBe(true);
  const resize = await page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string; height: number; layoutId: number }> }).received.find(m => m.type === 'openkey:resize')!);
  await page.evaluate(({ height, layoutId }) => {
    const iframe = document.querySelector<HTMLIFrameElement>('#sign-v2');
    if (!iframe) return;
    iframe.style.height = `${height}px`;
    iframe.style.visibility = 'visible';
    iframe.contentWindow?.postMessage({ type: 'openkey:layout-applied', requestId: 'phase-auth', protocolVersion: 2, height, layoutId }, location.origin);
  }, resize);
  await expect(page.frameLocator('#sign-v2').getByText('Sign in to review and sign this message')).toBeVisible();
});
