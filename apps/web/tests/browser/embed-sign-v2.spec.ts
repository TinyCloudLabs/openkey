import { test, expect } from '@playwright/test';
import { HOST, ORIGIN } from './e2e-port';

const address = '0x1111111111111111111111111111111111111111';
const key = {
  id: 'selected-key', address, publicKey: '0x02', keyIndex: 0,
  label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z',
};
const message = `${HOST} wants you to sign in with your Ethereum account:\n${address}\n\nSign in\n\nURI: ${ORIGIN}\nVersion: 1\nChain ID: 1\nNonce: 12345678\nIssued At: 2026-10-15T00:00:00.000Z`;

// Exercise the real embed route in a frame, not a mocked approval button.
for (const viewport of [{ width: 1280, height: 800 }, { width: 390, height: 844 }]) {
test(`v2 review at ${viewport.width}px reads one owner key and waits for fresh host layout`, async ({ page }) => {
  await page.setViewportSize(viewport);
  const keyReads: string[] = [];
  let signCalls = 0;
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.route('**/api/keys/**', async (route) => {
    if (route.request().url().endsWith('/sign')) {
      signCalls++;
      await route.fulfill({ json: { signature: '0x00', address } });
      return;
    }
    keyReads.push(route.request().url());
    await route.fulfill({ json: { key } });
  });
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({ json: { session: { id: 'test-session' }, user: { id: 'test-user' } } }));
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const frame = document.createElement('iframe');
    frame.id = 'sign-v2';
    frame.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=phase-1&protocolVersion=2&keyId=selected-key`;
    document.body.append(frame);
    (window as Window & { received?: unknown[] }).received = [];
    window.addEventListener('message', (event) => {
      if (event.source === frame.contentWindow && event.origin === location.origin) {
        (window as unknown as Window & { received: unknown[] }).received.push(event.data);
      }
    });
  });
  const frame = page.frameLocator('#sign-v2');
  await expect.poll(() => page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string; requestId?: string }> }).received?.some(m => m.type === 'openkey:ready' && m.requestId === 'phase-1'))).toBe(true);
  await expect.poll(() => keyReads.length).toBe(1); // URL key hint starts the scoped read before the request arrives.
  await page.evaluate((siwe) => {
    const iframe = document.querySelector<HTMLIFrameElement>('#sign-v2');
    iframe?.contentWindow?.postMessage({ type: 'openkey:sign:request', requestId: 'phase-1', protocolVersion: 2, keyId: 'selected-key', message: siwe }, location.origin);
  }, message);
  await expect.poll(() => frame.locator('body').innerText()).toContain('Requested by');
  const approve = frame.getByRole('button', { name: 'Approve', exact: true });
  await expect(approve).toBeDisabled();
  await expect(frame.getByRole('dialog')).toContainText('Requested by');
  await expect(frame.getByRole('dialog')).toContainText('No capability payload');
  await expect.poll(() => page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string }> }).received.filter(m => m.type === 'openkey:resize').length)).toBeGreaterThan(0);
  const lastResize = await page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string; height: number; layoutId: number }> }).received.filter(m => m.type === 'openkey:resize').at(-1));
  expect(lastResize?.height).toBeGreaterThan(0);
  await page.evaluate(({ height, layoutId }) => {
    const iframe = document.querySelector<HTMLIFrameElement>('#sign-v2');
    iframe?.contentWindow?.postMessage({ type: 'openkey:layout-applied', requestId: 'wrong-phase', protocolVersion: 2, height, layoutId }, location.origin);
  }, lastResize!);
  await expect(approve).toBeDisabled();
  await page.evaluate(({ height, layoutId }) => {
    const iframe = document.querySelector<HTMLIFrameElement>('#sign-v2');
    iframe?.contentWindow?.postMessage({ type: 'openkey:layout-applied', requestId: 'phase-1', protocolVersion: 2, height, layoutId }, location.origin);
  }, lastResize!);
  await expect(approve).toBeDisabled(); // ack alone cannot approve before the frame is resized
  await page.evaluate(({ height, layoutId }) => {
    const iframe = document.querySelector<HTMLIFrameElement>('#sign-v2');
    const appliedHeight = Math.min(height, window.innerWidth <= 390 ? 300 : Math.floor(window.innerHeight * 0.85));
    if (iframe) iframe.style.height = `${appliedHeight}px`;
    iframe?.contentWindow?.postMessage({ type: 'openkey:layout-applied', requestId: 'phase-1', protocolVersion: 2, height: appliedHeight, layoutId }, location.origin);
  }, lastResize!);
  await expect(approve).toBeEnabled();
  const stableHeight = await page.locator('#sign-v2').evaluate((iframe) => iframe.getBoundingClientRect().height);
  if (viewport.width === 390) {
    const frameBox = await page.locator('#sign-v2').boundingBox();
    const approveBox = await approve.boundingBox();
    expect(frameBox && approveBox).toBeTruthy();
    expect(approveBox!.y + approveBox!.height).toBeLessThanOrEqual(frameBox!.y + frameBox!.height);
  }
  expect(keyReads).toHaveLength(1);
  expect(keyReads[0]).toContain('/api/keys/selected-key');
  const count = await page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string }> }).received.filter(m => m.type === 'openkey:resize').length);
  await expect.poll(() => page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string }> }).received.some(m => m.type === 'openkey:layout-ready'))).toBe(true);
  // Let browser layout and ResizeObserver flush without a wall-clock sleep.
  await frame.locator('[role="dialog"]').evaluate(() => new Promise<void>((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
  }));
  expect(await page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string }> }).received.filter(m => m.type === 'openkey:resize').length)).toBe(count);
  await frame.getByText('Advanced details').click();
  await expect(approve).toBeDisabled();
  await expect.poll(() => page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string }> }).received.some(m => m.type === 'openkey:layout-invalidated'))).toBe(true);
  await expect.poll(() => page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string }> }).received.filter(m => m.type === 'openkey:resize').length)).toBeGreaterThan(count);
  const nextResize = await page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string; height: number; layoutId: number }> }).received.filter(m => m.type === 'openkey:resize').at(-1));
  expect(nextResize!.layoutId).toBeGreaterThan(lastResize!.layoutId);
  await page.evaluate(({ height, layoutId }) => {
    document.querySelector<HTMLIFrameElement>('#sign-v2')?.contentWindow?.postMessage(
      { type: 'openkey:layout-applied', requestId: 'phase-1', protocolVersion: 2, height, layoutId },
      location.origin,
    );
  }, lastResize!);
  await expect(approve).toBeDisabled(); // stale same-phase ack cannot approve changed review
  await page.evaluate(({ layoutId, stableHeight }) => {
    // A real v2 SDK keeps its first approved height, even if review text
    // changes and the widget needs a fresh acknowledgement.
    document.querySelector<HTMLIFrameElement>('#sign-v2')?.contentWindow?.postMessage(
      { type: 'openkey:layout-applied', requestId: 'phase-1', protocolVersion: 2, height: stableHeight, layoutId },
      location.origin,
    );
  }, { layoutId: nextResize!.layoutId, stableHeight });
  await expect(approve).toBeEnabled();
  expect(await page.locator('#sign-v2').evaluate((iframe) => iframe.getBoundingClientRect().height)).toBe(stableHeight);
  await frame.locator('body').evaluate(() => sessionStorage.setItem('openkey_session_token', 'other-owner-session'));
  await approve.click();
  await frame.locator('body').evaluate(() => new Promise<void>((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
  }));
  expect(signCalls).toBe(0); // A key read under the old owner cannot authorize the new owner.
});
}
