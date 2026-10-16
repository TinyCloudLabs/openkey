import { readFileSync } from 'node:fs';
import { test, expect } from '@playwright/test';

const address = '0x1111111111111111111111111111111111111111';
const key = {
  id: 'selected-key', address, publicKey: '0x02', keyIndex: 0,
  label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z',
};
const message = `localhost:5779 wants you to sign in with your Ethereum account:\n${address}\n\nSign in\n\nURI: http://localhost:5779\nVersion: 1\nChain ID: 1\nNonce: 12345678\nIssued At: 2026-10-15T00:00:00.000Z`;

// Serve the actual 0.12.1-beta.0 browser bundle from this checkout, not a protocol stub.
for (const suspendFrames of [false, true]) {
test(`SDK v2 Sign confirms layout with ${suspendFrames ? 'suspended' : 'normal'} animation frames`, async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'fixture-session'));
  if (suspendFrames) {
    // A hidden cross-origin iframe can have animation frames suspended.
    await page.addInitScript(() => {
      if (location.pathname === '/widget/embed/sign') {
        window.requestAnimationFrame = () => 0;
      }
    });
  }
  await page.route('**/__sdk_beta.mjs', (route) => route.fulfill({
    contentType: 'text/javascript',
    body: readFileSync(new URL('../../../../packages/sdk/dist/index.mjs', import.meta.url)),
  }));
  let signCalls = 0;
  await page.route('**/api/keys/**', (route) => {
    if (route.request().url().endsWith('/sign')) {
      signCalls++;
      return route.fulfill({ json: { signature: '0x00', address } });
    }
    return route.fulfill({ json: { key } });
  });
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({
    json: { session: { id: 'fixture-session' }, user: { id: 'fixture-user' } },
  }));
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    (window as any).widgetEvents = [];
    window.addEventListener('message', (event) => {
      if (event.origin === 'http://127.0.0.1:5779' && event.data?.type?.startsWith('openkey:')) {
        (window as any).widgetEvents.push(event.data.type);
      }
    });
  });
  await page.addScriptTag({
    type: 'module',
    content: `import { OpenKey } from '/__sdk_beta.mjs'; window.OpenKeyBeta = OpenKey;`,
  });
  await expect.poll(() => page.evaluate(() => typeof (window as any).OpenKeyBeta)).toBe('function');
  await page.evaluate((siwe) => {
    const sdk = new (window as any).OpenKeyBeta({ host: 'http://127.0.0.1:5779', oauthHost: 'http://127.0.0.1:5779', mode: 'iframe' });
    (window as any).signState = 'pending';
    (window as any).signOutcome = sdk.signMessage({ message: siwe, keyId: 'selected-key' })
      .then(() => { (window as any).signState = 'signed'; }, () => { (window as any).signState = 'rejected'; });
  }, message);

  await expect.poll(() => page.frames().find(frame => frame.url().includes('/widget/embed/sign?'))
    ?.locator('[role="dialog"]').count() ?? 0).toBe(1);
  const frame = page.frames().find(candidate => candidate.url().includes('/widget/embed/sign?'))!;
  const approve = frame.locator('button:has-text("Approve")');
  await expect.poll(() => page.evaluate(() => (window as any).widgetEvents.includes('openkey:resize'))).toBe(true);
  await expect.poll(() => page.evaluate(() => (window as any).widgetEvents.includes('openkey:layout-ready'))).toBe(true);
  await expect(approve).toBeEnabled();
  await expect.poll(() => page.evaluate(() => (window as any).signOutcome instanceof Promise)).toBe(true);
  await approve.click();
  await expect.poll(() => page.evaluate(() => (window as any).signState)).toBe('signed');
  expect(signCalls).toBe(1);
});
}

test('legacy host Sign stays actionable without a v2 layout exchange', async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'fixture-session'));
  let signCalls = 0;
  await page.route('**/api/keys/**', (route) => {
    if (route.request().url().endsWith('/sign')) {
      signCalls++;
      return route.fulfill({ json: { signature: '0x00', address } });
    }
    return route.fulfill({ json: { key } });
  });
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({
    json: { session: { id: 'fixture-session' }, user: { id: 'fixture-user' } },
  }));
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const frame = document.createElement('iframe');
    frame.id = 'legacy-sign';
    frame.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}`;
    (window as any).widgetEvents = [];
    window.addEventListener('message', (event) => {
      if (event.source === frame.contentWindow && event.origin === location.origin) {
        (window as any).widgetEvents.push({ type: event.data?.type, layoutId: event.data?.layoutId });
      }
    });
    document.body.append(frame);
  });
  await expect.poll(() => page.evaluate(() => (window as any).widgetEvents.some((event: { type: string }) => event.type === 'openkey:ready'))).toBe(true);
  await page.evaluate((siwe) => {
    document.querySelector<HTMLIFrameElement>('#legacy-sign')?.contentWindow?.postMessage(
      { type: 'openkey:sign:request', keyId: 'selected-key', message: siwe }, location.origin,
    );
  }, message);
  const approve = page.frameLocator('#legacy-sign').getByRole('button', { name: 'Approve', exact: true });
  await expect(approve).toBeEnabled();
  await approve.click();
  await expect.poll(() => signCalls).toBe(1);
  await expect.poll(() => page.evaluate(() => (window as any).widgetEvents.some((event: { type: string }) => event.type === 'openkey:sign:response'))).toBe(true);
  expect(await page.evaluate(() => (window as any).widgetEvents.some((event: { type: string; layoutId?: number }) =>
    event.type === 'openkey:layout-ready' || event.layoutId !== undefined))).toBe(false);
});
