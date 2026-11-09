import { test, expect } from '@playwright/test';
import { HOST, ORIGIN } from './e2e-port';

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
  await expect(frame.getByTestId('signing-key-refusal')).toBeVisible();
  await page.evaluate(([address, host, origin]) => {
    document.querySelector<HTMLIFrameElement>('#sign-v2')?.contentWindow?.postMessage({
      type: 'openkey:sign:request', requestId: 'phase-1', protocolVersion: 2, keyId: 'selected-key',
      message: `${host} wants you to sign in with your Ethereum account:\n${address}\n\nSign in\n\nURI: ${origin}\nVersion: 1\nChain ID: 1\nNonce: 12345678\nIssued At: 2026-10-15T00:00:00.000Z`,
    }, location.origin);
  }, [address, HOST, ORIGIN]);
  await expect(frame.getByTestId('signing-key-back')).toBeVisible();
  await expect.poll(() => page.evaluate(() => (window as unknown as Window & { received: Array<{ type: string }> }).received.some(m => m.type === 'openkey:resize'))).toBe(true);
  await frame.getByTestId('signing-key-back').click();
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
  await page.evaluate(([address, host, origin]) => {
    document.querySelector<HTMLIFrameElement>('#sign-v2')?.contentWindow?.postMessage({
      type: 'openkey:sign:request', requestId: 'phase-auth', protocolVersion: 2, keyId: 'selected-key',
      message: `${host} wants you to sign in with your Ethereum account:\n${address}\n\nSign in\n\nURI: ${origin}\nVersion: 1\nChain ID: 1\nNonce: 12345678\nIssued At: 2026-10-15T00:00:00.000Z`,
    }, location.origin);
  }, [address, HOST, ORIGIN]);
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

for (const surface of ['sign', 'embed/sign', 'sign-typed-data', 'embed/sign-typed-data']) {
  test(`${surface} refuses an archived pinned key before signing`, async ({ page }) => {
    let signingRequests = 0;
    await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
    await page.route('**/api/auth/get-session**', (route) => route.fulfill({
      json: { session: { id: 's', userId: 'u' }, user: { id: 'u' } },
    }));
    await page.route('**/api/keys/**', (route) => {
      if (route.request().method() !== 'GET') {
        signingRequests++;
        return route.fulfill({ status: 500, json: { error: 'Archived key must not be submitted' } });
      }
      return route.fulfill({ json: { key: {
        id: 'archived-key', address, publicKey: '0x', keyIndex: 0,
        label: 'Archived account', keyType: 'MANAGED', isPrimary: false,
        archivedAt: '2026-11-01T00:00:00Z', createdAt: '2026-01-01T00:00:00Z',
      } } });
    });
    await page.goto('/__parity_harness');
    await page.evaluate((surface) => {
      const frame = document.createElement('iframe');
      frame.id = 'archived-sign';
      frame.src = `/widget/${surface}?origin=${encodeURIComponent(location.origin)}`;
      (window as Window & { keyRefusals?: unknown[] }).keyRefusals = [];
      window.addEventListener('message', (event) => {
        if (event.source !== frame.contentWindow || event.origin !== location.origin) return;
        if (event.data?.success === false) {
          (window as Window & { keyRefusals?: unknown[] }).keyRefusals?.push(event.data);
          return;
        }
        if (event.data?.type !== 'openkey:ready') return;
        frame.contentWindow?.postMessage(surface.endsWith('sign-typed-data')
          ? { type: 'openkey:signTypedData:request', data: {
              keyId: 'archived-key', domain: { name: 'QA' }, types: { Note: [{ name: 'text', type: 'string' }] },
              primaryType: 'Note', message: { text: 'Review this request' },
            } }
          : { type: 'openkey:sign:request', keyId: 'archived-key', message: 'Review this request' },
          location.origin);
      });
      document.body.append(frame);
    }, surface);
    const frame = page.frameLocator('#archived-sign');
    await expect(frame.getByRole('button', { name: /^(Approve|Sign|Sign Data)$/ })).toHaveCount(0);
    await expect(frame.getByRole('button', { name: 'Back to app', exact: true })).toBeVisible();
    await frame.getByRole('button', { name: 'Back to app', exact: true }).click();
    await expect.poll(() => page.evaluate(() =>
      (window as Window & { keyRefusals?: Array<{ error?: { code?: string; message?: string } }> }).keyRefusals?.at(-1)?.error,
    )).toMatchObject({ code: 'NO_KEY', message: expect.stringMatching(/archived.*connect/i) });
    expect(signingRequests).toBe(0);
  });
}
