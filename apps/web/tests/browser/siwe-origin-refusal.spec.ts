import { test, expect, type Page } from '@playwright/test';

// TC-1486: the real sign routes, in a frame, must refuse a SIWE that does not
// name the requesting origin — with no approve control and no /sign call.
const address = '0x1111111111111111111111111111111111111111';
const key = {
  id: 'selected-key', address, publicKey: '0x02', keyIndex: 0,
  label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z',
};
const siwe = (domain: string, uri: string) =>
  `${domain} wants you to sign in with your Ethereum account:\n${address}\n\nSign in\n\nURI: ${uri}\nVersion: 1\nChain ID: 1\nNonce: 12345678\nIssued At: 2026-10-15T00:00:00.000Z`;

type Received = Array<{ type: string; success?: boolean; error?: { code: string; message: string }; data?: unknown }>;

async function openFrame(page: Page, route: string, query: string) {
  const apiCalls: string[] = [];
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.route('**/api/keys/**', async (route) => {
    apiCalls.push(route.request().url());
    await route.fulfill({ json: route.request().url().endsWith('/sign') ? { signature: '0x00', address } : { key } });
  });
  await page.route('**/api/delegate/**', async (route) => {
    apiCalls.push(route.request().url());
    await route.fulfill({ status: 500, json: { error: 'must not be reached' } });
  });
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({ json: { session: { id: 'test-session' }, user: { id: 'test-user' } } }));
  await page.goto('/__parity_harness');
  await page.evaluate(([src]) => {
    const frame = document.createElement('iframe');
    frame.id = 'sign';
    frame.src = src!.replace('ORIGIN', encodeURIComponent(location.origin));
    document.body.append(frame);
    (window as Window & { received?: unknown[] }).received = [];
    window.addEventListener('message', (event) => {
      if (event.source === frame.contentWindow && event.origin === location.origin) {
        (window as unknown as Window & { received: unknown[] }).received.push(event.data);
      }
    });
  }, [`${route}?origin=ORIGIN${query}`]);
  await expect.poll(() => page.evaluate(() => (window as unknown as Window & { received: Received }).received.some((m) => m.type === 'openkey:ready'))).toBe(true);
  return apiCalls;
}

function send(page: Page, payload: Record<string, unknown>) {
  return page.evaluate((data) => {
    document.querySelector<HTMLIFrameElement>('#sign')?.contentWindow?.postMessage(data, location.origin);
  }, payload);
}

const received = (page: Page) => page.evaluate(() => (window as unknown as Window & { received: Received }).received);

for (const surface of [
  { name: 'popup widget', route: '/widget/sign', query: '', proto: 1 },
  { name: 'embed widget', route: '/widget/embed/sign', query: '&requestId=phase-1&protocolVersion=2&keyId=selected-key', proto: 2 },
]) {
  test(`${surface.name} refuses a SIWE naming another relying party`, async ({ page }) => {
    const apiCalls = await openFrame(page, surface.route, surface.query);
    await send(page, {
      type: 'openkey:sign:request', requestId: 'phase-1', protocolVersion: surface.proto, keyId: 'selected-key',
      message: siwe('internal.tinycloud.xyz', 'https://internal.tinycloud.xyz'),
    });
    const frame = page.frameLocator('#sign');
    await expect(frame.getByTestId('siwe-origin-refusal')).toBeVisible();
    await expect(frame.getByTestId('siwe-origin-refusal')).toContainText('OpenKey refused this request');
    await expect(frame.getByRole('button', { name: /approve/i })).toHaveCount(0);
    await expect.poll(async () => (await received(page)).find((m) => m.type === 'openkey:sign:response')?.error?.message)
      .toContain('SIWE_ORIGIN_REFUSED: domain-mismatch');
    expect((await received(page)).some((m) => m.type === 'openkey:sign:response' && m.success === true)).toBe(false);
    expect(apiCalls.filter((url) => url.endsWith('/sign') || url.includes('authorize-sign'))).toEqual([]);
  });

  test(`${surface.name} refuses a matching domain with a mismatched URI`, async ({ page }) => {
    const apiCalls = await openFrame(page, surface.route, surface.query);
    await send(page, {
      type: 'openkey:sign:request', requestId: 'phase-1', protocolVersion: surface.proto, keyId: 'selected-key',
      message: siwe('localhost:5779', 'https://internal.tinycloud.xyz'),
    });
    await expect(page.frameLocator('#sign').getByTestId('siwe-origin-refusal')).toHaveAttribute('data-refusal-code', 'uri-mismatch');
    expect(apiCalls.filter((url) => url.endsWith('/sign') || url.includes('authorize-sign'))).toEqual([]);
  });
}

test('a SIWE on the unattributed legacy path is refused', async ({ page }) => {
  const apiCalls: string[] = [];
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.route('**/api/keys/**', async (route) => {
    apiCalls.push(route.request().url());
    await route.fulfill({ json: route.request().url().endsWith('/sign') ? { signature: '0x00', address } : { key } });
  });
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({ json: { session: { id: 'test-session' }, user: { id: 'test-user' } } }));
  await page.goto('/__parity_harness');
  // No `origin` query parameter: the widget cannot attribute the requester.
  await page.evaluate(() => {
    const frame = document.createElement('iframe');
    frame.id = 'sign';
    frame.src = '/widget/sign';
    (window as Window & { ready?: boolean }).ready = false;
    window.addEventListener('message', (event) => {
      if (event.source === frame.contentWindow && event.data?.type === 'openkey:ready') {
        (window as Window & { ready?: boolean }).ready = true;
      }
    });
    document.body.append(frame);
  });
  await expect.poll(() => page.evaluate(() => (window as Window & { ready?: boolean }).ready)).toBe(true);
  await page.evaluate((message) => {
    document.querySelector<HTMLIFrameElement>('#sign')?.contentWindow?.postMessage({ type: 'openkey:sign:request', keyId: 'selected-key', message }, '*');
  }, siwe('localhost:5779', 'http://localhost:5779'));
  await expect(page.frameLocator('#sign').getByTestId('siwe-origin-refusal')).toHaveAttribute('data-refusal-code', 'unattributed-origin');
  expect(apiCalls.filter((url) => url.endsWith('/sign'))).toEqual([]);
});
