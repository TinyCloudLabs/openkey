import { test, expect, type Page } from '@playwright/test';

// Hardening: registry record signing. The real sign routes, in a frame, show the refusal INSTEAD of the approval
// card for a registry record payload from an origin that is not TinyCloud One / Home: no approve control and no
// /sign call. Other messages still reach the approval card.
const address = '0x1111111111111111111111111111111111111111';
const key = {
  id: 'selected-key', address, publicKey: '0x02', keyIndex: 0,
  label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z',
};
const NODE_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const V1 = JSON.stringify({
  version: 1, subject: `did:pkh:eip155:1:${address}`, multiaddrs: ['/dns4/node.example/tcp/443/https'],
  updated_at: '2026-11-22T14:00:00.000Z', sequence: 7,
});
const V2 = JSON.stringify({
  version: 2, subject: `did:pkh:eip155:1:${address}`, nodes: [{ did: NODE_DID, url: 'https://node.example' }], spaces: [],
  encryptionNode: NODE_DID, updated_at: '2026-11-22T14:00:00.000Z', sequence: 8,
});
const hex = (text: string) => `0x${Buffer.from(text, 'utf8').toString('hex')}`;

const TITLE = "This app's request can't be signed";
const BODY = {
  popup: "It would set which TinyCloud node holds your data. Only TinyCloud's own apps can ask for that, so this app can't. Nothing was signed. You can close this window.",
  embed: "It would set which TinyCloud node holds your data. Only TinyCloud's own apps can ask for that, so this app can't. Nothing was signed. You can go back to the app.",
};

type Received = Array<{ type: string; success?: boolean; error?: { code: string; message: string } }>;

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
  { name: 'popup widget', variant: 'popup' as const, route: '/widget/sign', query: '', proto: 1, button: 'Close' },
  { name: 'embed widget', variant: 'embed' as const, route: '/widget/embed/sign', query: '&requestId=phase-1&protocolVersion=2&keyId=selected-key', proto: 2, button: 'Back to the app' },
]) {
  for (const [label, message] of [['v1 text', V1], ['v2 hex', hex(V2)]] as const) {
    test(`${surface.name} refuses a registry record (${label}) from another origin`, async ({ page }) => {
      const apiCalls = await openFrame(page, surface.route, surface.query);
      await send(page, { type: 'openkey:sign:request', requestId: 'phase-1', protocolVersion: surface.proto, keyId: 'selected-key', message });
      const refusal = page.frameLocator('#sign').getByTestId('registry-record-refusal');
      await expect(refusal).toBeVisible();
      await expect(refusal).toContainText(TITLE);
      await expect(refusal).toContainText(BODY[surface.variant]);
      await expect(refusal.getByRole('button', { name: surface.button })).toBeVisible();
      await expect(page.frameLocator('#sign').getByRole('button', { name: /approve/i })).toHaveCount(0);
      await expect.poll(async () => (await received(page)).find((m) => m.type === 'openkey:sign:response')?.error?.message)
        .toBe('REGISTRY_RECORD_SIGN_REFUSED');
      expect((await received(page)).some((m) => m.type === 'openkey:sign:response' && m.success === true)).toBe(false);
      expect(apiCalls.filter((url) => url.endsWith('/sign') || url.includes('authorize-sign'))).toEqual([]);
    });
  }

  test(`${surface.name} still shows the approval card for an ordinary message`, async ({ page }) => {
    await openFrame(page, surface.route, surface.query);
    await send(page, {
      type: 'openkey:sign:request', requestId: 'phase-1', protocolVersion: surface.proto, keyId: 'selected-key',
      message: JSON.stringify({ hello: 'world', sequence: 1 }),
    });
    await expect(page.frameLocator('#sign').getByRole('heading', { name: 'Sign Message' }).first()).toBeVisible();
    await expect(page.frameLocator('#sign').getByTestId('registry-record-refusal')).toHaveCount(0);
    expect((await received(page)).some((m) => m.type === 'openkey:sign:response')).toBe(false);
  });
}
