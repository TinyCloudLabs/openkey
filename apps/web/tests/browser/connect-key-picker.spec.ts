// TC-1496: both connect widgets use the shared key picker. With several keys
// they lead with the primary key (badge, "Use a different key", separate-owner
// warning) and return the chosen key's `keyId`. Every API call is answered by
// `page.route`; no API server runs.

import { test, expect, type Page, type FrameLocator, type Locator } from '@playwright/test';

const key = (id: string, keyIndex: number, address: string, isPrimary: boolean, keyType = 'MANAGED') =>
  ({ id, address, publicKey: '0x', keyIndex, label: null, keyType, isPrimary, createdAt: '2026-01-01T00:00:00Z' });
const keys = [
  key('key_0', 0, '0xd559ccd9eb87c530a9a349262669386de93cf412', true),
  key('key_1', 1, '0x2222222222222222222222222222222222222222', false),
  key('key_2', 2, '0x3333333333333333333333333333333333333333', false, 'EXTERNAL'),
];
const origin = 'http://localhost:5779';

type Message = { type: string; success?: boolean; keyId?: string; address?: string; keyType?: string };

type Recording = Window & { received?: Message[] };

const responses = (page: Page) => page.evaluate(() => {
  const recording: Recording = window;
  return (recording.received ?? []).filter((m) => m.type === 'openkey:auth:response');
});

async function mockApi(page: Page, list: unknown[]) {
  await page.route('**/api/keys', (route) => route.fulfill({ json: { keys: list } }));
  await page.route('**/api/auth/get-session**', (route) =>
    route.fulfill({ json: { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'sam@example.test', name: 'Sam' } } }));
}

async function expectPrimaryFirst(root: Page | FrameLocator, pick: (root: Page | FrameLocator, name: RegExp) => Locator) {
  await expect(root.getByText('Connect with your primary key:')).toBeVisible();
  await expect(pick(root, /Key 0/)).toContainText('Primary');
  await expect(pick(root, /Key 1/)).toHaveCount(0);
  await root.getByRole('button', { name: 'Use a different key' }).click();
  await expect(root.getByText(/Each key is a separate account owner, with its own data and spaces/)).toBeVisible();
  await expect(pick(root, /Key 1/)).toBeVisible();
  await expect(pick(root, /Key 2/)).toContainText('(External)');
  await expect(root.getByText('Primary', { exact: true })).toHaveCount(1);
}

const button = (root: Page | FrameLocator, name: RegExp) => root.getByRole('button', { name });

test.describe('TC-1496 connect widgets use the shared key picker', () => {
  test('popup widget: primary-first, and a non-primary pick returns that keyId', async ({ page }) => {
    await mockApi(page, keys);
    await page.addInitScript(() => {
      const received: Message[] = [];
      const recording: Recording = window;
      recording.received = received;
      Object.defineProperty(window, 'opener', { value: { postMessage: (data: Message) => received.push(data), closed: false }, configurable: true });
    });
    await page.goto(`/widget/connect?origin=${encodeURIComponent(origin)}`);

    await expectPrimaryFirst(page, button);
    // Nothing is returned until the user picks.
    expect(await responses(page)).toEqual([]);

    await button(page, /Key 1/).click();
    const sent = await responses(page);
    expect(sent).toEqual([{ type: 'openkey:auth:response', success: true, address: keys[1]!.address, keyId: 'key_1', keyType: 'MANAGED' }]);
  });

  test('popup widget: the primary key is picked in one click', async ({ page }) => {
    await mockApi(page, keys);
    await page.addInitScript(() => {
      const received: Message[] = [];
      const recording: Recording = window;
      recording.received = received;
      Object.defineProperty(window, 'opener', { value: { postMessage: (data: Message) => received.push(data), closed: false }, configurable: true });
    });
    await page.goto(`/widget/connect?origin=${encodeURIComponent(origin)}`);
    await button(page, /Key 0/).click();
    const sent = await responses(page);
    expect(sent.map((m) => m.keyId)).toEqual(['key_0']);
  });

  test('embed widget: primary-first, and a non-primary pick returns that keyId', async ({ page }) => {
    await mockApi(page, keys);
    await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
    await page.goto('/__parity_harness');
    await page.evaluate((o) => {
      const frame = document.createElement('iframe');
      frame.id = 'connect';
      frame.src = `/widget/embed/connect?origin=${encodeURIComponent(o)}`;
      document.body.append(frame);
      const recording: Recording = window;
      recording.received = [];
      window.addEventListener('message', (event) => {
        if (event.source === frame.contentWindow && event.origin === o) recording.received?.push(event.data);
      });
    }, origin);
    const frame = page.frameLocator('#connect');

    await expectPrimaryFirst(frame, button);
    expect(await responses(page)).toEqual([]);

    await button(frame, /Key 2/).click();
    await expect.poll(() => responses(page).then((list) => list.map((m) => m.keyId))).toEqual(['key_2']);
  });
});
