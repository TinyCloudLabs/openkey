// TC-2927: the extra warning screen for decrypt, key creation, or blocking and unblocking keys on the encryption
// network, or on keys outside the app's own area, on the real embedded sign-in route (synthetic API). Approve opens the
// screen first; the owner rejects or allows each permission, neither chosen for them; a rejection narrows the request
// and the rest is still approved; an allow travels to the server with the preview. Set TC2927_SHOTS_DIR to save 390px
// screenshots.

import { test, expect, type FrameLocator, type Page } from '@playwright/test';
import { HOST, ORIGIN } from './e2e-port';
import { FIXTURE_META, makeRecapResource, siweWithResources } from '../../../../packages/capability-review/test/fixtures/index';
import { TERMS_ACCEPTED } from './terms-fixtures';

const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const SHOTS = process.env.TC2927_SHOTS_DIR;
const owner = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const urn = (rest: string) => `urn:tinycloud:encryption:${owner}:default${rest}`;
const E = 'tinycloud.encryption/';

const network = { [urn('')]: { [`${E}decrypt`]: [{}], [`${E}network.create`]: [{}] } };
const sharePrefix = { [urn('/share/')]: { [`${E}decrypt`]: [{}] } };
const kvGet = { [FIXTURE_META.ownSpace]: { 'tinycloud.kv/get': [{}] } };

type Body = Record<string, unknown>;

async function open(page: Page, resources: Array<Record<string, Record<string, unknown[]>>>, options: { exactBytes?: boolean } = {}) {
  const message = siweWithResources(resources.map(makeRecapResource), { domain: HOST, uri: ORIGIN });
  const previews: Body[] = [];
  const authorizes: Body[] = [];
  const signs: Body[] = [];
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.route('**/api/keys/**', (route) => route.fulfill({ json: { key: {
    id: 'selected-key', address, publicKey: '0x02', keyIndex: 0, label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z',
  } } }));
  await page.route('**/api/keys/selected-key/sign', async (route) => {
    signs.push(route.request().postDataJSON() as Body);
    await route.fulfill({ json: { signature: '0x' + '11'.repeat(65), address } });
  });
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({ json: { session: { id: 'test-session' }, user: { id: 'test-user' } } }));
  await page.route('**/api/account/terms', (route) => route.fulfill({ json: TERMS_ACCEPTED }));
  await page.route('**/api/delegate/authorize-sign-prepare', (route) => route.fulfill({
    headers: { Date: new Date().toUTCString() },
    json: { authorizationContextToken: 'context-token', expiresAt: new Date(Date.now() + 300_000).toISOString() },
  }));
  let lastPreview: { signedMessage: string; selectedActionKeys: string[]; permissions: unknown[] } | null = null;
  await page.route('**/api/delegate/authorize-sign-preview', async (route) => {
    const body = route.request().postDataJSON() as Body;
    previews.push(body);
    const ids = body.selectedActionIds as string[];
    const permissions = ids.map((id) => {
      const [service, space, path, ability] = id.split('\0');
      return { service, space, path, actions: [ability] };
    });
    lastPreview = { signedMessage: message, selectedActionKeys: ids, permissions };
    await route.fulfill({
      headers: { Date: new Date().toUTCString() },
      json: { signedMessage: message, authorizationContextToken: 'context-token', previewApprovalToken: `preview-${previews.length}`, previewApprovalExpiresAt: new Date(Date.now() + 60_000).toISOString(), selectedActionKeys: ids, permissions },
    });
  });
  await page.route('**/api/delegate/authorize-sign', async (route) => {
    authorizes.push(route.request().postDataJSON() as Body);
    await route.fulfill({ headers: { Date: new Date().toUTCString() }, json: { signature: '0x' + '22'.repeat(65), address, ...lastPreview, protocolVersion: 1 } });
  });
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const iframe = document.createElement('iframe');
    iframe.id = 'sign';
    iframe.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=elevated&protocolVersion=1&keyId=selected-key`;
    (window as unknown as { received: unknown[] }).received = [];
    window.addEventListener('message', (event) => {
      if (event.source === iframe.contentWindow) (window as unknown as { received: unknown[] }).received.push(event.data);
    });
    document.body.append(iframe);
  });
  await expect.poll(() => page.evaluate(() => (window as unknown as { received: Array<{ type: string }> }).received.some((m) => m.type === 'openkey:ready'))).toBe(true);
  await page.evaluate(({ message, exactBytes }) => {
    document.querySelector<HTMLIFrameElement>('#sign')?.contentWindow?.postMessage(
      { type: 'openkey:sign:request', requestId: 'elevated', ...(exactBytes ? {} : { protocolVersion: 1, authorizationProtocolVersion: 1 }), keyId: 'selected-key', jwk: { kty: 'EC' }, message },
      location.origin,
    );
  }, { message, exactBytes: options.exactBytes === true });
  const frame = page.frameLocator('#sign');
  await expect(frame.getByRole('dialog')).toContainText('Requested by');
  return { frame, previews, authorizes, signs };
}

const responses = (page: Page) => page.evaluate(() => (window as unknown as { received: Array<Record<string, unknown>> }).received.filter((m) => m.type === 'openkey:sign:response'));
const approve = (frame: FrameLocator) => frame.locator('button.approve');
const sized = (page: Page) => page.evaluate(() => {
  const f = document.querySelector<HTMLIFrameElement>('#sign')!;
  f.style.cssText = 'width:390px;height:1100px;border:0;display:block';
  document.body.style.margin = '0';
});
const shot = async (page: Page, name: string) => {
  if (SHOTS) await page.locator('#sign').screenshot({ path: `${SHOTS}/${name}.png` });
};
const isElevated = (id: string) => /encryption\/(decrypt|key\.create|key\.block|key\.unblock)$/.test(id) && !id.includes('/apps/');

test.use({ viewport: { width: 390, height: 1100 } });

test('Approve opens the warning screen first; nothing is chosen for the owner and nothing is sent yet', async ({ page }) => {
  const { frame, authorizes } = await open(page, [network, kvGet]);
  await sized(page);
  await expect(approve(frame)).toBeEnabled();
  await approve(frame).click();
  await expect(frame.locator('#elevated-title')).toContainText('is asking for more access');
  await expect(frame.getByRole('heading', { level: 2, name: /Unlock all your encrypted data/ })).toBeVisible();
  await expect(frame.getByRole('button', { name: 'Reject this permission' })).toBeVisible();
  await expect(frame.getByRole('button', { name: 'Allow this permission' })).toBeVisible();
  await expect(frame.getByRole('button', { name: 'Continue' })).toBeDisabled();
  expect(authorizes).toHaveLength(0);
  expect(await responses(page)).toHaveLength(0);
  await shot(page, '390-card-a-network');
});

test('Allow: the next preview carries the allow, the request signs once, and the app gets the whole request', async ({ page }) => {
  const { frame, previews, authorizes } = await open(page, [network, kvGet]);
  await approve(frame).click();
  await frame.getByRole('button', { name: 'Allow this permission' }).click();
  await frame.getByRole('button', { name: 'Continue' }).click();
  await expect.poll(async () => (await responses(page)).length).toBe(1);
  const last = previews.at(-1)!;
  const allowed = (last.elevatedDecision as { allowed: string[] }).allowed;
  expect(allowed.length).toBeGreaterThan(0);
  expect(allowed.every(isElevated)).toBe(true);
  expect((last.selectedActionIds as string[]).filter(isElevated).sort()).toEqual([...allowed].sort());
  expect(authorizes).toHaveLength(1);
  expect(authorizes[0]).toMatchObject({ previewApprovalToken: `preview-${previews.length}` });
  const [response] = await responses(page);
  expect(response).toMatchObject({ success: true });
});

test('Reject: the permission leaves the request, no allow is sent for it, and the rest is still approved', async ({ page }) => {
  const { frame, previews, authorizes } = await open(page, [network, kvGet]);
  await approve(frame).click();
  await frame.getByRole('button', { name: 'Reject this permission' }).click();
  await expect(frame.getByText('You rejected this permission.')).toBeVisible();
  await frame.getByRole('button', { name: 'Continue' }).click();
  await expect.poll(async () => (await responses(page)).length).toBe(1);
  const last = previews.at(-1)!;
  expect((last.selectedActionIds as string[]).filter(isElevated)).toEqual([]);
  expect(last).not.toHaveProperty('elevatedDecision');
  expect((last.selectedActionIds as string[]).some((id) => id.includes('network.create'))).toBe(true);
  expect((last.selectedActionIds as string[]).some((id) => id.includes('tinycloud.kv'))).toBe(true);
  expect(authorizes).toHaveLength(1);
  const [response] = await responses(page) as Array<{ success: boolean; selectedActionKeys: string[] }>;
  expect(response.success).toBe(true);
  expect(response.selectedActionKeys.filter(isElevated)).toEqual([]);
});

test('two permissions: reject one, allow the other, and only the allowed one is signed and sent', async ({ page }) => {
  const { frame, previews } = await open(page, [network, sharePrefix, kvGet]);
  await sized(page);
  await approve(frame).click();
  await expect(frame.getByRole('heading', { level: 2 })).toHaveCount(2);
  await shot(page, '390-two-cards');
  await frame.getByRole('button', { name: 'Reject this permission' }).first().click();
  await frame.getByRole('button', { name: 'Allow this permission' }).click();
  await shot(page, '390-decided');
  await frame.getByRole('button', { name: 'Continue' }).click();
  await expect.poll(async () => (await responses(page)).length).toBe(1);
  const last = previews.at(-1)!;
  const elevated = (last.selectedActionIds as string[]).filter(isElevated);
  expect(elevated).toHaveLength(1);
  expect(elevated[0]).toContain('/share/');
  expect((last.elevatedDecision as { allowed: string[] }).allowed).toEqual(elevated);
});

test('a request with no extra permission approves at once, with no screen and no decision', async ({ page }) => {
  const { frame, previews } = await open(page, [kvGet]);
  await approve(frame).click();
  await expect.poll(async () => (await responses(page)).length).toBe(1);
  expect(previews.every((preview) => !('elevatedDecision' in preview))).toBe(true);
  await expect(frame.locator('#elevated-title')).toHaveCount(0);
});

test('exact-byte request: all or nothing, and Allow and approve tells the server the owner decided', async ({ page }) => {
  const { frame, signs } = await open(page, [network], { exactBytes: true });
  await sized(page);
  await approve(frame).click();
  await expect(frame.getByText(/sent this as one request, so you can approve all of it or none of it/)).toBeVisible();
  await expect(frame.getByRole('button', { name: 'Cancel the whole request' })).toBeVisible();
  await shot(page, '390-whole-request');
  expect(signs).toHaveLength(0);
  await frame.getByRole('button', { name: 'Allow and approve' }).click();
  await expect.poll(() => signs.length).toBe(1);
  expect(signs[0]).toMatchObject({ elevatedAcknowledged: true });
});

test('exact-byte request: Cancel the whole request signs nothing', async ({ page }) => {
  const { frame, signs } = await open(page, [network], { exactBytes: true });
  await approve(frame).click();
  await frame.getByRole('button', { name: 'Cancel the whole request' }).click();
  expect(signs).toHaveLength(0);
  expect((await responses(page)).filter((r) => r.success === true)).toHaveLength(0);
});

test('no sideways scroll at 390px and the buttons are big enough to tap', async ({ page }) => {
  const { frame } = await open(page, [network, sharePrefix]);
  await sized(page);
  await approve(frame).click();
  const wide = await frame.locator('body').evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  expect(wide).toBe(false);
  for (const name of ['Reject this permission', 'Allow this permission']) {
    const box = await frame.getByRole('button', { name }).first().boundingBox();
    expect(box!.height).toBeGreaterThanOrEqual(44);
  }
});

// Sam's words for blocking and unblocking keys: its own card, never joined to decrypt or key creation.
const blockFolder = { [urn('/Shared/')]: { [`${E}key.block`]: [{}] } };
const unblockAccount = { [urn('')]: { [`${E}key.unblock`]: [{}] } };
const decryptAndBlockFolder = { [urn('/Shared/')]: { [`${E}decrypt`]: [{}], [`${E}key.block`]: [{}] } };

test('blocking keys in a folder gets its own card with the words Sam approved, and nothing is sent yet', async ({ page }) => {
  const { frame, authorizes } = await open(page, [blockFolder, kvGet]);
  await sized(page);
  await approve(frame).click();
  await expect(frame.getByRole('heading', { level: 2, name: 'Control access to encryption keys in a folder named Shared' })).toBeVisible();
  await expect(frame.getByText(
    /could block encryption keys in a folder named Shared, for as long as this approval lasts\. Until the key is unblocked, requests to unlock the items it protects are refused, including your own\./,
  )).toBeVisible();
  await expect(frame.getByRole('button', { name: 'Continue' })).toBeDisabled();
  expect(authorizes).toHaveLength(0);
  expect(await responses(page)).toHaveLength(0);
  await shot(page, '390-card-block-folder');
});

test('unblocking keys in the whole account says so, and carries no sentence about refused requests', async ({ page }) => {
  const { frame } = await open(page, [unblockAccount, kvGet]);
  await approve(frame).click();
  await expect(frame.getByRole('heading', { level: 2, name: 'Control access to encryption keys anywhere in your account' })).toBeVisible();
  await expect(frame.getByText(/could unblock encryption keys anywhere in your account, for as long as this approval lasts\./)).toBeVisible();
  await expect(frame.getByText(/Until the key is unblocked/)).toHaveCount(0);
  await shot(page, '390-card-unblock-account');
});

test('Allow on a block card: the next preview carries the allow for exactly that permission', async ({ page }) => {
  const { frame, previews, authorizes } = await open(page, [blockFolder, kvGet]);
  await approve(frame).click();
  await frame.getByRole('button', { name: 'Allow this permission' }).click();
  await frame.getByRole('button', { name: 'Continue' }).click();
  await expect.poll(async () => (await responses(page)).length).toBe(1);
  const last = previews.at(-1)!;
  const allowed = (last.elevatedDecision as { allowed: string[] }).allowed;
  expect(allowed).toHaveLength(1);
  expect(allowed[0]).toMatch(/key\.block$/);
  expect(authorizes).toHaveLength(1);
});

test('Reject on a block card: the block leaves the request, no allow is sent, and the rest is still approved', async ({ page }) => {
  const { frame, previews } = await open(page, [blockFolder, kvGet]);
  await approve(frame).click();
  await frame.getByRole('button', { name: 'Reject this permission' }).click();
  await frame.getByRole('button', { name: 'Continue' }).click();
  await expect.poll(async () => (await responses(page)).length).toBe(1);
  const last = previews.at(-1)!;
  expect((last.selectedActionIds as string[]).filter(isElevated)).toEqual([]);
  expect(last).not.toHaveProperty('elevatedDecision');
  expect((last.selectedActionIds as string[]).some((id) => id.includes('tinycloud.kv'))).toBe(true);
});

test('decrypt and block on the same folder are one card that names both: allowing it allows both', async ({ page }) => {
  const { frame, previews } = await open(page, [decryptAndBlockFolder, kvGet]);
  await sized(page);
  await approve(frame).click();
  await expect(frame.getByRole('heading', { level: 2 })).toHaveCount(1);
  await expect(frame.getByRole('heading', { level: 2, name: 'Control access to encryption keys in a folder named Shared' })).toBeVisible();
  await expect(frame.getByText(/could unlock encrypted items and block encryption keys in a folder named Shared, for as long as this approval lasts\./)).toBeVisible();
  await shot(page, '390-decrypt-and-block');
  await frame.getByRole('button', { name: 'Allow this permission' }).click();
  await frame.getByRole('button', { name: 'Continue' }).click();
  await expect.poll(async () => (await responses(page)).length).toBe(1);
  const last = previews.at(-1)!;
  const elevated = (last.selectedActionIds as string[]).filter(isElevated);
  expect(elevated.map((id) => id.split('\0').pop()).sort()).toEqual([`${E}decrypt`, `${E}key.block`]);
  expect((last.elevatedDecision as { allowed: string[] }).allowed.sort()).toEqual([...elevated].sort());
});

test('decrypt and block on the same folder: rejecting the card sends neither', async ({ page }) => {
  const { frame, previews } = await open(page, [decryptAndBlockFolder, kvGet]);
  await approve(frame).click();
  await frame.getByRole('button', { name: 'Reject this permission' }).click();
  await frame.getByRole('button', { name: 'Continue' }).click();
  await expect.poll(async () => (await responses(page)).length).toBe(1);
  const last = previews.at(-1)!;
  expect((last.selectedActionIds as string[]).filter(isElevated)).toEqual([]);
  expect(last).not.toHaveProperty('elevatedDecision');
});
