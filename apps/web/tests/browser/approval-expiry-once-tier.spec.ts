// TC-3966: a sign-in whose grants reach all secrets or all encrypted data (the one-hour tier) shows the lifetime
// control and starts at one hour whether or not the app's request sends `expiryChangeable`; the server treats the
// request as expiry-changeable and defaults its signature to one hour when the owner picks nothing.

import { test, expect, type Page } from '@playwright/test';
import { HOST, ORIGIN } from './e2e-port';
import { TERMS_ACCEPTED } from './terms-fixtures';
import {
  EXPLORER_PERMISSION_POPUP_REQUEST,
  FIXTURE_META,
  makeRecapResource,
  siweWithResources,
} from '../../../../packages/capability-review/test/fixtures/index';

const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const siwe = EXPLORER_PERMISSION_POPUP_REQUEST.replace(/^explorer\.tinycloud\.xyz/, HOST);
const owner = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const NETWORK_DECRYPT = {
  [`urn:tinycloud:encryption:${owner}:default`]: { 'tinycloud.encryption/decrypt': [{}] },
};
const PREFIX_DECRYPT = {
  [`urn:tinycloud:encryption:${owner}:default/secrets/`]: { 'tinycloud.encryption/decrypt': [{}] },
};
const ONE_SECRET = {
  [`urn:tinycloud:encryption:${owner}:default/secrets/openai_api_key`]: { 'tinycloud.encryption/decrypt': [{}] },
};

async function open(page: Page, request: Record<string, unknown>, message: string = siwe) {
  const previews: Array<Record<string, unknown>> = [];
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.route('**/api/keys/**', (route) => route.fulfill({ json: { key: {
    id: 'selected-key', address, publicKey: '0x02', keyIndex: 0, label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z',
  } } }));
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({ json: { session: { id: 'test-session' }, user: { id: 'test-user' } } }));
  await page.route('**/api/account/terms', (route) => route.fulfill({ json: TERMS_ACCEPTED }));
  await page.route('**/api/delegate/authorize-sign-prepare', (route) => route.fulfill({ headers: { Date: new Date().toUTCString() }, json: { authorizationContextToken: 'context-token', expiresAt: new Date(Date.now() + 300_000).toISOString() } }));
  await page.route('**/api/delegate/authorize-sign-preview', async (route) => {
    const body = route.request().postDataJSON() as Record<string, unknown>;
    previews.push(body);
    const ids = body.selectedActionIds as string[];
    const permissions = ids.map((id) => {
      const [service, space, path, ability] = id.split('\0');
      return { service, space, path, actions: [ability] };
    });
    const signedMessage = typeof body.expirationTime === 'string'
      ? message.replace(/^Expiration Time:.*$/m, `Expiration Time: ${body.expirationTime}`)
      : message;
    await route.fulfill({ headers: { Date: new Date().toUTCString() }, json: { signedMessage, authorizationContextToken: 'context-token', previewApprovalToken: 'preview-token', previewApprovalExpiresAt: new Date(Date.now() + 60_000).toISOString(), selectedActionKeys: ids, permissions } });
  });
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const iframe = document.createElement('iframe');
    iframe.id = 'sign';
    iframe.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=once-tier&protocolVersion=2&keyId=selected-key`;
    (window as unknown as { received: unknown[] }).received = [];
    window.addEventListener('message', (event) => {
      if (event.source === iframe.contentWindow) (window as unknown as { received: unknown[] }).received.push(event.data);
    });
    document.body.append(iframe);
  });
  await expect.poll(() => page.evaluate(() => (window as unknown as { received: Array<{ type: string }> }).received.some((m) => m.type === 'openkey:ready'))).toBe(true);
  await page.evaluate(({ message, request }) => {
    document.querySelector<HTMLIFrameElement>('#sign')?.contentWindow?.postMessage(
      { type: 'openkey:sign:request', requestId: 'once-tier', protocolVersion: 2, authorizationProtocolVersion: 1, keyId: 'selected-key', jwk: { kty: 'EC' }, message, ...request },
      location.origin,
    );
  }, { message, request });
  const frame = page.frameLocator('#sign');
  await expect(frame.getByRole('dialog')).toContainText('Requested by');
  return { frame, previews };
}

const aboutAnHour = (value: unknown, before: number) => {
  const asked = Date.parse(String(value));
  expect(asked).toBeGreaterThanOrEqual(before + 60 * 60_000 - 1000);
  expect(asked).toBeLessThanOrEqual(Date.now() + 60 * 60_000 + 1000);
};

test('decrypt on the secrets/ prefix without the opt-in starts at one hour, and the preview asks for it', async ({ page }) => {
  const decrypt = siweWithResources([makeRecapResource(PREFIX_DECRYPT)], { domain: HOST, uri: ORIGIN });
  const before = Date.now();
  const { frame, previews } = await open(page, {}, decrypt);
  await expect(frame.getByTestId('approval-expiry-announcement')).toHaveText(/^Access lasts 1 hour, until /);
  const choice = frame.getByRole('group', { name: 'How long access lasts', exact: true });
  await expect(choice.getByRole('radio', { name: /^1 hour, until / })).toBeChecked();
  await expect(choice.getByRole('radio', { name: /^7 days, until .*, as the app asked$/ })).not.toBeChecked();
  await expect(frame.getByTestId('approval-expiry-compact-caution')).toHaveText('Covers every secret in your vault.');
  const latest = previews.at(-1)!;
  aboutAnHour(latest.expirationTime, before);
});

test('decrypt on the whole network without the opt-in starts at one hour', async ({ page }) => {
  const decrypt = siweWithResources([makeRecapResource(NETWORK_DECRYPT)], { domain: HOST, uri: ORIGIN });
  const before = Date.now();
  const { frame, previews } = await open(page, {}, decrypt);
  await expect(frame.getByTestId('approval-expiry-line')).toContainText('1 hour');
  const latest = previews.at(-1)!;
  aboutAnHour(latest.expirationTime, before);
});

test('without the opt-in the owner can still choose longer', async ({ page }) => {
  const decrypt = siweWithResources([makeRecapResource(PREFIX_DECRYPT)], { domain: HOST, uri: ORIGIN });
  const { frame, previews } = await open(page, {}, decrypt);
  await expect(frame.getByTestId('approval-expiry-announcement')).toHaveText(/^Access lasts 1 hour, until /);
  await frame.getByText('Advanced details', { exact: true }).click();
  await frame.getByText('How long it lasts', { exact: true }).click();
  await frame.getByLabel('Or type a time').fill('2d');
  await frame.getByLabel('Or type a time').press('Enter');
  await expect(frame.getByTestId('approval-expiry-length-line')).toHaveText(/^Access lasts 2 days, until /);
  await expect.poll(() => previews.at(-1)?.expirationTime).toBeTruthy();
  const asked = Date.parse(String(previews.at(-1)!.expirationTime));
  expect(asked).toBeGreaterThanOrEqual(Date.now() + 2 * 86_400_000 - 5000);
});

for (const [description, request] of [
  ['without the opt-in', {}],
  ['with a string opt-in', { expiryChangeable: 'true' }],
] as const) {
  test(`decrypt on one named secret ${description} shows no expiry control and sends no expiry`, async ({ page }) => {
    const decrypt = siweWithResources([makeRecapResource(ONE_SECRET)], { domain: HOST, uri: ORIGIN });
    const { frame, previews } = await open(page, request, decrypt);
    await expect(frame.locator('.expiry')).toHaveCount(0);
    await expect.poll(() => previews.length).toBe(1);
    expect(previews[0]).not.toHaveProperty('expirationTime');
  });
}

// TC-4156: the inline choice sends an explicit length for every option. A preview with no expirationTime is signed as
// one hour on a popup or frame, so "what the app asked" must travel as a length. The fixture message is issued at
// 2026-07-31T00:00:00Z, so its expirationTime sets how long the app asked for.
const within = (value: unknown, expected: number) => {
  const asked = Date.parse(String(value));
  expect(asked).toBeGreaterThanOrEqual(expected - 5000);
  expect(asked).toBeLessThanOrEqual(expected + 5000);
};

test('choosing what the app asked for prepares that length, and 1 hour again prepares 1 hour', async ({ page }) => {
  const decrypt = siweWithResources([makeRecapResource(NETWORK_DECRYPT)], { domain: HOST, uri: ORIGIN });
  const { frame, previews } = await open(page, {}, decrypt);
  const choice = frame.getByRole('group', { name: 'How long', exact: true });
  await choice.getByRole('radio', { name: '7 days (what the app asked)' }).check();
  await expect(choice.getByRole('radio', { name: '7 days (what the app asked)' })).toBeChecked();
  await expect(frame.getByTestId('approval-expiry-line')).toContainText('7 days');
  await expect.poll(() => Date.parse(String(previews.at(-1)?.expirationTime)) > Date.now() + 86_400_000).toBe(true);
  within(previews.at(-1)!.expirationTime, Date.now() + 7 * 86_400_000);
  await choice.getByRole('radio', { name: '1 hour' }).check();
  await expect(frame.getByTestId('approval-expiry-line')).toContainText('1 hour');
  await expect.poll(() => Date.parse(String(previews.at(-1)?.expirationTime)) < Date.now() + 2 * 3_600_000).toBe(true);
  within(previews.at(-1)!.expirationTime, Date.now() + 3_600_000);
  await expect(choice.getByRole('radio', { name: '1 hour' })).toBeChecked();
});

test('an ask over 7 days offers the longest allowed and never prepares more than 7 days', async ({ page }) => {
  const decrypt = siweWithResources([makeRecapResource(NETWORK_DECRYPT)], {
    domain: HOST,
    uri: ORIGIN,
    expirationTime: '2026-08-30T00:00:00.000Z',
  });
  const { frame, previews } = await open(page, {}, decrypt);
  const choice = frame.getByRole('group', { name: 'How long', exact: true });
  await expect(choice.getByRole('radio', { name: '7 days (the longest allowed)' })).not.toBeChecked();
  await choice.getByRole('radio', { name: '7 days (the longest allowed)' }).check();
  await expect.poll(() => Date.parse(String(previews.at(-1)?.expirationTime)) > Date.now() + 86_400_000).toBe(true);
  within(previews.at(-1)!.expirationTime, Date.now() + 7 * 86_400_000);
});

test('a request that asks for an hour or less shows the caution and no choice', async ({ page }) => {
  const decrypt = siweWithResources([makeRecapResource(NETWORK_DECRYPT)], {
    domain: HOST,
    uri: ORIGIN,
    expirationTime: '2026-07-31T00:30:00.000Z',
  });
  const { frame } = await open(page, {}, decrypt);
  await expect(frame.getByTestId('approval-expiry-once-caution')).toHaveText('This access can open all your encrypted data.');
  await expect(frame.getByTestId('approval-expiry-once-choice')).toHaveCount(0);
});

test('the choice and the caution fit a 390 px frame without sideways scrolling', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const decrypt = siweWithResources([makeRecapResource(NETWORK_DECRYPT)], { domain: HOST, uri: ORIGIN });
  const { frame } = await open(page, {}, decrypt);
  const group = frame.getByRole('group', { name: 'How long', exact: true });
  await expect(group).toBeVisible();
  expect(await frame.locator('html').evaluate((root) => root.scrollWidth - root.clientWidth)).toBeLessThanOrEqual(0);
  const box = await group.boundingBox();
  expect(box!.x + box!.width).toBeLessThanOrEqual(390);
});
