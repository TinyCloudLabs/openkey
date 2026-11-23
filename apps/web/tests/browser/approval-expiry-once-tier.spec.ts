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
  await expect(frame.getByTestId('approval-expiry-line')).toContainText('1 hour');
  await expect(frame.getByTestId('approval-expiry-once-note')).toContainText('asked for 7 days');
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
  await expect(frame.getByTestId('approval-expiry-line')).toContainText('1 hour');
  await frame.getByText('Advanced details', { exact: true }).click();
  await frame.getByText('How long it lasts', { exact: true }).click();
  await frame.getByLabel('Or type a time').fill('2d');
  await frame.getByLabel('Or type a time').press('Enter');
  await expect(frame.getByTestId('approval-expiry-line')).toContainText('2 days');
  await expect.poll(() => previews.at(-1)?.expirationTime).toBeTruthy();
  const asked = Date.parse(String(previews.at(-1)!.expirationTime));
  expect(asked).toBeGreaterThanOrEqual(Date.now() + 2 * 86_400_000 - 5000);
});

test('decrypt on one named secret without the opt-in shows no control and keeps the app\'s time', async ({ page }) => {
  const decrypt = siweWithResources([makeRecapResource(ONE_SECRET)], { domain: HOST, uri: ORIGIN });
  const { frame, previews } = await open(page, {}, decrypt);
  await expect(frame.locator('.expiry')).toHaveCount(0);
  await expect.poll(() => previews.length).toBe(1);
  expect(previews[0]).not.toHaveProperty('expirationTime');
});
