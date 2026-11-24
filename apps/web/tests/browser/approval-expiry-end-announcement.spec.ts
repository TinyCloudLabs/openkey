// The end beside the compact length toggle is what a screen reader hears: the group is described by the caution and by the
// visible end, and the announcement after a pick says the same end. The grants are the signer's own (the selected key's address).

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
const owner = `did:pkh:eip155:${FIXTURE_META.chainId}:${address}`;
const PREFIX_DECRYPT = {
  [`urn:tinycloud:encryption:${owner}:default/secrets/`]: { 'tinycloud.encryption/decrypt': [{}] },
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
    iframe.style.cssText = 'width:480px;height:900px;border:0';
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


test('the announcement after a pick names the same end as the visible end, and the group is described by it', async ({ page }) => {
  const decrypt = siweWithResources([makeRecapResource(PREFIX_DECRYPT)], { domain: HOST, uri: ORIGIN });
  const { frame } = await open(page, {}, decrypt);
  const toggle = frame.getByTestId('approval-expiry-toggle');
  const end = frame.getByTestId('approval-expiry-end');
  await expect(end).toHaveText(/^until \d{1,2}:\d{2}\s?[AP]M$/);
  await expect(frame.getByTestId('approval-expiry-announcement')).toHaveText(/^Access lasts 1 hour, until \d{1,2}:\d{2}\s?[AP]M\.$/);
  const describedBy = await toggle.getAttribute('aria-describedby');
  const ids = describedBy!.split(' ');
  expect(ids).toHaveLength(2);
  await expect(frame.locator(`[id="${ids[0]}"]`)).toHaveText('Covers every secret in your vault.');
  await expect(frame.locator(`[id="${ids[1]}"]`)).toHaveText(await end.innerText());

  await frame.getByRole('radio', { name: '7 days, as the app asked', exact: true }).check();
  await expect(end).toHaveText(/^until [A-Z][a-z]{2} \d{1,2}$/);
  const shown = (await end.innerText()).replace(/^until /, '');
  await expect(frame.getByTestId('approval-expiry-announcement')).toHaveText(`Access lasts 7 days, until ${shown}.`);
  await expect(frame.locator(`[id="${ids[1]}"]`)).toHaveText(`until ${shown}`);
});
