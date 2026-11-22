// The owner's own share/ folder (Share's sign-in: decrypt and key.create on `default/share/`, plus its KV reads) is not
// the one-hour tier: the page starts at the length the app asked for, says nothing about an hour, and the owner can pick
// any length in Advanced details. Requests for the whole network or other folders keep the one-hour start (see
// approval-expiry-optin.spec.ts).

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
    iframe.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=optin&protocolVersion=2&keyId=selected-key`;
    (window as unknown as { received: unknown[] }).received = [];
    window.addEventListener('message', (event) => {
      if (event.source === iframe.contentWindow) (window as unknown as { received: unknown[] }).received.push(event.data);
    });
    document.body.append(iframe);
  });
  await expect.poll(() => page.evaluate(() => (window as unknown as { received: Array<{ type: string }> }).received.some((m) => m.type === 'openkey:ready'))).toBe(true);
  await page.evaluate(({ message, request }) => {
    document.querySelector<HTMLIFrameElement>('#sign')?.contentWindow?.postMessage(
      { type: 'openkey:sign:request', requestId: 'optin', protocolVersion: 2, authorizationProtocolVersion: 1, keyId: 'selected-key', jwk: { kty: 'EC' }, message, ...request },
      location.origin,
    );
  }, { message, request });
  const frame = page.frameLocator('#sign');
  await expect(frame.getByRole('dialog')).toContainText('Requested by');
  return { frame, previews };
}


// Share's request as the post-deploy capture lists it: the share/ key folder, the recipient's files-for-you mailbox and
// its capabilities read, and the sender history records.
function shareRequest(owner: string) {
  const space = (name: string) => `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${address}:${name}`;
  const network = `urn:tinycloud:encryption:${owner}:default`;
  const att: Record<string, Record<string, unknown[]>> = {
    [`${space('applications')}/kv/vault/sender-history/v2/records/`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/list': [{}], 'tinycloud.kv/put': [{}] },
    [`${space('files-for-you')}/capabilities`]: { 'tinycloud.capabilities/read': [{}] },
    [`${space('files-for-you')}/kv/v1/`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/list': [{}], 'tinycloud.kv/put': [{}] },
    [`${network}/share/`]: { 'tinycloud.encryption/key.create': [{}], 'tinycloud.encryption/decrypt': [{}] },
  };
  return siweWithResources([makeRecapResource(att)], { domain: HOST, uri: ORIGIN });
}

const ownerDid = `did:pkh:eip155:${FIXTURE_META.chainId}:${address}`;

test('a share/ folder request starts at the length the app asked for, with no one-hour note', async ({ page }) => {
  const { frame, previews } = await open(page, { expiryChangeable: true }, shareRequest(ownerDid));
  await expect(frame.getByTestId('approval-expiry-line')).toContainText('7 days');
  await expect(frame.getByTestId('approval-expiry-once-note')).toHaveCount(0);
  await expect.poll(() => previews.length).toBe(1);
  expect(previews[0]).not.toHaveProperty('expirationTime');
});

test('the owner is not held to the start: a longer pick and the hour itself both apply', async ({ page }) => {
  const { frame, previews } = await open(page, { expiryChangeable: true }, shareRequest(ownerDid));
  await frame.getByText('Advanced details', { exact: true }).click();
  await frame.getByText('How long it lasts', { exact: true }).click();
  await frame.getByLabel('Or type a time').fill('2d');
  await frame.getByLabel('Or type a time').press('Enter');
  await expect(frame.getByTestId('approval-expiry-line')).toContainText('2 days');
  const asked = Date.parse(String(previews.at(-1)!.expirationTime));
  expect(asked).toBeGreaterThanOrEqual(Date.now() + 2 * 86_400_000 - 5000);
  await frame.getByRole('button', { name: '1 hour', exact: true }).click();
  await expect(frame.getByTestId('approval-expiry-line')).toContainText('1 hour');
});

test('the same folder under another owner keeps the one-hour start', async ({ page }) => {
  const other = `did:pkh:eip155:${FIXTURE_META.chainId}:0x2222222222222222222222222222222222222222`;
  const { frame } = await open(page, { expiryChangeable: true }, shareRequest(other));
  await expect(frame.getByTestId('approval-expiry-line')).toContainText('1 hour');
  await expect(frame.getByTestId('approval-expiry-once-note')).toContainText('asked for 7 days');
});
