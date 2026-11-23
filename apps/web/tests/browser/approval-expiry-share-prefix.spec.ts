// The owner's own share/ folder (decrypt on `default/share/`, with Share's KV reads) is not the one-hour tier and asks
// nothing to renew. Share's library sign-in signs a 30-day session (SIGN_IN_SESSION_MS in Share's
// src/share/openkey-session.ts). Two real shapes of that request are driven through the embedded sign frame:
// - the signed message alone (no authorization protocol): the frame prepares nothing and shows the signed length;
// - the versioned sign-in with `expiryChangeable` and a renewal ask: the frame prepares the request, starts it at the
//   length the app signed and offers the renewal box.
// Requests for the whole network or other folders keep the one-hour start (see approval-expiry-optin.spec.ts).

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
const DAY = 86_400;
const RENEWAL_ASK = { version: 1, leaseLifetimeSeconds: 90 * DAY };

type Mode = {
  /** Frame the request the way the versioned sign-in does (authorization protocol 1); off sends the message alone. */
  versioned: boolean;
  /** The prepare answer offers renewal for up to this many seconds. */
  renewalOfferSeconds?: number;
};

async function open(page: Page, request: Record<string, unknown>, message: string, mode: Mode) {
  const previews: Array<Record<string, unknown>> = [];
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.route('**/api/keys/**', (route) => route.fulfill({ json: { key: {
    id: 'selected-key', address, publicKey: '0x02', keyIndex: 0, label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z',
  } } }));
  await page.route('**/api/auth/get-session**', (route) => route.fulfill({ json: { session: { id: 'test-session' }, user: { id: 'test-user' } } }));
  await page.route('**/api/account/terms', (route) => route.fulfill({ json: TERMS_ACCEPTED }));
  await page.route('**/api/delegate/authorize-sign-prepare', (route) => route.fulfill({ headers: { Date: new Date().toUTCString() }, json: {
    authorizationContextToken: 'context-token',
    expiresAt: new Date(Date.now() + 300_000).toISOString(),
    ...(mode.renewalOfferSeconds === undefined ? {} : { renewal: { leaseLifetimeSeconds: mode.renewalOfferSeconds } }),
  } }));
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
    iframe.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=share&protocolVersion=2&keyId=selected-key`;
    (window as unknown as { received: unknown[] }).received = [];
    window.addEventListener('message', (event) => {
      if (event.source === iframe.contentWindow) (window as unknown as { received: unknown[] }).received.push(event.data);
    });
    document.body.append(iframe);
  });
  await expect.poll(() => page.evaluate(() => (window as unknown as { received: Array<{ type: string }> }).received.some((m) => m.type === 'openkey:ready'))).toBe(true);
  await page.evaluate(({ message, request, versioned }) => {
    document.querySelector<HTMLIFrameElement>('#sign')?.contentWindow?.postMessage(
      { type: 'openkey:sign:request', requestId: 'share', protocolVersion: 2, ...(versioned ? { authorizationProtocolVersion: 1 } : {}), keyId: 'selected-key', jwk: { kty: 'EC' }, message, ...request },
      location.origin,
    );
  }, { message, request, versioned: mode.versioned });
  const frame = page.frameLocator('#sign');
  await expect(frame.getByRole('dialog')).toContainText('Requested by');
  return { frame, previews };
}

// Share's request: the share/ key folder, the recipient's files-for-you mailbox with its capabilities read, Share's own
// app folder and the sender history records. The signed length is a parameter so the start is checked against what the
// request itself asks.
const SIGNED_AT = Date.parse('2026-07-31T00:00:00.000Z');

function shareRequest(owner: string, days: number, signedAt: number = SIGNED_AT) {
  const space = (name: string) => `tinycloud:pkh:eip155:${FIXTURE_META.chainId}:${address}:${name}`;
  const network = `urn:tinycloud:encryption:${owner}:default`;
  const att: Record<string, Record<string, unknown[]>> = {
    [`${space('applications')}/kv/xyz.tinycloud.share/`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/list': [{}], 'tinycloud.kv/metadata': [{}] },
    [`${space('applications')}/kv/vault/sender-history/v2/records/`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/list': [{}], 'tinycloud.kv/put': [{}] },
    [`${space('files-for-you')}/capabilities`]: { 'tinycloud.capabilities/read': [{}] },
    [`${space('files-for-you')}/kv/v1/`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/list': [{}], 'tinycloud.kv/put': [{}] },
    [`${network}/share/`]: { 'tinycloud.encryption/key.create': [{}], 'tinycloud.encryption/decrypt': [{}] },
  };
  const expirationTime = new Date(signedAt + days * 86_400_000).toISOString();
  return siweWithResources([makeRecapResource(att)], { domain: HOST, uri: ORIGIN, expirationTime });
}

const ownerDid = `did:pkh:eip155:${FIXTURE_META.chainId}:${address}`;
const otherOwnerDid = `did:pkh:eip155:${FIXTURE_META.chainId}:0x2222222222222222222222222222222222222222`;

test.describe('the signed message alone (no authorization protocol)', () => {
  test('shows the signed 30 days with no one-hour note, no renewal box and nothing prepared', async ({ page }) => {
    // The line counts from the current time, so this message is signed at the time of the test, as Share's is.
    const { frame, previews } = await open(page, {}, shareRequest(ownerDid, 30, Date.now()), { versioned: false });
    const dialog = frame.getByRole('dialog');
    await expect(dialog).toContainText('Open all your shared files, including ones you share later.');
    await expect(dialog.locator('.summary-statement').filter({ hasText: 'Open all your shared files' }).locator('.summary-sensitive-pill')).toHaveText('Sensitive');
    await expect(dialog.locator('.summary-statement').filter({ hasText: 'Read and change files shared with you' }).locator('.summary-sensitive-pill')).toHaveText('Sensitive');
    await expect(dialog).toContainText('See which permissions are already granted');
    await expect(frame.getByTestId('approval-access-line')).toContainText('lasts 30 days');
    await expect(frame.getByTestId('approval-expiry-once-note')).toHaveCount(0);
    await expect(frame.locator('.renewal-box')).toHaveCount(0);
    expect(previews).toHaveLength(0);
  });
});

test.describe('the versioned sign-in with an expiry control', () => {
  for (const days of [7, 30]) {
    test(`a share/ folder request that signs ${days} days starts at ${days} days, with no one-hour note`, async ({ page }) => {
      const { frame, previews } = await open(page, { expiryChangeable: true }, shareRequest(ownerDid, days), { versioned: true });
      await expect(frame.getByTestId('approval-expiry-line')).toContainText(`${days} days`);
      await expect(frame.getByTestId('approval-expiry-once-note')).toHaveCount(0);
      await expect.poll(() => previews.length).toBe(1);
      expect(previews[0]).not.toHaveProperty('expirationTime');
    });
  }

  test('the owner is not held to the start: a longer pick and the hour itself both apply', async ({ page }) => {
    const { frame, previews } = await open(page, { expiryChangeable: true }, shareRequest(ownerDid, 30), { versioned: true });
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
    const { frame } = await open(page, { expiryChangeable: true }, shareRequest(otherOwnerDid, 30), { versioned: true });
    await expect(frame.getByTestId('approval-expiry-line')).toContainText('1 hour');
    await expect(frame.getByTestId('approval-expiry-once-note')).toContainText('asked for 30 days');
  });
});

test.describe('the versioned sign-in with a renewal ask', () => {
  const renewing = { expiryChangeable: true, renewal: RENEWAL_ASK };
  const offered: Mode = { versioned: true, renewalOfferSeconds: 90 * DAY };

  test('without a purpose the box starts unticked, and ticking it asks nothing and keeps the signed 30 days', async ({ page }) => {
    const { frame, previews } = await open(page, renewing, shareRequest(ownerDid, 30), offered);
    const box = frame.locator('.renewal-box');
    await expect(box).not.toBeChecked();
    await expect(frame.getByTestId('approval-expiry-line')).toContainText('30 days');
    await box.check();
    await expect(frame.getByRole('alertdialog')).toHaveCount(0);
    await expect(box).toBeChecked();
    await expect.poll(() => previews.length).toBe(2);
    expect(previews[1].renewal).toMatchObject({ choice: 'leased' });
    expect(previews[1].renewal).not.toHaveProperty('sensitiveConfirmed');
    expect(previews[1]).not.toHaveProperty('expirationTime');
  });

  test('a standing request starts with the box ticked and no confirm', async ({ page }) => {
    const { frame, previews } = await open(page, { ...renewing, renewal: { ...RENEWAL_ASK, purpose: 'standing' } }, shareRequest(ownerDid, 30), offered);
    await expect(frame.locator('.renewal-box')).toBeChecked();
    await expect(frame.getByRole('alertdialog')).toHaveCount(0);
    await expect.poll(() => previews.length).toBeGreaterThan(0);
    expect(previews.at(-1)!.renewal).toMatchObject({ choice: 'leased' });
  });

  test('the same folder under another owner asks "Renew sensitive access?" when the box is ticked', async ({ page }) => {
    const { frame } = await open(page, renewing, shareRequest(otherOwnerDid, 30), offered);
    await frame.locator('.renewal-box').click();
    await expect(frame.getByRole('alertdialog')).toContainText('Renew sensitive access?');
    await expect(frame.locator('.renewal-box')).toHaveCount(0);
  });
});
