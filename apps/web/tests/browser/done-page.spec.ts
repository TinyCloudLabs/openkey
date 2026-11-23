// The done page: one page for every end with nothing to copy. A heading that says what happened and where to go,
// one line, a receipt of what the page knows for certain, and Close this tab. Every API call is answered by
// `page.route`; no API server runs.

import { test, expect, type Page } from '@playwright/test';
import { generateKeyPairSync } from 'node:crypto';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';
import { formatLocalAccessEnd } from '../../src/lib/access-end';
import { address, approvalLink, delegateLink, json, mockApi, preparedLink } from './approval-end-pages-fixtures';
import { approve, callback, cors, delegation, receipt, space } from './approval-code-fixtures';

test.use({ timezoneId: 'UTC' });

const signedEnd = formatLocalAccessEnd('2026-11-03T01:00:00.000Z', 'UTC');

async function expectNothingToCopy(page: Page) {
  await expect(page.getByRole('textbox')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Copy/ })).toHaveCount(0);
  await expect(page.locator('[data-code-box]')).toHaveCount(0);
}

async function approveWithCallback(page: Page, body: unknown = delegation) {
  await mockApi(page, { signedIn: true, approveReply: { status: 200, body } });
  await page.route(`${callback}**`, (route) => route.fulfill({ status: 200, contentType: 'application/json', headers: cors, body: '{"success":true}' }));
  await page.goto(`${delegateLink}&${new URLSearchParams({ callback })}`);
  await approve(page);
  await expect(page.getByRole('heading', { name: 'Approved. Go back to your agent.' })).toBeVisible();
}

test('a /delegate approval the terminal on this device received: heading, receipt, nothing to copy', async ({ page }) => {
  await approveWithCallback(page);
  await expect(page.getByText('You can close this window and return to the CLI.', { exact: true })).toBeVisible();
  await expect(page.getByText('Your approval was sent to')).toHaveCount(0);
  await expect(receipt(page, 'Access')).toHaveText('1 permission in default');
  await expect(receipt(page, 'Ends')).toHaveText(signedEnd);
  await expect(receipt(page, 'Sent to')).toHaveText('Your terminal, this device');
  // One key on the account: the receipt does not name it.
  await expect(receipt(page, 'Signed with')).toHaveCount(0);
  await expectNothingToCopy(page);
  await expect(page.getByRole('button', { name: 'Close this tab' })).toBeVisible();
});

test('a space still being set up is said once, in a status line', async ({ page }) => {
  await approveWithCallback(page, { ...delegation, spacePending: true });
  const note = 'Your ‘default’ space in TinyCloud is being set up.';
  await expect(page.getByRole('status').filter({ hasText: note })).toHaveCount(1);
  await expect(page.getByText(note, { exact: false })).toHaveCount(1);
});

test('Close this tab in a tab the browser keeps open: a status line takes its place and focus', async ({ page }) => {
  await approveWithCallback(page);
  await page.getByRole('button', { name: 'Close this tab' }).click();
  const refusal = page.getByRole('status').filter({ hasText: 'Your browser kept this tab open. Close it from your browser.' });
  await expect(refusal).toBeVisible();
  await expect(refusal).toBeFocused();
  await expect(page.getByRole('button', { name: 'Close this tab' })).toHaveCount(0);
});

test('an approval link: the receipt says the approval went to the app that asked', async ({ page }) => {
  await mockApi(page, { signedIn: true, approveReply: { status: 200, body: delegation } });
  await page.goto(approvalLink);
  await approve(page);
  await expect(page.getByRole('heading', { name: 'Approved. Go back to your agent.' })).toBeVisible();
  await expect(receipt(page, 'Sent to')).toHaveCount(0);
  await expectNothingToCopy(page);
});

test('an approval link declined: nothing was shared, and there is no receipt', async ({ page }) => {
  await mockApi(page, { signedIn: true });
  await page.route('**/api/approval-requests/*/deny', (route) => json(route, 200, { status: 'denied' }));
  await page.goto(approvalLink);
  await page.getByTestId('signing-decline').click();
  await expect(page.getByRole('heading', { name: 'Declined. Nothing was shared.' })).toBeVisible();
  await expect(page.getByText('Whoever sent this link has been told no.', { exact: false })).toBeVisible();
  await expect(page.locator('dl')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Close this tab' })).toBeVisible();
});

test('a device link: the receipt says the approval went to the terminal that showed the code', async ({ page }) => {
  const deviceJwk = { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) };
  const relayPublicJwk = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' });
  const permissions = [{ service: 'tinycloud.kv', space, path: 'notes/', actions: ['tinycloud.kv/get'] }];
  await mockApi(page, { signedIn: true });
  await page.route('**/api/device-authorizations/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/device-authorizations/lookup') {
      return json(route, 200, {
        id: 'tx_1', userCode: 'ABCDEFGH', sessionDid: 'did:key:z6Mk', publicJwk: deviceJwk, relayPublicJwk,
        permissions, nodeOrigin: 'https://node.tinycloud.xyz', shareOrigin: 'https://share.tinycloud.xyz',
        delegationExpiresAt: '2026-11-03T01:00:00.000Z', transactionExpiresAt: '2026-10-16T17:10:00.000Z',
        delegationTtlSeconds: 2_592_000,
      });
    }
    if (path === '/api/device-authorizations/tx_1/approve') return json(route, 200, {});
    return route.fallback();
  });
  await page.route('**/api/delegate', (route) => json(route, 200, {
    ...delegation, jwk: deviceJwk, address, chainId: 1, permissions,
  }));
  const params = new URLSearchParams({
    did: 'did:key:z6Mk', jwk: encodeBase64UrlJson(deviceJwk), host: 'https://node.tinycloud.xyz',
    deviceTransactionId: 'tx_1', deviceShareOrigin: 'https://share.tinycloud.xyz', deviceUserCode: 'ABCDEFGH',
    relayJwk: encodeBase64UrlJson(relayPublicJwk), expiry: '2592000s', permissions: encodeBase64UrlJson({ permissions }),
  });
  await page.goto(`/delegate?${params}`);
  await approve(page);
  await expect(page.getByRole('heading', { name: 'Approved. Go back to your agent.' })).toBeVisible();
  await expect(receipt(page, 'Sent to')).toHaveText('The terminal that showed the code');
  await expectNothingToCopy(page);
});

/** The prepared link of the fixtures, with a callback on this device. */
function preparedLinkWithCallback(): string {
  const fragment = preparedLink().split('#tv2=')[1]!;
  const input = JSON.parse(Buffer.from(fragment, 'base64url').toString('utf8'));
  input.delivery.callback = `http://127.0.0.1:47123/callback/${'D'.repeat(22)}`;
  return `/delegate#tv2=${Buffer.from(JSON.stringify(input)).toString('base64url')}`;
}

test('a prepared sign-in the terminal accepted: signed in, and nothing to copy', async ({ page }) => {
  await mockApi(page, { signedIn: true });
  await page.route('http://127.0.0.1:47123/callback/**', (route) => route.fulfill({ status: 200, contentType: 'application/json', headers: cors, body: '{"accepted":true}' }));
  await page.goto(preparedLinkWithCallback());
  await page.getByRole('button', { name: 'Preview signing message' }).click();
  await approve(page);
  await expect(page.getByRole('heading', { name: 'Signed in. Go back to your terminal.' })).toBeVisible();
  await expect(page.getByText('cli.tinycloud.xyz has your sign-in. There is nothing to copy.')).toBeVisible();
  await expect(receipt(page, 'Ends')).toHaveText(formatLocalAccessEnd('2026-10-23T17:00:00.000Z', 'UTC'));
  await expectNothingToCopy(page);
});

test('a prepared sign-in cancelled after the claim: cancelled, nothing was approved', async ({ page }) => {
  const mocked = await mockApi(page, { signedIn: true });
  await page.goto(preparedLink());
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Cancelled. Nothing was approved.' })).toBeVisible();
  await expect(page.getByText('To try again, run the command again.')).toBeVisible();
  await expect(page.getByRole('alert')).toHaveCount(0);
  expect(mocked.cancelCalls).toBe(1);
});
