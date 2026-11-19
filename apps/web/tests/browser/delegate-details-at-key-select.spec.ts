// A refused request that is first refused when a key is chosen shows the same
// closed Details disclosure as the review card. Every API call is answered by
// `page.route`; no API server runs.

import { test, expect, type Page, type Route } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';

const keyAddress = '0x1111111111111111111111111111111111111111';
const otherAddress = '0x2222222222222222222222222222222222222222';
const KV_GET = 'tinycloud.kv/get';
const SERVER_MESSAGE = 'Requested spaces must belong to the signing account <b id="injected">bold</b>';

const json = (route: Route, status: number, body: unknown) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

async function mockApi(page: Page, prepares: string[] = []) {
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/auth/get-session') {
      return json(route, 200, {
        session: { id: 'session_1', userId: 'user_1', expiresAt: new Date(Date.now() + 3_600_000).toISOString() },
        user: { id: 'user_1', email: 'alice@example.test', name: 'Alice' },
      });
    }
    if (url.pathname === '/api/keys') {
      return json(route, 200, {
        keys: [{ id: 'key_1', address: keyAddress, publicKey: '0x', keyIndex: 0, label: 'Main', keyType: 'MANAGED', createdAt: new Date().toISOString() }],
      });
    }
    if (url.pathname === '/api/delegate/prepare') {
      prepares.push(url.pathname);
      return json(route, 400, { code: 'invalid_permissions', error: 'Invalid permissions', message: SERVER_MESSAGE });
    }
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });
}

async function openDelegate(page: Page, owner: string) {
  const jwk = encodeBase64UrlJson({ kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
  const space = `tinycloud:pkh:eip155:1:${owner}:secrets`;
  const permissions = [{ service: 'tinycloud.kv', space, path: 'a', actions: [KV_GET] }];
  await page.goto(`/delegate?did=did:key:z6Mk&jwk=${jwk}&permissions=${encodeBase64UrlJson({ permissions })}`);
}

test('a refusal at key selection shows the server message as plain text', async ({ page }) => {
  const prepares: string[] = [];
  await mockApi(page, prepares);
  await openDelegate(page, keyAddress);

  const stop = page.getByTestId('stop-page');
  await expect(stop.getByRole('heading', { name: 'The app’s request has a mistake in it' })).toBeVisible();
  const details = stop.getByText('What OpenKey found', { exact: true }).locator('..');
  await expect(details).toContainText('Requested spaces must belong to the signing account');
  await expect(details.locator('#injected')).toHaveCount(0);
  await expect(details).toContainText('<b id="injected">bold</b>');
  expect(prepares).toEqual(['/api/delegate/prepare']);
  await page.screenshot({ path: '/var/tmp/shot-details-keyselect.png' });
});

test('a request for another wallet stops before key selection', async ({ page }) => {
  const prepares: string[] = [];
  await mockApi(page, prepares);
  await openDelegate(page, otherAddress);

  await expect(page.getByRole('heading', { name: 'This request is for a wallet this account doesn’t have' })).toBeVisible();
  await expect(page.getByRole('button', { name: /Main/ })).toHaveCount(0);
  expect(prepares).toEqual([]);
  await expect(page.getByText('What OpenKey found', { exact: true })).toHaveCount(0);
});
