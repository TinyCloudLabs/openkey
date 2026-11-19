// TC-3342: a key made on `/delegate` joins the key list even when preparing it
// fails, so the picker shows it and a second click does not make another key.
// Every API call is answered by `page.route`; no API server runs.

import { test, expect, type Route } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';

const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const jwk = encodeBase64UrlJson({ kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });

test('a generated key stays listed after prepare fails, and only one key is made', async ({ page }) => {
  const created = { id: 'key_0', address: '0xd559ccd9eb87c530a9a349262669386de93cf412', publicKey: '0x', keyIndex: 0, label: 'Key 0', keyType: 'MANAGED', isPrimary: true, createdAt: new Date().toISOString() };
  let posts = 0;
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/auth/get-session') return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'sam@example.test', name: 'Sam' } });
    if (url.pathname === '/api/keys/generate') { posts++; return json(route, 201, { key: created }); }
    if (url.pathname === '/api/keys') return json(route, 200, { keys: [] });
    if (url.pathname === '/api/delegate/prepare') return json(route, 400, { code: 'invalid_permissions', error: 'x' });
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });

  await page.goto(`/delegate?did=did:key:z6Mk&jwk=${jwk}`);
  await expect(page.getByText('No keys found. Generate your first key to connect.')).toBeVisible();
  await page.getByRole('button', { name: 'Generate Key' }).click();

  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.getByText('No keys found. Generate your first key to connect.')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Key 0/ })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Generate Key' })).toHaveCount(0);
  expect(posts).toBe(1);
});
