// TC-3343: a refusal that comes back when a key is first chosen on /delegate and is the same for every key
// leaves the sentence and the way out, not the key buttons. A refusal that another key can change keeps the
// list. Every API call is answered by `page.route`; no API server runs.

import { test, expect, type Page, type Route } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';

const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const key = (id: string, keyIndex: number, address: string, isPrimary: boolean) =>
  ({ id, address, publicKey: '0x', keyIndex, label: `Key ${keyIndex}`, keyType: 'MANAGED', isPrimary, createdAt: new Date().toISOString() });

const primary = key('key_0', 0, '0xd559ccd9eb87c530a9a349262669386de93cf412', true);
const second = key('key_1', 1, '0x2222222222222222222222222222222222222222', false);

const KEY_DELETE_SENTENCE = "Apps and commands can't be given permission to delete keys. Nothing was approved. Ask the app or command to send a new request without that permission.";

const jwk = encodeBase64UrlJson({ kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
const noOwner = `/delegate?did=did:key:z6Mk&jwk=${jwk}`;
const keyButton = (page: Page, name: string) => page.getByRole('button', { name, exact: true });

/** Mocks the API; `prepare` answers every `/api/delegate/prepare`. Returns how many times it was asked. */
async function mock(page: Page, keys: unknown[], prepare: { status: number; body: Record<string, unknown> }) {
  const calls = { prepare: 0 };
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/auth/get-session') return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'sam@example.test', name: 'Sam' } });
    if (url.pathname === '/api/keys') return json(route, 200, { keys });
    if (url.pathname === '/api/delegate/prepare') {
      calls.prepare += 1;
      return json(route, prepare.status, prepare.body);
    }
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });
  return calls;
}

test.describe('TC-3343 terminal refusal at the key step', () => {
  test('a refusal no key can change shows its sentence with no key buttons, and Sign out stays', async ({ page }) => {
    const calls = await mock(page, [primary, second], { status: 403, body: { code: 'key_delete_not_grantable', error: 'x' } });
    await page.goto(noOwner);
    await keyButton(page, 'Key 0').click();

    await expect(page.getByRole('alert').filter({ hasText: KEY_DELETE_SENTENCE })).toBeVisible();
    expect(calls.prepare).toBe(1);
    await expect(page.getByText('Sign in with your primary key')).toHaveCount(0);
    await expect(page.getByText('Select a key to authorize:')).toHaveCount(0);
    await expect(keyButton(page, 'Key 0')).toHaveCount(0);
    await expect(keyButton(page, 'Key 1')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Use a different key' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Link External Wallet' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /Generate/ })).toHaveCount(0);
    await page.locator('[data-account-menu] button').first().click();
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
    await page.screenshot({ path: '/var/tmp/shot-terminal-keys.png', fullPage: true });
  });

  test('a request that has ended shows its sentence with no key buttons', async ({ page }) => {
    await mock(page, [primary, second], { status: 410, body: { code: 'expired_request', error: 'x' } });
    await page.goto(noOwner);
    await keyButton(page, 'Key 0').click();

    await expect(page.getByRole('alert').filter({ hasText: 'This request has already been answered or has ended.' })).toBeVisible();
    await expect(keyButton(page, 'Key 0')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Link External Wallet' })).toHaveCount(0);
    await page.locator('[data-account-menu] button').first().click();
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
  });

  for (const refusal of [
    { status: 400, body: { code: 'invalid_permissions', error: 'x' }, text: "OpenKey can't approve this kind of access." },
    { status: 403, body: { code: 'app_key_grant_refused', error: 'x' }, text: "OpenKey can't approve this kind of access." },
    { status: 500, body: { code: 'authorization_context_failed', error: 'x' }, text: 'This request changed after you opened it' },
  ]) {
    test(`a ${refusal.status} ${refusal.body.code} refusal keeps the keys`, async ({ page }) => {
      const calls = await mock(page, [primary, second], refusal);
      await page.goto(noOwner);
      await keyButton(page, 'Key 0').click();

      await expect(page.getByRole('alert').filter({ hasText: refusal.text })).toBeVisible();
      expect(calls.prepare).toBe(1);
      await expect(page.getByText('Sign in with your primary key')).toBeVisible();
      await expect(keyButton(page, 'Key 0')).toBeEnabled();
      await expect(page.getByRole('button', { name: 'Use a different key' })).toBeVisible();
      await page.getByRole('button', { name: 'Use a different key' }).click();
      await expect(keyButton(page, 'Key 1')).toBeEnabled();
    });
  }

  test('a wallet mismatch on a generated key keeps the controls for choosing another key', async ({ page }) => {
    await mock(page, [], { status: 400, body: { code: 'invalid_permissions', error: 'x' } });
    await page.route('**/api/keys/generate', (route) => json(route, 200, { key: second }));
    const space = `tinycloud:pkh:eip155:1:${primary.address}:default`;
    const permissions = [{ service: 'tinycloud.kv', space, path: 'notes/', actions: ['tinycloud.kv/get'] }];
    await page.goto(`${noOwner}&permissions=${encodeBase64UrlJson({ permissions })}`);
    await page.getByRole('button', { name: 'Generate Key' }).click();

    await expect(page.getByRole('alert').filter({ hasText: 'This request is for wallet 0xd559…f412, but the key you picked is for 0x2222…2222.' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Link External Wallet' })).toBeVisible();
  });
});
