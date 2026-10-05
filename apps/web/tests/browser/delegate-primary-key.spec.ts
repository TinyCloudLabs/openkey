// TC-703: with several keys and no owner named, `/delegate` signs in with the
// primary key unless the user explicitly asks for a different one. Every API
// call is answered by `page.route`; no API server runs.

import { test, expect, type Page, type Route } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const CAPS_READ = 'tinycloud.capabilities/read';
const KV_GET = 'tinycloud.kv/get';
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const key = (id: string, keyIndex: number, address: string, isPrimary: boolean, keyType = 'MANAGED') =>
  ({ id, address, publicKey: '0x', keyIndex, label: null, keyType, isPrimary, createdAt: new Date().toISOString() });

const primary = key('key_0', 0, '0xd559ccd9eb87c530a9a349262669386de93cf412', true);
const second = key('key_1', 1, '0x2222222222222222222222222222222222222222', false);
const external = key('key_2', 2, '0x3333333333333333333333333333333333333333', false, 'EXTERNAL');
const threeKeys = [primary, second, external];

/** A `/api/delegate/prepare` response for the key that will sign. */
function preparedFor(address: string) {
  const space = `tinycloud:pkh:eip155:1:${address}:default`;
  const siwe = [
    'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
    'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-03T00:00:00.000Z', 'Expiration Time: 2026-11-03T01:00:00.000Z',
    'Resources:',
    `- ${makeRecapResource({ [`${space}/capabilities`]: { [CAPS_READ]: [{}] }, [`${space}/kv/notes/`]: { [KV_GET]: [{}] } })}`,
  ].join('\n');
  const option = (service: string, short: string, path: string, ability: string, required: boolean) => {
    const optionKey = `${service}\0${space}\0${path}`;
    return { key: optionKey, service: short, path, label: short, resourcePath: path ? `${short}/${path}` : short,
      actions: [{ key: `${optionKey}\0${ability}`, action: ability.split('/')[1], ability, required }] };
  };
  const permissions = [option('tinycloud.capabilities', 'capabilities', '', CAPS_READ, true), option('tinycloud.kv', 'kv', 'notes/', KV_GET, false)];
  return {
    prepared: { siwe, spaceId: space, jwk: {} }, spaceId: space, ownerDid: `did:pkh:eip155:1:${address}`, address, chainId: 1,
    host: 'https://node.tinycloud.xyz', permissions, selectedActionKeys: permissions.flatMap((p) => p.actions.map((a) => a.key)), edited: false,
    authorizationContext: { token: 't', expiresAt: Date.now() + 600_000, baselineAbilitiesDigest: 'd' },
  };
}

/** Mocks the API; returns the key IDs `/api/delegate/prepare` was asked to prepare, in order. */
async function mock(page: Page, keys: unknown[], delegation: Record<string, unknown> = {}) {
  const prepared: string[] = [];
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/auth/get-session') return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'sam@example.test', name: 'Sam' } });
    if (url.pathname === '/api/keys') return json(route, 200, { keys });
    if (url.pathname === '/api/delegate/prepare') {
      const { keyId } = route.request().postDataJSON() as { keyId: string };
      prepared.push(keyId);
      const signer = (keys as Array<{ id: string; address: string }>).find((k) => k.id === keyId)!;
      return json(route, 200, preparedFor(signer.address));
    }
    if (url.pathname === '/api/delegate') {
      return json(route, 200, { delegationHeader: { Authorization: 'Bearer x' }, delegationCid: 'bafy', spaceId: 'tinycloud:pkh:eip155:1:0xd559ccd9eb87c530a9a349262669386de93cf412:default', hostActivated: true, permissions: [], ...delegation });
    }
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });
  return prepared;
}

const jwk = encodeBase64UrlJson({ kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
const noOwner = `/delegate?did=did:key:z6Mk&jwk=${jwk}`;
const approve = (page: Page) => page.getByRole('button', { name: 'Approve', exact: true });
const keyButton = (page: Page, name: RegExp) => page.getByRole('button', { name });

test.describe('TC-703 primary key picker', () => {
  test('with no owner named, the primary key is preselected', async ({ page }) => {
    const prepared = await mock(page, threeKeys);
    await page.goto(noOwner);
    await expect(approve(page)).toBeEnabled();
    expect(prepared).toEqual(['key_0']);
    await expect(page.getByLabel('Signing key')).toContainText('Key 0');
    await expect(page.getByLabel('Signing key')).toContainText('0xd559...f412');
  });

  test('Back shows the primary key; another key needs "Use a different key"', async ({ page }) => {
    const prepared = await mock(page, threeKeys);
    await page.goto(noOwner);
    await expect(approve(page)).toBeEnabled();
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();

    // No auto-advance loop: the picker stays, offering only the primary key.
    await expect(page.getByText('Sign in with your primary key')).toBeVisible();
    await expect(keyButton(page, /Key 0/)).toContainText('Primary');
    await expect(keyButton(page, /Key 1/)).toHaveCount(0);
    await expect(keyButton(page, /Key 2/)).toHaveCount(0);
    await expect(page.getByRole('button', { name: /Generate/ })).toHaveCount(0);
    await expect(page.getByText(/separate account owner/)).toHaveCount(0);

    await page.getByRole('button', { name: 'Use a different key' }).click();
    await expect(page.getByText(/Each key is a separate account owner, with its own data and spaces/)).toBeVisible();
    await expect(keyButton(page, /Key 1/)).toBeVisible();
    await expect(keyButton(page, /Key 2/)).toContainText('(External)');
    await expect(keyButton(page, /Key 1/)).not.toContainText('Primary');
    await expect(page.getByRole('button', { name: /Generate/ })).toHaveCount(0);

    await keyButton(page, /Key 1/).click();
    await expect(approve(page)).toBeEnabled();
    await expect(page.getByLabel('Signing key')).toContainText('Key 1');
    expect(prepared).toEqual(['key_0', 'key_1']);
  });

  test('a named owner still wins, with the primary key labelled in the list', async ({ page }) => {
    const prepared = await mock(page, threeKeys);
    const space = `tinycloud:pkh:eip155:1:${second.address}:default`;
    const request = [
      { service: 'tinycloud.kv', space, path: 'notes/', actions: [KV_GET] },
      { service: 'tinycloud.capabilities', space, path: '', actions: [CAPS_READ] },
    ];
    await page.goto(`${noOwner}&permissions=${encodeBase64UrlJson({ permissions: request })}`);
    await expect(approve(page)).toBeEnabled();
    expect(prepared).toEqual(['key_1']);

    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    await expect(page.getByText('Select a key to authorize:')).toBeVisible();
    await expect(keyButton(page, /Key 1/)).toContainText('Requested');
    await expect(keyButton(page, /Key 0/)).toContainText('Primary');
    // The named-owner path keeps its own override; no primary-key gate.
    await expect(keyButton(page, /Key 0/)).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Use a different key' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /Generate/ })).toHaveCount(0);
  });

  test('without a primary key, every key is listed and none is preselected', async ({ page }) => {
    const prepared = await mock(page, [{ ...primary, isPrimary: false }, second, external]);
    await page.goto(noOwner);
    await expect(page.getByText('Select a key to authorize:')).toBeVisible();
    for (const name of [/Key 0/, /Key 1/, /Key 2/]) await expect(keyButton(page, name)).toBeEnabled();
    await expect(page.getByText('Primary', { exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Use a different key' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /Generate/ })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Link External Wallet' })).toBeVisible();
    expect(prepared).toEqual([]);
  });

  test('the paste code carries the primary flag from the API unchanged', async ({ page }) => {
    await mock(page, threeKeys, { primary: true });
    await page.goto(noOwner);
    await approve(page).click();
    const code = await page.locator('textarea').inputValue();
    const payload = JSON.parse(Buffer.from(code, 'base64').toString('utf8')) as Record<string, unknown>;
    expect(payload.primary).toBe(true);
  });

  test('the CLI callback receives the primary flag from the API unchanged', async ({ page }) => {
    await mock(page, threeKeys, { primary: false });
    let delivered: Record<string, unknown> | null = null;
    await page.route('http://127.0.0.1:47123/callback', (route) => {
      if (route.request().method() === 'POST') delivered = route.request().postDataJSON() as Record<string, unknown>;
      return route.fulfill({ status: 200, contentType: 'application/json', headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type' }, body: '{"success":true}' });
    });
    await page.goto(`${noOwner}&callback=${encodeURIComponent('http://127.0.0.1:47123/callback')}`);
    await approve(page).click();
    await expect(page.getByText('You can close this window and return to the CLI.')).toBeVisible();
    expect(delivered).not.toBeNull();
    expect(delivered!.primary).toBe(false);
  });
});
