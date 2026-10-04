// TC-659 / TC-660: the real /delegate and /device routes with every API
// call answered by `page.route`; no API server runs.

import { test, expect, type Page, type Route } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const KV_GET = 'tinycloud.kv/get', KV_PUT = 'tinycloud.kv/put', CAPS_READ = 'tinycloud.capabilities/read';
const request = [
  { service: 'tinycloud.kv', space, path: 'notes/', actions: [KV_GET, KV_PUT] },
  { service: 'tinycloud.capabilities', space, path: '', actions: [CAPS_READ] },
];
const siwe = [
  'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
  'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-03T00:00:00.000Z', 'Expiration Time: 2026-11-03T01:00:00.000Z',
  'Resources:',
  `- ${makeRecapResource({ [`${space}/capabilities`]: { [CAPS_READ]: [{}] }, [`${space}/kv/notes/`]: { [KV_GET]: [{}], [KV_PUT]: [{}] } })}`,
].join('\n');
const option = (service: string, short: string, path: string, abilities: [string, boolean][]) => {
  const key = `${service}\0${space}\0${path}`;
  return { key, service: short, path, label: short, resourcePath: path ? `${short}/${path}` : short,
    actions: abilities.map(([ability, required]) => ({ key: `${key}\0${ability}`, action: ability.split('/')[1], ability, required })) };
};
const permissionOptions = [option('tinycloud.capabilities', 'capabilities', '', [[CAPS_READ, true]]), option('tinycloud.kv', 'kv', 'notes/', [[KV_GET, false], [KV_PUT, false]])];
const prepared = { prepared: { siwe, spaceId: space, jwk: {} }, spaceId: space, ownerDid: `did:pkh:eip155:1:${address}`, address, chainId: 1,
  host: 'https://node.tinycloud.xyz', permissions: permissionOptions,
  selectedActionKeys: permissionOptions.flatMap((p) => p.actions.map((a) => a.key)), edited: false,
  authorizationContext: { token: 't', expiresAt: Date.now() + 600_000, baselineAbilitiesDigest: 'd' } };
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const key = (id: string, keyIndex: number, keyAddress: string) => ({ id, address: keyAddress, publicKey: '0x', keyIndex, label: null, keyType: 'MANAGED', createdAt: new Date().toISOString() });
const oneKey = [key('key_1', 0, address)];

async function mock(page: Page, keys: unknown[] = oneKey, lookupOk = true) {
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/auth/get-session') return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'sam@example.test', name: 'Sam' } });
    if (url.pathname === '/api/keys') return json(route, 200, { keys });
    if (url.pathname === '/api/delegate/prepare') {
      const body = route.request().postDataJSON() as { actionKeys?: unknown };
      return body.actionKeys === undefined ? json(route, 200, prepared) : json(route, 503, { error: 'Service unavailable' });
    }
    if (url.pathname === '/api/device-authorizations/lookup') return lookupOk ? json(route, 200, { id: 'tx_1', userCode: 'ABCDEFGH', sessionDid: 'did:key:z6Mk', publicJwk: {}, relayPublicJwk: {}, permissions: request, nodeOrigin: 'https://node.tinycloud.xyz', shareOrigin: 'https://share.tinycloud.xyz', delegationExpiresAt: new Date(Date.now() + 86_400_000 * 30).toISOString(), transactionExpiresAt: new Date(Date.now() + 600_000).toISOString(), reason: 'Publish notes from my laptop', delegationTtlSeconds: 2_592_000 }) : json(route, 404, { error: 'not found' });
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });
}
const jwk = encodeBase64UrlJson({ kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });

async function openEditor(page: Page) {
  const details = page.locator('details.advanced-details');
  await details.locator(':scope > summary').click();
  await details.getByRole('button', { name: 'Edit' }).click();
  const closed = details.locator('details.severity-bucket:not([open]) > summary');
  if (await closed.count()) await closed.first().click();
  return details;
}

test.describe('TC-659 CLI /delegate consent parity', () => {
  test('a user with one key skips the key picker and sees no signing-key card', async ({ page }) => {
    await mock(page);
    // No `permissions` parameter: the request names no wallet.
    await page.goto(`/delegate?did=did:key:z6Mk&jwk=${jwk}`);
    await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
    await expect(page.getByText('Select a key to authorize')).toHaveCount(0);
    await expect(page.getByLabel('Signing key')).toHaveCount(0);
    // Header, requester and CLI context come from the shared component.
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByRole('heading', { name: 'Authorize capabilities' })).toBeVisible();
    await expect(dialog).toContainText('Requested by TinyCloud CLI');
    await expect(dialog.getByRole('region', { name: 'Delegation destination' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Authorize CLI Access' })).toHaveCount(0);
  });

  test('a user with several keys picks one and sees it as a static line', async ({ page }) => {
    await mock(page, [key('key_1', 0, address), key('key_2', 1, '0x2222222222222222222222222222222222222222')]);
    await page.goto(`/delegate?did=did:key:z6Mk&jwk=${jwk}`);
    await page.getByRole('button', { name: /Key 0/ }).click();
    await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
    await expect(page.getByLabel('Signing key')).toContainText('Key 0');
    await expect(page.getByLabel('Signing key')).toContainText('0xd559...f412');
  });

  test('an error is shown once, above the buttons', async ({ page }) => {
    await mock(page);
    await page.goto(`/delegate?did=did:key:z6Mk&jwk=${jwk}&permissions=${encodeBase64UrlJson({ permissions: request, reason: 'Sync my notes' })}`);
    await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
    // The reason renders once, in the shared view.
    await expect(page.getByText('Sync my notes', { exact: true })).toHaveCount(1);
    const details = await openEditor(page);
    await details.getByRole('checkbox').last().uncheck();
    await expect(page.getByText('Service unavailable')).toHaveCount(1);
    await expect(page.getByRole('alert').filter({ hasText: 'Service unavailable' })).toHaveCount(1);
  });
});

test.describe('TC-660 /device prefilled code', () => {
  test('a code from the link is read-only and sign-in is the only button', async ({ page }) => {
    await mock(page);
    await page.goto('/device?user_code=ABCD-EFGH');
    await expect(page.getByText('Requested capabilities')).toBeVisible();
    await expect(page.getByRole('textbox', { name: 'Device code' })).toHaveCount(0);
    await expect(page.getByLabel('Device code')).toContainText('ABCD-EFGH');
    const card = page.locator('main');
    await expect(card.getByRole('button')).toHaveCount(0);
    await expect(card.getByRole('link')).toHaveText(['Sign in and review delegation']);
  });

  test('without a code the editable form stays', async ({ page }) => {
    await mock(page);
    await page.goto('/device');
    await expect(page.getByRole('textbox', { name: 'Device code' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Continue' })).toBeVisible();
  });

  test('a prefilled code that fails reopens the editable form', async ({ page }) => {
    await mock(page, oneKey, false);
    await page.goto('/device?user_code=ABCD-EFGH');
    await expect(page.getByText('That code is invalid or expired')).toBeVisible();
    await expect(page.getByRole('textbox', { name: 'Device code' })).toHaveValue('ABCD-EFGH');
  });
});
