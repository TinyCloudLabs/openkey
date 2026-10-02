import { test, expect, type Page } from '@playwright/test';
import { generateKeyPairSync } from 'node:crypto';

if (process.env.OPENKEY_TEST_BROWSER_CHANNEL) test.use({ channel: process.env.OPENKEY_TEST_BROWSER_CHANNEL });

const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const relayPublicJwk = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' });
const permissions = [
  { service: 'tinycloud.kv', space: 'default', path: 'shares/', actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] },
  { service: 'tinycloud.capabilities', space: 'default', path: '', actions: ['tinycloud.capabilities/read'] },
];
const record = {
  id: 'device-fixture', userCode: 'TEST-CODE', sessionDid: 'did:key:synthetic-browser-fixture', publicJwk: jwk, relayPublicJwk,
  permissions, nodeOrigin: 'https://node.tinycloud.xyz', shareOrigin: 'https://share.tinycloud.xyz',
  delegationExpiresAt: '2099-01-01T01:00:00Z', transactionExpiresAt: '2099-01-01T00:00:00Z', delegationTtlSeconds: 3600,
  reason: 'Server-verified device request', shareOnly: false,
};
const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

async function setup(page: Page, options: { tamperedScope?: boolean; discovery?: boolean; emptyPermissions?: boolean; device?: boolean } = {}) {
  const calls: Array<{ path: string; body: any }> = [];
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return route.fulfill({ json: {
      session: { id: 'session', userId: 'user', token: 'synthetic-session', expiresAt: '2099-01-01T00:00:00Z' },
      user: { id: 'user', name: 'Test user', email: 'test@example.invalid', emailVerified: true },
    } });
    if (path === '/api/keys') return route.fulfill({ json: { keys: [{ id: 'key', address: '0x1111111111111111111111111111111111111111', keyIndex: 0, keyType: 'MANAGED', label: 'Test account' }] } });
    calls.push({ path, body: route.request().postDataJSON() });
    if (path === '/api/device-authorizations/lookup') return route.fulfill({ json: record });
    if (path === '/api/delegate/prepare') return route.fulfill({ json: {
      prepared: { siwe: 'Synthetic device permission preview' }, authorizationContext: { token: 'prepared-context' },
      selectedActionKeys: ['read'], permissions: [{ key: 'read', label: 'Read', resourcePath: 'shares/', actions: [{ key: 'read', action: 'read', ability: 'tinycloud.kv/get', required: true }] }],
    } });
    if (path === '/api/delegate') return route.fulfill({ json: {
      hostActivated: true, delegationHeader: 'synthetic-proof-not-a-credential', expiresAt: '2099-01-01T01:00:00Z',
      permissions: permissions.map(entry => ({ ...entry, service: entry.service.slice('tinycloud.'.length), space: 'tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:default' })),
    } });
    if (path === '/api/device-authorizations/device-fixture/approve') return route.fulfill({ json: { ok: true } });
    return route.fulfill({ status: 404, json: { error: 'Unexpected test request' } });
  });
  const query = new URLSearchParams({ jwk: encode(jwk), host: record.nodeOrigin, reason: 'Untrusted link reason', expiry: '3600s' });
  query.set('permissions', options.emptyPermissions ? '' : encode({ permissions: options.tamperedScope ? permissions.slice(1) : permissions }));
  if (options.device !== false) {
    query.set('deviceTransactionId', record.id);
    query.set('deviceUserCode', record.userCode);
    query.set('did', record.sessionDid);
    query.set('relayJwk', encode(relayPublicJwk));
    query.set('deviceShareOrigin', record.shareOrigin);
  }
  if (options.discovery) { query.set('discovery', 'app-read'); query.set('discoveryProtocolVersion', '1'); }
  await page.goto(`/delegate?${query}`);
  await page.getByRole('button', { name: /Test account/ }).click();
  return calls;
}

test('device consent keeps verified reason, acknowledgement, transaction binding and encrypted relay', async ({ page }) => {
  const calls = await setup(page);
  await expect(page.getByRole('heading', { name: 'Authorize CLI Access' })).toBeVisible();
  await expect(page.getByText(record.reason).first()).toBeVisible();
  await expect(page.getByText('Untrusted link reason')).toHaveCount(0);
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.getByRole('alert').first()).toContainText('Confirm that you started this request yourself');
  expect(calls.filter(call => call.path === '/api/delegate')).toHaveLength(0);
  await page.getByRole('checkbox', { name: 'I started this request myself, on a device I control.' }).check();
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Authenticated', exact: true })).toBeVisible();
  for (const path of ['/api/delegate/prepare', '/api/delegate']) {
    expect(calls.find(call => call.path === path)?.body).toMatchObject({ deviceTransactionId: record.id, reason: record.reason, expiry: '3600s', permissions });
  }
  const approved = calls.find(call => call.path.endsWith('/approve'))?.body;
  expect(approved.binding.permissions).toEqual(permissions);
  expect(approved.relay.algorithm).toBe('ECDH-P256-A256GCM');
  expect(approved.relay.delegationHeader).toBeUndefined();
});

test('app discovery cannot bypass a mismatched device request', async ({ page }) => {
  const calls = await setup(page, { tamperedScope: true, discovery: true });
  await expect(page.getByRole('alert')).toContainText('does not match the device request');
  expect(calls.map(call => call.path)).toEqual(['/api/device-authorizations/lookup']);
});

for (const discovery of [false, true]) test(`empty permissions refuse ${discovery ? 'app discovery' : 'fixed approval'} before preparation`, async ({ page }) => {
  const calls = await setup(page, { device: false, emptyPermissions: true, discovery });
  await expect(page.getByRole('alert')).toContainText('Could not decode the requested permissions');
  expect(calls).toEqual([]);
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(0);
});
