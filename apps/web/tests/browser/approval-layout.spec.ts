import { test, expect, type BrowserContext, type Page } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';
import { makeRecapResource, siweWithResources, FIXTURE_META } from '../../../../packages/capability-review/test/fixtures/index';

const id = 'abcdefghijklmnopqrstuvwxyz';
const reference = `/a/${id}#v=4&k=${'A'.repeat(43)}&c=bafkreia${'a'.repeat(52)}`;
const address = FIXTURE_META.address;
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) };
const space = `tinycloud:pkh:eip155:1:${address}:agents`;
const kvTuples: Array<[string, string[]]> = [
  ['to/', ['get', 'put', 'list', 'del', 'metadata']],
  ['me/requests/', ['put']], ['me/mirror/', ['get', 'put', 'list', 'del']],
  ['me/state/', ['get', 'put', 'list', 'del']], ['me/consumed/', ['get', 'put', 'list']],
  ['me/peers/', ['get', 'put', 'list', 'del']], ['me/', ['get', 'list']],
];
const permissions = kvTuples.map(([path, verbs]) => ({ service: 'tinycloud.kv', space: 'agents', path: `xyz.tinycloud.courier/${path}`, actions: verbs.map(verb => `tinycloud.kv/${verb}`) }));
permissions.push({ service: 'tinycloud.hooks', space: 'agents', path: 'kv/xyz.tinycloud.courier/', actions: ['tinycloud.hooks/subscribe'] });
const key = { id: 'layout-key', address, publicKey: '0x', keyIndex: 0, label: 'Test key', keyType: 'MANAGED', isPrimary: true, createdAt: new Date().toISOString() };

// Browser-boundary responses exercise the real route layouts and controls. Details: TC-2315
async function serve(context: BrowserContext) {
  const writes: string[] = [];
  await context.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname;
    const json = (body: unknown) => route.fulfill({ json: body });
    if (path === '/api/auth/get-session') return json({ session: { id: 'layout-session', userId: 'layout-user', expiresAt: new Date(Date.now() + 3600_000).toISOString() }, user: { id: 'layout-user', email: 'owner@example.test', name: 'Owner' } });
    if (path === '/api/keys') return json({ keys: [key] });
    if (path === '/api/keys/layout-key') return json({ key });
    if (path === `/api/approval-requests/${id}/load`) return json({ requestId: id, approved: false, expiresAt: new Date(Date.now() + 3600_000).toISOString(), request: { targetDid: 'did:key:requester', targetPublicJwk: jwk, nodeOrigin: 'https://node.tinycloud.xyz', permissions, grantLifetimeSeconds: 3600 } });
    if (path === '/api/delegate/prepare') {
      const siwe = siweWithResources([makeRecapResource(Object.fromEntries(permissions.map(entry => [`${space}/${entry.service.replace('tinycloud.', '')}/${entry.path}`, Object.fromEntries(entry.actions.map(action => [action, []]))])))]);
      const options = permissions.map(entry => ({ key: `${entry.service}\0${space}\0${entry.path}`, service: entry.service.replace('tinycloud.', ''), path: entry.path, label: entry.path, resourcePath: entry.path, actions: entry.actions.map(ability => ({ key: `${entry.service}\0${space}\0${entry.path}\0${ability}`, action: ability.split('/')[1], ability, required: false })) }));
      return json({ prepared: { siwe, spaceId: space, jwk }, spaceId: space, ownerDid: `did:pkh:eip155:1:${address}`, address, chainId: 1, host: 'https://node.tinycloud.xyz', permissions: options, selectedActionKeys: options.flatMap(option => option.actions.map(action => action.key)), edited: false, authorizationContext: { token: 'layout-context', expiresAt: Date.now() + 600_000, baselineAbilitiesDigest: 'layout-digest' } });
    }
    if (path === '/api/auth/sign-out') { writes.push(path); return json({ success: true }); }
    writes.push(path);
    return route.fulfill({ status: 404, json: { error: 'Unexpected local test request' } });
  });
  return writes;
}

async function screenshot(page: Page, name: string) {
  const phase = process.env.TC2315_BEFORE ? 'before' : 'after';
  await page.screenshot({ path: `/var/tmp/tc-2315-${phase}-${name}.png` });
}

for (const [name, url] of [['short-approval', reference], ['delegate', `/delegate?did=did:key:requester&jwk=${encodeBase64UrlJson(jwk)}`]]) {
  test(`${name} uses the approval layout and retains Sign out`, async ({ page, context }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    const calls = await serve(context);
    await page.goto(url);
    await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
    await screenshot(page, name);
    if (!process.env.TC2315_BEFORE) {
      await expect(page.getByRole('link', { name: 'OpenKey Account', exact: false })).toHaveCount(0);
      await expect(page.getByRole('link', { name: 'Dashboard', exact: true })).toHaveCount(0);
      await expect(page.locator('footer').filter({ hasText: 'OpenKey Account' })).toHaveCount(0);
    }
    await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await expect.poll(() => calls.includes('/api/auth/sign-out')).toBe(true);
    expect(calls.filter(path => path === '/api/delegate' || path.includes('/approve'))).toEqual([]);
  });
}

test('popup sign uses the approval layout and keeps Cancel', async ({ page, context }) => {
  await serve(context);
  await page.goto('/__parity_harness');
  await page.evaluate(() => { (window as any).responses = []; window.addEventListener('message', event => { (window as any).responses.push(event.data); }); });
  const opened = page.waitForEvent('popup');
  await page.evaluate(() => { (window as any).signPopup = window.open(`/widget/sign?origin=${encodeURIComponent(location.origin)}`); });
  const popup = await opened;
  await popup.setViewportSize({ width: 390, height: 844 });
  await expect.poll(() => page.evaluate(() => (window as any).responses.some((entry: any) => entry.type === 'openkey:ready'))).toBe(true);
  await page.evaluate(() => (window as any).signPopup.postMessage({ type: 'openkey:sign:request', requestId: 'layout-popup', protocolVersion: 1, keyId: 'layout-key', message: 'Local layout review' }, location.origin));
  await expect(popup.getByRole('button', { name: 'Approve', exact: true })).toBeVisible();
  await screenshot(popup, 'popup');
  if (!process.env.TC2315_BEFORE) await expect(popup.getByRole('link', { name: 'Dashboard', exact: true })).toHaveCount(0);
  await popup.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect.poll(() => page.evaluate(() => (window as any).responses.some((entry: any) => entry.type === 'openkey:sign:response' && entry.success === false))).toBe(true);
});

test('account pages retain their account navigation', async ({ page, context }) => {
  await serve(context);
  for (const path of ['/dashboard', '/dashboard/api-keys']) {
    await page.goto(path);
    await expect(page.getByRole('link', { name: 'Dashboard', exact: true })).toBeVisible();
    await expect(page.getByRole('link', { name: 'API keys', exact: true })).toBeVisible();
    await expect(page.getByRole('link', { name: 'OpenKey Admin console' })).toBeVisible();
  }
});
