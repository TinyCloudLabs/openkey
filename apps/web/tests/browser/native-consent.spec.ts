import { test, expect, type Route } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:applications`;
const caps = 'tinycloud.capabilities/read';
const kvGet = 'tinycloud.kv/get';
const kvPut = 'tinycloud.kv/put';
const siwe = (withPut: boolean) => [
  'openkey.so wants you to sign in with your Ethereum account:', address, '',
  'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-07T04:00:00.000Z',
  'Expiration Time: 2026-10-07T05:00:00.000Z', 'Resources:',
  `- ${makeRecapResource({ [`${space}/capabilities`]: { [caps]: [{}] }, [`${space}/kv/xyz.tinycloud.tinychat/threads/`]: { [kvGet]: [{}], ...(withPut ? { [kvPut]: [{}] } : {}) } })}`,
].join('\n');
const option = (service: string, short: string, path: string, actions: [string, boolean][]) => {
  const key = `${service}\0${space}\0${path}`;
  return { key, service: short, path, label: short, resourcePath: path ? `${short}/${path}` : short,
    actions: actions.map(([ability, required]) => ({ key: `${key}\0${ability}`, action: ability.split('/')[1], ability, required })) };
};
const permissionOptions = [option('tinycloud.capabilities', 'capabilities', '', [[caps, true]]), option('tinycloud.kv', 'kv', 'xyz.tinycloud.tinychat/threads/', [[kvGet, false], [kvPut, false]])];
const selected = permissionOptions.flatMap(p => p.actions.map(a => a.key));
const base = { requestId: 'native-1', userId: 'u', keyId: 'key-1', address, client: { clientId: 'exo-native', name: 'Exo', icon: null, organization: 'TinyCloud Labs', verified: false },
  redirectScheme: 'xyz.tinycloud.exo', sessionDid: 'did:key:z6Mk', tinycloudHost: 'https://tee.node.tinycloud.xyz', ttlSeconds: 3600,
  grantLifetimeSeconds: 2592000, hostPlan: { host: 'https://tee.node.tinycloud.xyz', spaceId: space, peerId: 'did:key:z6Mk', hostSiwe: 'host bytes' }, permissionOptions };
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

test('native consent shows the disclosed grant, re-prepares optional actions and echoes the approved revision', async ({ page }) => {
  const calls: Array<{ path: string; body: any }> = [];
  let revision = 0;
  await page.route('**/api/**', route => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'u', email: 'sam@example.test', name: 'Sam' } });
    if (path.endsWith('/prepare')) {
      revision++;
      const body = route.request().postDataJSON();
      calls.push({ path, body });
      const keys = body.actionKeys ?? selected;
      return json(route, { ...base, revision, digest: `digest-${revision}`, sessionSiwe: siwe(keys.includes(selected.at(-1))), selectedActionKeys: keys });
    }
    if (path.endsWith('/approve')) { calls.push({ path, body: route.request().postDataJSON() }); return json(route, { status: 'APPROVED', revision, hosting: 'existing' }); }
    if (path === '/api/auth/oauth2/consent') { calls.push({ path, body: route.request().postDataJSON() }); return json(route, { url: 'https://example.test/callback?code=code' }); }
    return json(route, { error: `unmocked ${path}` }, 404);
  });
  await page.goto('/oauth/consent?client_id=exo-native&tinycloud_request=native-1&sig=test');
  await expect(page.getByText('Unverified app')).toBeVisible();
  await expect(page.getByText('xyz.tinycloud.exo://')).toBeVisible();
  await expect(page.getByText(/permanent hosting authorization/)).toBeVisible();
  await expect(page.getByText(/1 hour from approval/)).toBeVisible();
  const details = page.locator('details.advanced-details');
  await details.locator(':scope > summary').click();
  await details.getByRole('button', { name: 'Edit' }).click();
  const closed = details.locator('details.severity-bucket:not([open]) > summary');
  if (await closed.count()) await closed.first().click();
  const optional = details.getByRole('checkbox').last();
  await optional.uncheck();
  await expect.poll(() => calls.filter(c => c.path.endsWith('/prepare')).length).toBe(2);
  await expect(page.getByRole('button', { name: 'Allow', exact: true })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Deny', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Allow', exact: true }).click();
  await expect.poll(() => calls.some(c => c.path.endsWith('/approve'))).toBe(true);
  const approve = calls.find(c => c.path.endsWith('/approve'))!.body;
  expect(approve).toMatchObject({ revision: 2, digest: 'digest-2', hostSiwe: 'host bytes', sessionSiwe: siwe(false) });
  await expect.poll(() => calls.some(c => c.path === '/api/auth/oauth2/consent' && c.body.accept === true)).toBe(true);
});
