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
const base = { requestId: 'native-1', userId: 'u', keyId: 'key-1', address, client: { clientId: 'exo-native', name: 'Exo', icon: null, organization: 'TinyCloud Labs' },
  redirectScheme: 'xyz.tinycloud.exo', sessionDid: 'did:key:z6Mk', tinycloudHost: 'https://tee.node.tinycloud.xyz', ttlSeconds: 3600,
  grantLifetimeSeconds: 2592000, hostPlan: { host: 'https://tee.node.tinycloud.xyz', spaceId: space, peerId: 'did:key:z6Mk', hostSiwe: 'host bytes' }, permissionOptions };
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

const EXO_BRANDING = { clientId: 'exo-native', name: 'Exo', icon: 'https://tinycloud.chat/icons/pwa-512.png', organization: 'TinyCloud Labs',
  theme: { backgroundColor: '#09090B', accentColor: '#FAFAFA' } };
const sessionBody = { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'u', email: 'sam@example.test', name: 'Sam' } };

test.describe('compact native consent', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('shows one sentence, collapsed details, re-prepares optional actions and echoes the approved revision', async ({ page }) => {
    const calls: Array<{ path: string; body: any }> = [];
    let revision = 0;
    await page.route('**/api/**', route => {
      const path = new URL(route.request().url()).pathname;
      if (path === '/api/auth/get-session') return json(route, sessionBody);
      if (path === '/api/oauth/tinycloud/clients/exo-native/branding') return json(route, EXO_BRANDING);
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
    await page.route('https://tinycloud.chat/**', route => route.fulfill({ status: 200, contentType: 'image/svg+xml', body: '<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"/>' }));
    await page.route('https://example.test/**', route => route.fulfill({ status: 200, contentType: 'text/html', body: '<p>app</p>' }));
    await page.goto('/oauth/consent?client_id=exo-native&tinycloud_request=native-1&sig=test');

    await expect(page.getByRole('heading', { name: 'Exo wants access' })).toBeVisible();
    const icon = await page.locator('.nb-icon').boundingBox();
    expect([icon!.width, icon!.height]).toEqual([64, 64]);
    await expect(page.locator('.nb-icon')).toHaveCSS('border-radius', '22.5%');
    await expect(page.getByRole('heading', { name: 'Exo wants access' })).toHaveCSS('font-size', '32px');
    await expect(page.getByText('Exo will be able to read and save your Exo data.')).toBeVisible();
    await expect(page.getByText('Access lasts up to 30 days and renews automatically while you use Exo.')).toBeVisible();
    await expect(page.getByText(/First sign-in: this also lets your TinyCloud node host your data/)).toBeVisible();
    await expect(page.getByText('Signed in as')).toContainText('sam@example.test');
    await expect(page.getByRole('button', { name: 'Not you?' })).toHaveCount(0);
    await expect(page.getByText('Secured by OpenKey · openkey.so')).toBeVisible();
    await expect(page.locator('[data-native-shell]')).toHaveCSS('background-color', 'rgb(9, 9, 11)');
    await expect(page.getByRole('button', { name: 'Allow', exact: true })).toHaveCSS('background-color', 'rgb(250, 250, 250)');

    const details = page.locator('details.details');
    await expect(details).not.toHaveAttribute('open', '');
    await expect(page.getByText('xyz.tinycloud.exo://')).toBeHidden();
    await details.locator(':scope > summary').click();
    await expect(page.getByText('xyz.tinycloud.exo://')).toBeVisible();
    await expect(page.getByText('https://tee.node.tinycloud.xyz', { exact: true })).toBeVisible();
    await expect(page.getByText('TinyCloud Labs', { exact: true })).toBeVisible();
    await expect(page.getByText(/permanent hosting authorization/)).toBeVisible();
    await expect(page.getByText(/Each renewal lasts 1 hour/)).toBeVisible();
    await expect(page.getByText('Canonical OpenKey key')).toBeVisible();
    await expect(page.getByText('No signed manifest')).toBeVisible();
    await expect(page.getByText('Private-use redirect schemes do not verify the app')).toBeVisible();
    for (const label of await details.locator('label.action-toggle').all()) {
      expect((await label.boundingBox())!.height).toBeGreaterThanOrEqual(48);
    }
    for (const summary of await page.locator('summary').all()) {
      expect((await summary.boundingBox())!.height).toBeGreaterThanOrEqual(48);
    }
    await expect(details.getByRole('checkbox', { name: 'get' })).toBeChecked();
    await expect(details.getByRole('checkbox', { name: 'put' })).toBeChecked();

    await details.getByRole('checkbox').last().uncheck();
    await expect.poll(() => calls.filter(c => c.path.endsWith('/prepare')).length).toBe(2);
    await expect(page.getByText('Exo will be able to read your Exo data.')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Allow', exact: true })).toBeEnabled();
    await expect(page.getByRole('button', { name: "Don't allow", exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Allow', exact: true }).click();
    await expect.poll(() => calls.some(c => c.path.endsWith('/approve'))).toBe(true);
    const approve = calls.find(c => c.path.endsWith('/approve'))!.body;
    expect(approve).toMatchObject({ revision: 2, digest: 'digest-2', hostSiwe: 'host bytes', sessionSiwe: siwe(false) });
    await expect.poll(() => calls.some(c => c.path === '/api/auth/oauth2/consent' && c.body.accept === true)).toBe(true);
    await page.waitForURL('https://example.test/callback?code=code');
  });

  test('a failed branding fetch keeps the dark shell and the consent still works', async ({ page }) => {
    await page.route('**/api/**', route => {
      const path = new URL(route.request().url()).pathname;
      if (path === '/api/auth/get-session') return json(route, sessionBody);
      if (path === '/api/oauth/tinycloud/clients/exo-native/branding') return json(route, { error: 'boom' }, 500);
      if (path.endsWith('/prepare')) return json(route, { ...base, hostPlan: null, revision: 1, digest: 'digest-1', sessionSiwe: siwe(true), selectedActionKeys: selected });
      return json(route, { error: `unmocked ${path}` }, 404);
    });
    await page.goto('/oauth/consent?client_id=exo-native&tinycloud_request=native-1&sig=test');
    await expect(page.locator('[data-native-shell]')).toHaveAttribute('data-branding', 'unavailable');
    await expect(page.locator('[data-native-shell]')).toHaveCSS('background-color', 'rgb(9, 9, 11)');
    await expect(page.getByRole('heading', { name: 'Exo wants access' })).toBeVisible();
    await expect(page.getByText(/First sign-in/)).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Allow', exact: true })).toBeEnabled();
  });

  test('parser warnings stay reachable inside Details', async ({ page }) => {
    const [recap] = siwe(true).split('\n').filter(line => line.startsWith('- urn:recap:'));
    const duplicated = `${siwe(true)}\n${recap}`;
    await page.route('**/api/**', route => {
      const path = new URL(route.request().url()).pathname;
      if (path === '/api/auth/get-session') return json(route, sessionBody);
      if (path === '/api/oauth/tinycloud/clients/exo-native/branding') return json(route, EXO_BRANDING);
      if (path.endsWith('/prepare')) return json(route, { ...base, revision: 1, digest: 'digest-1', sessionSiwe: duplicated, selectedActionKeys: selected });
      return json(route, { error: `unmocked ${path}` }, 404);
    });
    await page.goto('/oauth/consent?client_id=exo-native&tinycloud_request=native-1&sig=test');
    const details = page.locator('details.details');
    await expect(details).toBeVisible();
    await expect(page.getByText(/appears multiple times/).first()).toBeHidden();
    await details.locator(':scope > summary').click();
    await expect(page.getByRole('heading', { name: 'Notes' })).toBeVisible();
    await expect(page.getByText(/duplicate-action Action tinycloud\.kv\/get appears multiple times/)).toBeVisible();
  });

  test('a session-less visitor is sent to login and never sees the light consent card', async ({ page }) => {
    await page.route('**/api/**', route => {
      const path = new URL(route.request().url()).pathname;
      if (path === '/api/auth/get-session') return json(route, null);
      if (path === '/api/oauth/tinycloud/clients/exo-native/branding') return json(route, EXO_BRANDING);
      if (path === '/api/auth/providers') return json(route, { providers: [] });
      return json(route, { error: `unmocked ${path}` }, 404);
    });
    await page.goto('/oauth/consent?client_id=exo-native&tinycloud_request=native-1&sig=test');
    await page.waitForURL(/\/auth\/login\?redirect=/);
    await expect(page.getByText('Loading...')).toHaveCount(0);
  });
});

test('retry after provider consent failure does not approve or sign again', async ({ page }) => {
  let approvals = 0;
  let providerPosts = 0;
  await page.route('**/api/**', route => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'u', email: 'sam@example.test' } });
    if (path.endsWith('/prepare')) return json(route, { ...base, revision: 1, digest: 'digest-1', sessionSiwe: siwe(true), selectedActionKeys: selected });
    if (path.endsWith('/approve')) { approvals++; return json(route, { status: 'APPROVED', revision: 1, hosting: 'existing' }); }
    if (path === '/api/auth/oauth2/consent') {
      providerPosts++;
      return providerPosts === 1 ? json(route, { error: 'temporarily_unavailable' }, 503)
        : json(route, { url: 'https://example.test/callback?code=code' });
    }
    return json(route, { error: `unmocked ${path}` }, 404);
  });
  await page.goto('/oauth/consent?client_id=exo-native&tinycloud_request=native-1&sig=test');
  await page.getByRole('button', { name: 'Allow', exact: true }).click();
  await expect(page.getByText('temporarily_unavailable')).toBeVisible();
  await page.getByRole('button', { name: 'Continue to app' }).click();
  await expect.poll(() => providerPosts).toBe(2);
  expect(approvals).toBe(1);
});

test('denial still reaches provider when request denial route fails', async ({ page }) => {
  let providerDenied = false;
  await page.route('**/api/**', route => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'u', email: 'sam@example.test' } });
    if (path.endsWith('/prepare')) return json(route, { ...base, revision: 1, digest: 'digest-1', sessionSiwe: siwe(true), selectedActionKeys: selected });
    if (path.endsWith('/deny')) return json(route, { error: 'request_not_pending' }, 409);
    if (path === '/api/auth/oauth2/consent') { providerDenied = route.request().postDataJSON().accept === false; return json(route, { url: 'https://example.test/callback?error=access_denied' }); }
    return json(route, { error: `unmocked ${path}` }, 404);
  });
  await page.goto('/oauth/consent?client_id=exo-native&tinycloud_request=native-1&sig=test');
  await page.getByRole('button', { name: "Don't allow", exact: true }).click();
  await expect.poll(() => providerDenied).toBe(true);
});

test('reloaded approved request can finish provider consent', async ({ page }) => {
  let approvals = 0;
  let providerPosts = 0;
  await page.route('**/api/**', route => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'u', email: 'sam@example.test' } });
    if (path.endsWith('/prepare')) return json(route, { status: 'APPROVED' });
    if (path.endsWith('/approve')) { approvals++; return json(route, { error: 'must not reapprove' }, 409); }
    if (path === '/api/auth/oauth2/consent') { providerPosts++; return json(route, { url: 'https://example.test/callback?code=code' }); }
    return json(route, { error: `unmocked ${path}` }, 404);
  });
  await page.goto('/oauth/consent?client_id=exo-native&tinycloud_request=native-1&sig=test');
  await expect(page.getByText('Your delegation was approved.')).toBeVisible();
  await page.getByRole('button', { name: 'Continue to app' }).click();
  await expect.poll(() => providerPosts).toBe(1);
  expect(approvals).toBe(0);
});
