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

const jwk = encodeBase64UrlJson({ kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });

// TC-2304: signed-out /delegate -> Register -> Google popup -> back on /delegate. The popup signs in inside its
// own window; this tab must re-read its session when it finishes, not stay on the signed-out card until a reload.
async function mockWithPopupSession(page: Page) {
  const state = { signedIn: false };
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/auth/get-session') {
      return json(route, 200, state.signedIn
        ? { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'new@example.test', name: 'New' } }
        : null);
    }
    if (url.pathname === '/api/auth/providers') return json(route, 200, { providers: ['google'] });
    if (url.pathname === '/api/keys') return json(route, 200, { keys: oneKey });
    if (url.pathname === '/api/delegate/prepare') return json(route, 200, prepared);
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });
  // The popup's own page: it signs the account in (server side) and tells its opener, as /auth/social/callback does.
  // A popup is a new page of the same context: the route must be on the context, not on the opener page.
  await page.context().route('**/auth/social/callback**', (route) => {
    state.signedIn = true;
    return route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: '<!doctype html><script>window.opener.postMessage({ type: "openkey:social:complete", sessionToken: "popup-session" }, location.origin); window.close();</script>',
    });
  });
  return state;
}

test('after the Google popup signs a new user in, this tab leaves the signed-out card without a reload', async ({ page }) => {
  await mockWithPopupSession(page);
  await page.goto(`/delegate?did=did:key:z6Mk&jwk=${jwk}`);
  await expect(page.getByText('Sign in to review the requested access')).toBeVisible();
  await page.getByRole('link', { name: 'Register', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Continue with Google' })).toBeVisible();
  await page.getByRole('button', { name: 'Continue with Google' }).click();
  // Back on /delegate, signed in: the approval, not the signed-out card.
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
  await expect(page.getByText('Sign in to review the requested access')).toHaveCount(0);
});
