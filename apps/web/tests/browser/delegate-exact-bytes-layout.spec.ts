// The 'Exact bytes being signed' block on the `/delegate` approval shows every
// line feed as one line, and a long line scrolls sideways and does not wrap.
// The check reads computed styles and measured sizes, so it holds against a
// production build as well as the dev server. Every API call is answered by
// `page.route`; no API server runs.

import { test, expect, type Page, type Route } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const address = '0x1111111111111111111111111111111111111111';
const space = `tinycloud:pkh:eip155:1:${address}:secrets`;
const KV_GET = 'tinycloud.kv/get';

const request = [{ service: 'tinycloud.kv', space, path: 'vault/secrets/TC_FWD_TOKEN', actions: [KV_GET] }];

const siwe = [
  'cli.tinycloud.xyz wants you to sign in with your Ethereum account:',
  address,
  '',
  'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  'Version: 1',
  'Chain ID: 1',
  'Nonce: abcdef123456',
  'Issued At: 2026-10-03T00:00:00.000Z',
  'Expiration Time: 2026-10-03T01:00:00.000Z',
  'Resources:',
  `- ${makeRecapResource({ [`${space}/kv/vault/secrets/TC_FWD_TOKEN`]: { [KV_GET]: [{}] } })}`,
].join('\n');

const key = `tinycloud.kv\0${space}\0vault/secrets/TC_FWD_TOKEN`;
const preparedResponse = {
  prepared: { siwe, spaceId: space, jwk: {} },
  spaceId: space,
  ownerDid: `did:pkh:eip155:1:${address}`,
  address,
  chainId: 1,
  host: 'https://node.tinycloud.xyz',
  permissions: [{
    key,
    service: 'kv',
    path: 'vault/secrets/TC_FWD_TOKEN',
    label: 'kv',
    resourcePath: 'kv/vault/secrets/TC_FWD_TOKEN',
    actions: [{ key: `${key}\0${KV_GET}`, action: 'get', ability: KV_GET, required: false }],
  }],
  selectedActionKeys: [`${key}\0${KV_GET}`],
  edited: false,
  authorizationContext: { token: 'context-token', expiresAt: Date.now() + 600_000, baselineAbilitiesDigest: 'digest' },
};

const json = (route: Route, status: number, body: unknown) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

async function openDelegate(page: Page) {
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') {
      return json(route, 200, {
        session: { id: 'session_1', userId: 'user_1', expiresAt: new Date(Date.now() + 3_600_000).toISOString() },
        user: { id: 'user_1', email: 'alice@example.test', name: 'Alice' },
      });
    }
    if (path === '/api/keys') {
      return json(route, 200, {
        keys: [{ id: 'key_1', address, publicKey: '0x', keyIndex: 0, label: 'Main', keyType: 'MANAGED', createdAt: new Date().toISOString() }],
      });
    }
    if (path === '/api/delegate/prepare') return json(route, 200, preparedResponse);
    return json(route, 404, { error: `unmocked ${path}` });
  });
  const jwk = encodeBase64UrlJson({ kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
  await page.goto(`/delegate?did=did:key:z6Mk&jwk=${jwk}&permissions=${encodeBase64UrlJson({ permissions: request })}`);
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
}

for (const width of [390, 1280]) {
  test(`the exact bytes block shows one line per line feed and scrolls sideways at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await openDelegate(page);
    await page.locator('details.advanced-details > summary').click();
    const block = page.locator('pre.raw-bytes');
    await expect(block).toBeVisible();
    expect(await block.textContent()).toBe(siwe);
    const shape = await block.evaluate((element) => {
      const style = getComputedStyle(element);
      const padding = parseFloat(style.paddingTop) + parseFloat(style.paddingBottom);
      return {
        whiteSpace: style.whiteSpace,
        overflowX: style.overflowX,
        lines: (element.scrollHeight - padding) / parseFloat(style.lineHeight),
        scrolls: element.scrollWidth > element.clientWidth,
        pageOverflow: document.documentElement.scrollWidth > window.innerWidth,
      };
    });
    expect(shape).toEqual({ whiteSpace: 'pre', overflowX: 'auto', lines: siwe.split('\n').length, scrolls: true, pageOverflow: false });
  });
}
