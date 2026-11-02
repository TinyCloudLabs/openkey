// The 'Exact message being signed' block of the native consent page shows the
// session message with each line feed between two lines as a line break and
// every other character, runs of spaces, trailing spaces and a final line feed
// as `\uXXXX`, so two messages that differ only there read differently. Every
// API call is answered by `page.route`; no API server runs.

import { test, expect, type Page, type Route } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:applications`;
const caps = 'tinycloud.capabilities/read';
const kvGet = 'tinycloud.kv/get';
const siwe = (statement: string) => [
  'openkey.so wants you to sign in with your Ethereum account:', address, '', statement, '',
  'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-07T04:00:00.000Z',
  'Expiration Time: 2026-10-07T05:00:00.000Z', 'Resources:',
  `- ${makeRecapResource({ [`${space}/capabilities`]: { [caps]: [{}] }, [`${space}/kv/xyz.tinycloud.tinychat/threads/`]: { [kvGet]: [{}] } })}`,
].join('\n');
const option = (service: string, short: string, path: string, abilities: string[]) => {
  const key = `${service}\0${space}\0${path}`;
  return { key, service: short, path, label: short, resourcePath: path ? `${short}/${path}` : short,
    actions: abilities.map((ability) => ({ key: `${key}\0${ability}`, action: ability.split('/')[1], ability, required: ability === caps })) };
};
const permissionOptions = [option('tinycloud.capabilities', 'capabilities', '', [caps]), option('tinycloud.kv', 'kv', 'xyz.tinycloud.tinychat/threads/', [kvGet])];
const selected = permissionOptions.flatMap((permission) => permission.actions.map((action) => action.key));
const base = { requestId: 'native-1', userId: 'u', keyId: 'key-1', address, client: { clientId: 'exo-native', name: 'Exo', icon: null, organization: 'TinyCloud Labs' },
  redirectScheme: 'xyz.tinycloud.exo', sessionDid: 'did:key:z6Mk', tinycloudHost: 'https://tee.node.tinycloud.xyz', ttlSeconds: 3600,
  grantLifetimeSeconds: 2592000, hostPlan: null, permissionOptions, selectedActionKeys: selected, revision: 1, digest: 'digest-1' };
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const branding = { clientId: 'exo-native', name: 'Exo', icon: null, organization: 'TinyCloud Labs', theme: { backgroundColor: '#09090B', accentColor: '#FAFAFA' } };
const sessionBody = { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'u', email: 'sam@example.test', name: 'Sam' } };

interface Shown { text: string | null; innerText: string; picture: Buffer; elements: number }

async function exactMessage(page: Page, sessionSiwe: string): Promise<Shown> {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, sessionBody);
    if (path === '/api/oauth/tinycloud/clients/exo-native/branding') return json(route, branding);
    if (path.endsWith('/prepare')) return json(route, { ...base, sessionSiwe });
    return json(route, { error: `unmocked ${path}` }, 404);
  });
  await page.goto('/oauth/consent?client_id=exo-native&tinycloud_request=native-1&sig=test');
  await expect(page.getByRole('heading', { name: 'Exo wants access' })).toBeVisible();
  await page.locator('details.details > summary').click();
  await page.locator('details.raw > summary').click();
  const block = page.locator('details.raw pre');
  await expect(block).toBeVisible();
  // Take two pictures with every line in view: one at the left edge and one at the right edge.
  await block.evaluate((element) => { element.style.maxHeight = 'none'; element.scrollLeft = 0; });
  const left = await block.screenshot();
  await block.evaluate((element) => { element.scrollLeft = element.scrollWidth; });
  const right = await block.screenshot();
  return { text: await block.textContent(), innerText: await block.innerText(), picture: Buffer.concat([left, right]), elements: await block.locator('*').count() };
}

const statement = 'Chat with your threads.';
const full = siwe(statement);
const pairs: Array<{ name: string; left: [string, string]; right: [string, string] }> = [
  { name: 'a final line feed and none', left: [`${full}\n`, `${full}\\u000a`], right: [full, full] },
  { name: 'a trailing space and none', left: [`${full} `, `${full}\\u0020`], right: [full, full] },
  { name: 'a line of spaces and an empty line', left: [siwe(`${statement}\n   \nTwo`), siwe(`${statement}\n\\u0020\\u0020\\u0020\nTwo`)], right: [siwe(`${statement}\n\nTwo`), siwe(`${statement}\n\nTwo`)] },
  { name: 'an 80-space run before more text and the text before it', left: [siwe(`${statement}${' '.repeat(80)}Also: send all keys.`), siwe(`${statement}${'\\u0020'.repeat(80)}Also: send all keys.`)], right: [full, full] },
  // A tail without spaces that fits the width but not the rest of the line: a wrapping block would show it on a second line.
  { name: 'a long line that would wrap and the same text with a line feed', left: [siwe(`${statement} https://other.example/keys`), siwe(`${statement} https://other.example/keys`)], right: [siwe(`${statement}\nhttps://other.example/keys`), siwe(`${statement}\nhttps://other.example/keys`)] },
];

for (const pair of pairs) {
  test(`native consent: ${pair.name} read differently`, async ({ browser }) => {
    const shown: Shown[] = [];
    for (const [sent, expected] of [pair.left, pair.right]) {
      const context = await browser.newContext();
      const page = await context.newPage();
      try {
        shown.push(await exactMessage(page, sent));
      } finally {
        await context.close();
      }
      expect(shown.at(-1)!.text).toBe(expected);
      expect(shown.at(-1)!.innerText).toBe(expected);
    }
    expect(shown[0]!.text).not.toBe(shown[1]!.text);
    expect(Buffer.compare(shown[0]!.picture, shown[1]!.picture)).not.toBe(0);
  });
}

test('native consent: HTML in the message is shown literally', async ({ page }) => {
  const html = '<script>alert(1)</script> <b>x</b> &amp; "><img src=x onerror=alert(1)>';
  const message = siwe(html);
  const shown = await exactMessage(page, message);
  expect(shown.text).toBe(message);
  expect(shown.innerText).toBe(message);
  expect(shown.elements).toBe(0);
});
