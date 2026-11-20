// The /delegate approval names the assistant that asked, taken from the
// registered return address in the link, and its closing line says where to go
// back to. Every API call is answered by `page.route`; no API server runs.

import { test, expect, type Page, type Route } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const CAPS_READ = 'tinycloud.capabilities/read';
const KV_GET = 'tinycloud.kv/get';
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

const siwe = [
  'mcp.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
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
const prepared = {
  prepared: { siwe, spaceId: space, jwk: {} }, spaceId: space, ownerDid: `did:pkh:eip155:1:${address}`, address, chainId: 1,
  host: 'https://node.tinycloud.xyz', permissions, selectedActionKeys: permissions.flatMap((p) => p.actions.map((a) => a.key)), edited: false,
  authorizationContext: { token: 't', expiresAt: Date.now() + 600_000, baselineAbilitiesDigest: 'd' },
};
const oneKey = [{ id: 'key_0', address, publicKey: '0x', keyIndex: 0, label: 'Key 0', keyType: 'MANAGED', isPrimary: true, createdAt: new Date().toISOString() }];

async function mock(page: Page) {
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/auth/get-session') return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'sam@example.test', name: 'Sam' } });
    if (url.pathname === '/api/keys') return json(route, 200, { keys: oneKey });
    if (url.pathname === '/api/delegate/prepare') return json(route, 200, prepared);
    if (url.pathname === '/api/delegate') return json(route, 200, { delegationHeader: { Authorization: 'Bearer x' }, delegationCid: 'bafy', spaceId: space, hostActivated: true, permissions: [] });
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });
}
/** The callback endpoint answers the page's POST (and its CORS preflight). */
async function mockCallback(page: Page, endpoint: string) {
  await page.route(`${endpoint}**`, (route) => route.fulfill({
    status: 200, contentType: 'application/json',
    headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type' }, body: '{"success":true}',
  }));
}

const jwk = encodeBase64UrlJson({ kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
const link = (callback: string) => `/delegate?did=did:key:z6Mk&jwk=${jwk}&callback=${encodeURIComponent(callback)}`;

const registered: Array<[string, string, string, string]> = [
  ['Claude', 'https://mcp.tinycloud.xyz/claude/connect/callback', 'Claude via TinyCloud', 'Claude'],
  ['Grok', 'https://mcp.tinycloud.xyz/grok/connect/callback', 'Grok via TinyCloud', 'Grok'],
  ['Muse', 'https://mcp.tinycloud.xyz/muse/connect/callback', 'Muse via TinyCloud', 'Muse'],
  ['ChatGPT', 'https://mcp.tinycloud.xyz/chatgpt/connect/callback', 'ChatGPT via TinyCloud', 'ChatGPT'],
  ['Gemini', 'https://mcp.tinycloud.xyz/gemini/connect/callback', 'Gemini via TinyCloud', 'Gemini'],
  ['Perplexity', 'https://mcp.tinycloud.xyz/perplexity/connect/callback', 'Perplexity via TinyCloud', 'Perplexity'],
  ['Mistral', 'https://mcp.tinycloud.xyz/mistral/connect/callback', 'Mistral via TinyCloud', 'Mistral'],
  ['Copilot', 'https://mcp.tinycloud.xyz/copilot/connect/callback', 'Copilot via TinyCloud', 'Copilot'],
  ['the bare TinyCloud MCP', 'https://mcp.tinycloud.xyz/connect/callback', 'TinyCloud MCP', 'your MCP client'],
];

test.describe('approval names the requesting assistant', () => {
  for (const [label, endpoint, displayName, returnTo] of registered) {
    test(`${label}: "Requested by" and the closing line use its name`, async ({ page }) => {
      await mock(page);
      await mockCallback(page, endpoint);
      await page.goto(link(`${endpoint}?state=t.n.sig`));
      const dialog = page.getByRole('dialog');
      await expect(dialog).toContainText(`Requested by ${displayName}`);
      await expect(dialog).not.toContainText('TinyCloud CLI');
      await page.getByRole('button', { name: 'Approve', exact: true }).click();
      await expect(page.getByText(`You can close this window and return to ${returnTo}.`)).toBeVisible();
      await expect(page.getByText('return to the CLI')).toHaveCount(0);
    });
  }

  test('an unregistered callback is refused and no assistant is named', async ({ page }) => {
    await mock(page);
    await page.goto(link('https://mcp.tinycloud.xyz/unlisted/connect/callback?state=x'));
    await expect(page.getByRole('heading', { name: 'This link would send your approval to a site OpenKey doesn’t know' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(0);
    await expect(page.getByText(/Requested by (Claude|Grok|Muse|ChatGPT|Gemini|Perplexity|Mistral|Copilot|TinyCloud MCP)/)).toHaveCount(0);
  });
});
