import { test, expect, type Page, type Route } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const siwe = [
  'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
  'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-03T00:00:00.000Z', 'Expiration Time: 2026-11-03T01:00:00.000Z',
  'Resources:', `- ${makeRecapResource({ [`${space}/capabilities`]: { 'tinycloud.capabilities/read': [{}] } })}`,
].join('\n');
const permission = {
  key: `tinycloud.capabilities\0${space}\0`,
  label: 'capabilities',
  resourcePath: 'capabilities',
  actions: [{ key: `tinycloud.capabilities\0${space}\0\0tinycloud.capabilities/read`, action: 'read', ability: 'tinycloud.capabilities/read', required: true }],
};
const prepared = {
  prepared: { siwe, spaceId: space, jwk: {} },
  spaceId: space,
  ownerDid: `did:pkh:eip155:1:${address}`,
  address,
  chainId: 1,
  host: 'https://node.tinycloud.xyz',
  permissions: [permission],
  selectedActionKeys: [permission.actions[0].key],
  edited: false,
  authorizationContext: { token: 'prepared-token', expiresAt: Date.now() + 600_000, baselineAbilitiesDigest: 'digest' },
};
const delegation = {
  delegationHeader: { Authorization: 'Bearer signed' },
  delegationCid: 'bafy-signed',
  spaceId: space,
  ownerDid: `did:pkh:eip155:1:${address}`,
  verificationMethod: 'did:key:z6Mk',
  jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
  address,
  chainId: 1,
  hostActivated: true,
  expirationTime: '2026-11-03T01:00:00.000Z',
  siwe,
  signedMessage: siwe,
  signature: '0xsignature',
};
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const jwk = encodeBase64UrlJson(delegation.jwk);

async function mockApproval(page: Page) {
  const issued: Array<Record<string, unknown>> = [];
  let codeNumber = 0;
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/auth/get-session') return json(route, 200, { session: { id: 'session-1', userId: 'user-1', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'user-1', email: 'sam@example.test', name: 'Sam' } });
    if (url.pathname === '/api/keys') return json(route, 200, { keys: [{ id: 'key-1', address, publicKey: '0x', keyIndex: 0, label: null, keyType: 'MANAGED', createdAt: new Date().toISOString() }] });
    if (url.pathname === '/api/delegate/prepare') return json(route, 200, prepared);
    if (url.pathname === '/api/delegate') return json(route, 200, delegation);
    if (url.pathname === '/api/delegation-codes' || url.pathname === '/api/delegation-codes/refresh') {
      issued.push(route.request().postDataJSON() as Record<string, unknown>);
      codeNumber += 1;
      return json(route, 201, {
        code: codeNumber === 1 ? 'ABCD-EF23' : 'WXYZ-3456',
        expiresAt: new Date(Date.now() + 300_000).toISOString(),
        ...(codeNumber === 1 ? { refreshGrant: 'session-bound-refresh-grant' } : {}),
      });
    }
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async (text: string) => { document.documentElement.dataset.copiedText = text; } } });
  });
  return issued;
}

test('refreshes a code for the same approved delegation and copies both values exactly', async ({ page }) => {
  const issued = await mockApproval(page);
  await page.goto(`/delegate?did=did:key:z6Mk&jwk=${jwk}`);
  await page.getByRole('button', { name: 'Approve', exact: true }).click();

  await expect(page.getByRole('heading', { name: 'Delegation Created' })).toBeVisible();
  const beforeShot = process.env.TC2175_SCREENSHOT_DIR;
  if (beforeShot) await page.screenshot({ path: `${beforeShot}/before.png`, fullPage: true });

  const code = page.getByRole('button', { name: 'Copy code ABCD-EF23' });
  await expect(code).toBeVisible();

  await code.click();
  await expect(page.getByText('Copied', { exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.dataset.copiedText)).toBe('ABCD-EF23');

  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Copy code WXYZ-3456' })).toBeVisible();
  await expect(page.getByText('Copied', { exact: true })).toHaveCount(0);
  expect(issued).toEqual([
    { delegation },
    { delegation, refreshGrant: 'session-bound-refresh-grant' },
  ]);
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Sign in/ })).toHaveCount(0);

  await page.getByText('Use full delegation code instead').click();
  const fullCode = page.getByRole('textbox', { name: 'Full delegation code' });
  await expect(fullCode).toBeVisible();
  const exactPaste = await fullCode.inputValue();
  await page.getByRole('button', { name: 'Copy full delegation code' }).click();
  expect(await page.evaluate(() => document.documentElement.dataset.copiedText)).toBe(exactPaste);
  await expect(page.getByText('Copied', { exact: true }).last()).toBeVisible();

  if (beforeShot) await page.screenshot({ path: `${beforeShot}/after.png`, fullPage: true });
});
