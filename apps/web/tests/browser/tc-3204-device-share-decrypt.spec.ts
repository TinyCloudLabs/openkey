// TC-3204: a device request may ask to decrypt only exact shared files (`share/<id>`), never the whole network.
// The /device preview and the /delegate review show one Sensitive row: "Open this shared file", or "Open {n} shared
// files" for several, never one row per file and never the whole network. Every API call is
// answered by `page.route`; the /delegate review gets the ReCap the API prepares for the request (each
// `share/<id>` resolved to the signer's own `default` network). Set TC3204_SHOTS_DIR to save 390px screenshots.

import { generateKeyPairSync } from 'node:crypto';
import { test, expect, type Page, type Route } from '@playwright/test';
import { makeSpaceId, parseRecapFromSiwe, prepareSession } from '@tinycloud/node-sdk-wasm';
import { getAddress } from 'viem';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';
import { HOST } from './e2e-port';

test.use({ viewport: { width: 390, height: 844 } });

const SHOTS = process.env.TC3204_SHOTS_DIR;
const address = getAddress('0xd559ccd9eb87c530a9a349262669386de93cf412');
const DECRYPT = 'tinycloud.encryption/decrypt';
const allShareIds = ['3f9c1a7e5b2d48a09c6e1f7a2b4d8c03', '9b0e4d2c7a1f48e3b5c6d7e8f9a0b1c2', 'c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2'];
const requestFor = (shareIds: string[]) => shareIds.map((id) => ({ service: 'tinycloud.encryption', space: 'default', path: `share/${id}`, actions: [DECRYPT] }));
const deviceJwk = { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) };
const relayPublicJwk = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' });
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

/** `/api/delegate/prepare`'s answer for the request: the SIWE to sign and its per-action options (delegate-session.ts). */
function preparedResponse(shareIds: string[]) {
  const spaceId = makeSpaceId(address, 1, 'default');
  const rawAbilities = Object.fromEntries(shareIds.map((id) => [`urn:tinycloud:encryption:did:pkh:eip155:1:${address}:default/share/${id}`, [DECRYPT]]));
  const prepared = prepareSession({
    address, chainId: 1, domain: HOST, issuedAt: new Date().toISOString(),
    expirationTime: new Date(Date.now() + 86_400_000).toISOString(), spaceId, jwk: deviceJwk, abilities: {}, rawAbilities,
  } as never);
  const entries = parseRecapFromSiwe(prepared.siwe) as Array<{ service: string; space: string; path: string; actions: string[] }>;
  const permissions = entries.map((entry) => {
    const key = `tinycloud.${entry.service}\0${entry.space}\0${entry.path}`;
    return {
      key, service: entry.service, path: entry.path, label: entry.service, resourcePath: `${entry.service}/${entry.path}`,
      actions: entry.actions.map((ability) => ({ key: `${key}\0${ability}`, action: ability.slice(ability.indexOf('/') + 1), ability, required: false })),
    };
  });
  return {
    prepared, spaceId, ownerDid: `did:pkh:eip155:1:${address}`, address, chainId: 1, host: 'https://node.tinycloud.xyz',
    permissions, selectedActionKeys: permissions.flatMap((option) => option.actions.map((action) => action.key)), edited: false,
    authorizationContext: { token: 't', expiresAt: Date.now() + 600_000, baselineAbilitiesDigest: 'd' },
  };
}

async function deviceApi(page: Page, shareIds: string[]) {
  const expiresAt = new Date(Date.now() + 86_400_000).toISOString();
  const prepared = preparedResponse(shareIds);
  const requested = requestFor(shareIds);
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/auth/get-session') {
      return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'owner@example.test' } });
    }
    if (url.pathname === '/api/organizations') return json(route, 200, { organizations: [] });
    if (url.pathname === '/api/keys') {
      return json(route, 200, { keys: [{ id: 'key_1', address, publicKey: '0x', keyIndex: 0, label: null, keyType: 'MANAGED', createdAt: new Date().toISOString() }] });
    }
    if (url.pathname === '/api/device-authorizations/lookup') {
      return json(route, 200, {
        id: 'tx_1', userCode: 'ABCDEFGH', sessionDid: 'did:key:z6Mk', publicJwk: deviceJwk, relayPublicJwk,
        permissions: requested, nodeOrigin: 'https://node.tinycloud.xyz', shareOrigin: 'https://share.tinycloud.xyz',
        delegationExpiresAt: expiresAt, transactionExpiresAt: new Date(Date.now() + 600_000).toISOString(), delegationTtlSeconds: 86_400,
      });
    }
    if (url.pathname === '/api/delegate/prepare') return json(route, 200, prepared);
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });
}

for (const [count, row] of [[1, 'Open this shared file'], [3, 'Open 3 shared files']] as const) {
  const shareIds = allShareIds.slice(0, count);

  test(`the device preview shows one row for ${count} shared file(s) and nothing wider`, async ({ page }) => {
    await deviceApi(page, shareIds);
    await page.goto('/device?user_code=ABCD-EFGH');
    const rows = page.getByRole('list', { name: 'Requested access' }).getByRole('listitem');
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toHaveText(new RegExp(`^\\s*${row}\\s*Sensitive\\s*$`));
    if (SHOTS) await page.screenshot({ path: `${SHOTS}/device-${count}.png`, fullPage: true });
  });

  test(`the /delegate review of a device request shows one row for ${count} shared file(s)`, async ({ page }) => {
    await deviceApi(page, shareIds);
    const params = new URLSearchParams({
      did: 'did:key:z6Mk', jwk: encodeBase64UrlJson(deviceJwk), relayJwk: encodeBase64UrlJson(relayPublicJwk),
      host: 'https://node.tinycloud.xyz', permissions: encodeBase64UrlJson({ permissions: requestFor(shareIds) }),
      expiry: '86400s', protocolVersion: '1', deviceTransactionId: 'tx_1', deviceShareOrigin: 'https://share.tinycloud.xyz', deviceUserCode: 'ABCD-EFGH',
    });
    await page.goto(`/delegate?${params}`);
    await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
    const rows = page.locator('.summary-statement');
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText(row);
    await expect(rows.first()).toContainText('Sensitive');
    if (SHOTS) await page.screenshot({ path: `${SHOTS}/delegate-${count}.png`, fullPage: true });
  });
}
