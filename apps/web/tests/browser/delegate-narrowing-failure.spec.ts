// TC-598 review: the real `/delegate` page must not approve a prepared
// authorization that differs from the visible selection. The owner unticks
// the raw encryption decrypt grant, the narrowing `/api/delegate/prepare`
// fails, and Approve must not submit the earlier SIWE (which still grants
// decrypt). Every API call is answered by `page.route`; no API server runs.

import { test, expect, type Page, type Route } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const address = '0x1111111111111111111111111111111111111111';
const space = `tinycloud:pkh:eip155:1:${address}:secrets`;
const network = `urn:tinycloud:encryption:did:pkh:eip155:1:${address}:default`;
const KV_GET = 'tinycloud.kv/get';
const CAPS_READ = 'tinycloud.capabilities/read';
const DECRYPT = 'tinycloud.encryption/decrypt';

const request = [
  { service: 'tinycloud.kv', space, path: 'vault/secrets/TC_FWD_TOKEN', actions: [KV_GET] },
  { service: 'tinycloud.encryption', space: 'encryption', path: network, actions: [DECRYPT] },
  { service: 'tinycloud.capabilities', space, path: '', actions: [CAPS_READ] },
];

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
  `- ${makeRecapResource({
    [`${space}/capabilities`]: { [CAPS_READ]: [{}] },
    [`${space}/kv/vault/secrets/TC_FWD_TOKEN`]: { [KV_GET]: [{}] },
    [network]: { [DECRYPT]: [{}] },
  })}`,
].join('\n');

// The `/api/delegate/prepare` response for the full request.
const option = (service: string, short: string, keySpace: string, path: string, ability: string, required: boolean) => {
  const key = `${service}\0${keySpace}\0${path}`;
  return {
    key,
    service: short,
    path,
    label: short,
    resourcePath: path ? `${short}/${path}` : short,
    actions: [{ key: `${key}\0${ability}`, action: ability.split('/')[1], ability, required }],
  };
};
const permissionOptions = [
  option('tinycloud.capabilities', 'capabilities', space, '', CAPS_READ, true),
  option('tinycloud.kv', 'kv', space, 'vault/secrets/TC_FWD_TOKEN', KV_GET, false),
  option('tinycloud.encryption', 'encryption', 'encryption', network, DECRYPT, false),
];
const fullSelection = permissionOptions.flatMap((permission) => permission.actions.map((action) => action.key));
const preparedResponse = {
  prepared: { siwe, spaceId: space, jwk: {} },
  spaceId: space,
  ownerDid: `did:pkh:eip155:1:${address}`,
  address,
  chainId: 1,
  host: 'https://node.tinycloud.xyz',
  permissions: permissionOptions,
  selectedActionKeys: fullSelection,
  edited: false,
  authorizationContext: { token: 'context-token', expiresAt: Date.now() + 600_000, baselineAbilitiesDigest: 'digest' },
};

const json = (route: Route, status: number, body: unknown) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

async function openConsent(page: Page, approvals: unknown[]) {
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/auth/get-session') {
      return json(route, 200, {
        session: { id: 'session_1', userId: 'user_1', expiresAt: new Date(Date.now() + 3_600_000).toISOString() },
        user: { id: 'user_1', email: 'alice@example.test', name: 'Alice' },
      });
    }
    if (url.pathname === '/api/keys') {
      return json(route, 200, {
        keys: [{ id: 'key_1', address, publicKey: '0x', keyIndex: 0, label: 'Main', keyType: 'MANAGED', createdAt: new Date().toISOString() }],
      });
    }
    if (url.pathname === '/api/delegate/prepare') {
      const body = route.request().postDataJSON() as { actionKeys?: unknown };
      // The first preparation succeeds; any narrowing fails.
      return body.actionKeys === undefined
        ? json(route, 200, preparedResponse)
        : json(route, 503, { error: 'Service unavailable' });
    }
    if (url.pathname === '/api/delegate') {
      approvals.push(route.request().postDataJSON());
      return json(route, 500, { error: 'approval should not be sent' });
    }
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });

  const jwk = encodeBase64UrlJson({ kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
  const permissions = encodeBase64UrlJson({ permissions: request });
  await page.goto(`/delegate?did=did:key:z6Mk&jwk=${jwk}&permissions=${permissions}`);
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
}

test('a failed narrowing keeps Approve disabled and sends no approval', async ({ page }) => {
  const approvals: unknown[] = [];
  await openConsent(page, approvals);

  const details = page.locator('details.advanced-details');
  await details.locator(':scope > summary').click();
  await details.getByRole('button', { name: 'Edit' }).click();
  const decrypt = details.getByRole('checkbox', { name: 'decrypt' });
  await decrypt.uncheck();

  await expect(page.getByText('Service unavailable').first()).toBeVisible();
  const approve = page.getByRole('button', { name: 'Approve', exact: true });
  await expect(approve).toBeDisabled();
  await expect(page.getByText('have not been prepared for signing')).toBeVisible();
  await approve.click({ force: true });
  expect(approvals).toEqual([]);

  // Re-selecting decrypt restores the prepared selection: Approve works again.
  await decrypt.check();
  await expect(approve).toBeEnabled();
});
