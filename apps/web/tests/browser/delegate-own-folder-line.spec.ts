// TC-3443: a request that names no permissions gets only an app folder, and
// the approval screen says so. Real /delegate page, API fixtures only.
import { test, expect, type Page, type Route } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const OWN_LINE = "This app didn't say what it needs, so it only gets its own folder.";
const SHARED_LINE = "This app didn't say what it needs or where it's from, so it only gets a folder that other apps like it can also use.";
const address = '0x1111111111111111111111111111111111111111';
const applications = `tinycloud:pkh:eip155:1:${address}:applications`;
const grantsFor = (folder: string) => [
  { service: 'kv', path: folder, actions: ['get', 'put', 'del', 'list', 'metadata'] },
  { service: 'sql', path: folder, actions: ['read', 'write'] },
  { service: 'capabilities', path: '', actions: ['read'] },
];

/** What /prepare returns for a request from `domain` whose folder is `applications/<folder>`. */
function prepareResponse(domain: string, folder: string, flags: { ownFolderOnly: boolean; ownFolderShared: boolean }) {
  const permissions = grantsFor(folder).map((grant) => {
    const key = `tinycloud.${grant.service}\0${applications}\0${grant.path}`;
    return {
      key, service: grant.service, path: grant.path, label: grant.service,
      resourcePath: grant.path ? `${grant.service}/${grant.path}` : grant.service,
      actions: grant.actions.map((action) => ({
        key: `${key}\0tinycloud.${grant.service}/${action}`, ability: `tinycloud.${grant.service}/${action}`, action,
        required: grant.service === 'capabilities',
      })),
    };
  });
  const issuedAt = new Date();
  const siwe = [
    `${domain} wants you to sign in with your Ethereum account:`, address, '',
    'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456',
    `Issued At: ${issuedAt.toISOString()}`, `Expiration Time: ${new Date(issuedAt.getTime() + 7 * 86_400_000).toISOString()}`,
    'Resources:',
    `- ${makeRecapResource(Object.fromEntries(permissions.map((permission) => [
      `${applications}/${permission.resourcePath}`,
      Object.fromEntries(permission.actions.map((action) => [action.ability, [{}]])),
    ])))}`,
  ].join('\n');
  return {
    prepared: { siwe, spaceId: applications, jwk: {} }, spaceId: applications, ownerDid: `did:pkh:eip155:1:${address}`, address, chainId: 1,
    host: 'https://node.tinycloud.xyz', permissions,
    selectedActionKeys: permissions.flatMap((permission) => permission.actions.map((action) => action.key)),
    edited: false, ...flags,
    authorizationContext: { token: 'context-1', expiresAt: Date.now() + 600000, baselineAbilitiesDigest: 'fixture-digest' },
  };
}

const json = (route: Route, body: unknown) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });
const jwk = encodeBase64UrlJson({ kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });

async function openApproval(page: Page, query: string, prepared: unknown) {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, { session: { id: 'tc3443-session', userId: 'tc3443', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'tc3443', email: 'tc3443@example.test', name: 'QA Fixture' } });
    if (path === '/api/keys') return json(route, { keys: [{ id: 'tc3443-key', address, publicKey: '0x', keyIndex: 0, label: 'QA Fixture', keyType: 'MANAGED', isPrimary: true, createdAt: '2026-11-21T00:00:00.000Z' }] });
    if (path === '/api/delegate/prepare') return json(route, prepared);
    return route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: `Unmocked API: ${path}` }) });
  });
  await page.goto(`/delegate?did=did:key:z6Mk&jwk=${jwk}${query}`);
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
  return errors;
}

test.use({ viewport: { width: 390, height: 844 } });

test('a request from a readable origin that names no permissions shows the own-folder line', async ({ page }) => {
  const errors = await openApproval(page, '', prepareResponse('notes.example.com', 'com.example.notes/', { ownFolderOnly: true, ownFolderShared: false }));
  await expect(page.getByRole('note').filter({ hasText: OWN_LINE })).toHaveText(OWN_LINE);
  await expect(page.getByText(SHARED_LINE)).toHaveCount(0);
  if (process.env.TC3443_SCREEN_DIR) await page.screenshot({ path: `${process.env.TC3443_SCREEN_DIR}/own-folder-390.png`, fullPage: true });
  expect(errors).toEqual([]);
});

test('a request with no origin that names no permissions shows the shared-folder line instead', async ({ page }) => {
  const errors = await openApproval(page, '', prepareResponse('cli.tinycloud.xyz', 'xyz.tinycloud.cli/', { ownFolderOnly: true, ownFolderShared: true }));
  await expect(page.getByRole('note').filter({ hasText: SHARED_LINE })).toHaveText(SHARED_LINE);
  await expect(page.getByText(OWN_LINE)).toHaveCount(0);
  if (process.env.TC3443_SCREEN_DIR) await page.screenshot({ path: `${process.env.TC3443_SCREEN_DIR}/shared-folder-390.png`, fullPage: true });
  expect(errors).toEqual([]);
});

test('a request that names its permissions shows neither line', async ({ page }) => {
  const request = grantsFor('com.example.notes/').map((grant) => ({
    service: `tinycloud.${grant.service}`, space: 'applications', path: grant.path, actions: grant.actions.map((action) => `tinycloud.${grant.service}/${action}`),
  }));
  const errors = await openApproval(
    page,
    `&permissions=${encodeBase64UrlJson({ permissions: request })}`,
    prepareResponse('notes.example.com', 'com.example.notes/', { ownFolderOnly: false, ownFolderShared: false }),
  );
  await expect(page.getByText(OWN_LINE)).toHaveCount(0);
  await expect(page.getByText(SHARED_LINE)).toHaveCount(0);
  expect(errors).toEqual([]);
});
