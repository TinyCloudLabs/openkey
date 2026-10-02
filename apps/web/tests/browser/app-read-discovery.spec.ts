import { test, expect, type Page } from '@playwright/test';
import { EXPLORER_PERMISSION_POPUP_REQUEST } from '../../../../packages/capability-review/test/fixtures/index';

if (process.env.OPENKEY_TEST_BROWSER_CHANNEL) test.use({ channel: process.env.OPENKEY_TEST_BROWSER_CHANNEL });

const ownerDid = 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111';
const permissions = [{ service: 'tinycloud.sql', space: `tinycloud:${ownerDid.slice(4)}:health`, path: 'fitness', actions: ['read'] }];
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'synthetic-public-key' };
const app = (appId: string, name: string, scope = permissions) => ({ appId, name, description: `${name} records`, manifests: [], manifestHash: `hash-${appId}`, selectionDigest: `digest-${appId}`, permissions: scope });

async function setup(page: Page, options: { external?: boolean; fixed?: boolean; single?: boolean; owner?: string; parsed?: boolean; missingDiscovery?: boolean; incompatibleApi?: boolean; discoveryProtocolVersion?: string; unicode?: boolean; incomplete?: boolean } = {}) {
  const calls: Array<{ path: string; body: any }> = [];
  const scope = options.unicode ? permissions.map(entry => ({ ...entry, path: '測定/体重' })) : permissions;
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return route.fulfill({ json: {
      session: { id: 'session', userId: 'user', token: 'synthetic-session', expiresAt: '2099-01-01T00:00:00Z' },
      user: { id: 'user', name: 'Test user', email: 'test@example.invalid', emailVerified: true, createdAt: '2026-01-01T00:00:00Z', updatedAt: '2026-01-01T00:00:00Z' },
    } });
    if (path === '/api/keys') return route.fulfill({ json: { keys: [{ id: 'key', address: ownerDid.split(':').at(-1), publicKey: 'public', keyIndex: 0, keyType: options.external ? 'EXTERNAL' : 'MANAGED', label: 'Test account', createdAt: '2026-01-01T00:00:00Z' }] } });
    if (path === '/api/delegate/app-read-capabilities') return route.fulfill(options.incompatibleApi ? { status: 404, body: 'Not found' } : { json: { schemaVersion: 1, protocolVersion: 1, implementationVersion: '1', discovery: 'app-read', scope: 'registry-and-selected-app', transport: 'paste' } });
    const body = route.request().postDataJSON();
    calls.push({ path, body });
    if (path === '/api/delegate/app-read-discovery' && options.missingDiscovery) return route.fulfill({ status: 404, body: 'Not found' });
    if (path === '/api/delegate/app-read-discovery') return route.fulfill({ json: {
      schemaVersion: 1, protocolVersion: 1, discoveryToken: 'discovery-context', ownerDid, host: 'https://node.tinycloud.xyz', clientKeyDigest: 'jwk-digest', expiresAt: '2099-01-01T00:00:00Z', complete: !options.incomplete, issues: options.incomplete ? [{ key: 'applications/legacy', code: 'LEGACY_RECORD', category: 'legacy', field: 'record' }] : [],
      applications: options.single ? [app('health', 'Health', scope)] : [app('health', 'Health', scope), app('notes', 'Notes', scope)],
    } });
    if (path === '/api/delegate/prepare') return route.fulfill({ json: {
      prepared: { siwe: options.parsed ? EXPLORER_PERMISSION_POPUP_REQUEST : 'Synthetic review bytes for selected read scope' }, authorizationContext: { token: 'prepared-context' },
      selectedActionKeys: ['fitness-read'], permissions: [{ key: 'fitness', label: 'Fitness', resourcePath: scope[0].path, actions: [{ key: 'fitness-read', action: 'read', ability: 'tinycloud.sql/read', required: true }] }],
      appReadSelection: options.fixed ? undefined : { schemaVersion: 1, appId: body.appId, manifestHash: `hash-${body.appId}`, selectionDigest: body.selectionDigest, ownerDid, host: 'https://node.tinycloud.xyz', clientKeyDigest: 'jwk-digest' },
    } });
    if (path === '/api/delegate') return route.fulfill({ json: { hostActivated: true, delegationHeader: 'synthetic-proof-not-a-credential', appReadSelection: { appId: body.appId, permissions: scope } } });
    return route.fulfill({ status: 404, json: { error: 'Unexpected test request' } });
  });
  const query = new URLSearchParams({ jwk: Buffer.from(JSON.stringify(jwk)).toString('base64url'), reason: options.unicode ? 'Qual foi a minha última pesagem? ⚖️' : 'When was my last recorded weight-in?' });
  if (options.owner) query.set('owner', options.owner);
  if (!options.fixed) {
    query.set('discovery', 'app-read');
    query.set('discoveryProtocolVersion', options.discoveryProtocolVersion ?? '1');
  }
  else query.set('permissions', Buffer.from(JSON.stringify({ permissions })).toString('base64url'));
  await page.goto(`/delegate?${query}`);
  if (!options.fixed && !options.owner) await page.getByRole('button', { name: /Test account/ }).click();
  return calls;
}

test('selects an app before one approval and one paste result in the same browser visit', async ({ page }) => {
  const calls = await setup(page);
  await expect(page.getByRole('heading', { name: 'Choose an application' })).toBeVisible();
  expect(calls.map(call => call.path)).toEqual(['/api/delegate/app-read-discovery']);
  await page.getByRole('button', { name: /Health records/ }).click();
  await expect(page.getByRole('heading', { name: 'Authorize CLI Access' })).toBeVisible();
  expect(calls.filter(call => call.path === '/api/delegate')).toHaveLength(0);
  expect(calls.find(call => call.path === '/api/delegate/prepare')?.body).toMatchObject({ discoveryToken: 'discovery-context', appId: 'health', selectionDigest: 'digest-health' });
  expect(calls.find(call => call.path === '/api/delegate/prepare')?.body.permissions).toBeUndefined();
  await page.getByRole('button', { name: 'Approve' }).click();
  await expect(page.getByText('Copy this code and paste it into your agent conversation:')).toBeVisible();
  const approvals = calls.filter(call => call.path === '/api/delegate');
  expect(approvals).toHaveLength(1);
  expect(approvals[0].body).toMatchObject({ discoveryToken: 'discovery-context', appId: 'health', selectionDigest: 'digest-health' });
  expect(approvals[0].body.permissions).toBeUndefined();
});

test('one discovered app goes directly to consent without a second browser approval', async ({ page }) => {
  const calls = await setup(page, { single: true });
  await expect(page.getByRole('heading', { name: 'Authorize CLI Access' })).toBeVisible();
  await expect(page.getByText('SQL read access covers all records in each listed database.')).toBeVisible();
  expect(calls.map(call => call.path)).toEqual(['/api/delegate/app-read-discovery', '/api/delegate/prepare']);
});

test('external keys show the unsupported discovery case without preparing broad defaults', async ({ page }) => {
  const calls = await setup(page, { external: true });
  await expect(page.getByRole('alert')).toContainText('Choose an OpenKey-managed key');
  expect(calls).toEqual([]);
});

test('fixed manifest callers keep their existing prepare path', async ({ page }) => {
  const calls = await setup(page, { fixed: true });
  await expect(page.getByRole('heading', { name: 'Authorize CLI Access' })).toBeVisible();
  expect(calls.map(call => call.path)).toEqual(['/api/delegate/prepare']);
  expect(calls[0].body.permissions).toEqual(permissions);
  expect(calls[0].body.discoveryToken).toBeUndefined();
});


test('discovery preselects the expected owner without allowing an account override', async ({ page }) => {
  const calls = await setup(page, { owner: ownerDid, single: true });
  await expect(page.getByRole('heading', { name: 'Authorize CLI Access' })).toBeVisible();
  expect(calls.map(call => call.path)).toEqual(['/api/delegate/app-read-discovery', '/api/delegate/prepare']);
});

test('a missing expected owner cannot prepare access using another account', async ({ page }) => {
  const calls = await setup(page, { owner: 'did:pkh:eip155:1:0x2222222222222222222222222222222222222222' });
  await expect(page.getByRole('alert')).toContainText('Sign in to the OpenKey account that holds this key');
  await expect(page.getByRole('button', { name: /Test account/ })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Continue with a different wallet anyway' })).toHaveCount(0);
  expect(calls).toEqual([]);
});


test('discovered application scope cannot be narrowed during review', async ({ page }) => {
  const calls = await setup(page, { single: true, parsed: true });
  await expect(page.getByRole('heading', { name: 'Authorize CLI Access' })).toBeVisible();
  await page.getByText('Advanced details', { exact: false }).click();
  await page.getByRole('button', { name: 'Edit', exact: true }).click();
  await expect(page.getByRole('checkbox')).toHaveCount(0);
  expect(calls.filter(call => call.path === '/api/delegate/prepare')).toHaveLength(1);
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Choose an application' })).toBeVisible();
});


test('a missing discovery API never prepares default access', async ({ page }) => {
  const calls = await setup(page, { missingDiscovery: true });
  await expect(page.getByRole('alert')).toContainText('Your applications could not be loaded. No access has been approved.');
  expect(calls.map(call => call.path)).toEqual(['/api/delegate/app-read-discovery']);
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(0);
});

test('a new frontend paired with an old API fails before discovery and approval', async ({ page }) => {
  const calls = await setup(page, { incompatibleApi: true });
  await expect(page.getByRole('alert')).toContainText('Update the OpenKey web and API deployments together');
  expect(calls).toEqual([]);
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(0);
});

test('an incompatible discovery protocol cannot prepare or sign', async ({ page }) => {
  const calls = await setup(page, { discoveryProtocolVersion: '2' });
  await expect(page.getByRole('alert')).toContainText('This application-read protocol is incompatible');
  expect(calls).toEqual([]);
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(0);
});


test('one approval produces a UTF-8 paste code for Unicode task and resource paths', async ({ page }) => {
  const calls = await setup(page, { single: true, unicode: true });
  // TC-539 removes invisible variation selectors from displayed consent text.
  await expect(page.getByText('Qual foi a minha última pesagem? ⚖').first()).toBeVisible();
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.getByText('Copy this code and paste it into your agent conversation:')).toBeVisible();
  const encoded = await page.locator('textarea').inputValue();
  const decoded = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
  expect(decoded.appReadSelection.permissions[0].path).toBe('測定/体重');
  expect(calls.filter(call => call.path === '/api/delegate')).toHaveLength(1);
});


test('single-app consent keeps partial registry discovery visible', async ({ page }) => {
  await setup(page, { single: true, incomplete: true });
  await expect(page.getByRole('heading', { name: 'Authorize CLI Access' })).toBeVisible();
  await expect(page.getByText('Some registrations are unavailable or lack supported read access. This approval covers the selected application.')).toBeVisible();
});
