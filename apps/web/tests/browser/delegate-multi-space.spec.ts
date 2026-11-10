// TC-2490: real shared /delegate consent, with API-boundary fixtures only.
// No live account, signing server, or TinyCloud node is contacted.
import { test, expect, type Route } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const address = '0x1111111111111111111111111111111111111111';
const spaceId = (name: string) => `tinycloud:pkh:eip155:1:${address}:${name}`;
const request = [
  { service: 'tinycloud.kv', space: 'account', path: 'spaces/', actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] },
  { service: 'tinycloud.kv', space: 'account', path: 'applications/', actions: ['tinycloud.kv/get', 'tinycloud.kv/list'] },
  ...['xyz.tinycloud.tinychat/home_feed', 'xyz.tinycloud.tinychat/feed/'].map(path => ({ service: 'tinycloud.sql', space: 'applications', path, actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] })),
  { service: 'tinycloud.hooks', space: 'applications', path: 'sql/xyz.tinycloud.tinychat/feed/', actions: ['tinycloud.hooks/subscribe'] },
  ...['account', 'applications'].map(space => ({ service: 'tinycloud.capabilities', space, path: '', actions: ['tinycloud.capabilities/read'] })),
];
const permissions = request.map(entry => {
  const service = entry.service.slice('tinycloud.'.length);
  const key = `${entry.service}\0${spaceId(entry.space)}\0${entry.path}`;
  return { key, service, path: entry.path, label: service, resourcePath: entry.path ? `${service}/${entry.path}` : service,
    actions: entry.actions.map(ability => ({ key: `${key}\0${ability}`, ability, action: ability.split('/')[1], required: service === 'capabilities' })) };
});
const fullKeys = permissions.flatMap(entry => entry.actions.map(action => action.key));
const issuedAt = new Date();
const expirationTime = new Date(issuedAt.getTime() + 86_400_000);
function message(keys: string[]) {
  const att: Record<string, Record<string, object[]>> = {};
  permissions.forEach((permission, index) => {
    const entry = request[index]!;
    const actions = permission.actions.filter(action => keys.includes(action.key));
    if (actions.length) att[`${spaceId(entry.space)}/${permission.resourcePath}`] = Object.fromEntries(actions.map(action => [action.ability, [{}]]));
  });
  return [
    'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
    'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456',
    `Issued At: ${issuedAt.toISOString()}`, `Expiration Time: ${expirationTime.toISOString()}`,
    'Resources:', `- ${makeRecapResource(att)}`,
  ].join('\n');
}
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

test.use({ viewport: { width: 390, height: 844 } });

test('one consent retains account discovery and Home/feed space identity through edits and approval', async ({ page }) => {
  const prepares: Array<{ permissions: unknown; actionKeys?: string[] }> = [];
  const approvals: Record<string, unknown>[] = [];
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/api/**', route => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, { session: { id: 'tc2490-fixture-session', userId: 'tc2490-fixture', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'tc2490-fixture', email: 'tc2490@example.test', name: 'QA Fixture' } });
    if (path === '/api/keys') return json(route, { keys: [{ id: 'tc2490-key', address, publicKey: '0x', keyIndex: 0, label: 'QA Fixture', keyType: 'MANAGED', isPrimary: true, createdAt: '2026-11-05T00:00:00.000Z' }] });
    if (path === '/api/delegate/prepare') {
      const body = route.request().postDataJSON();
      prepares.push(body);
      const selected = body.actionKeys ?? fullKeys;
      return json(route, {
        prepared: { siwe: message(selected), spaceId: spaceId('applications'), jwk: {} },
        spaceId: spaceId('applications'), ownerDid: `did:pkh:eip155:1:${address}`, address, chainId: 1,
        host: 'https://node.tinycloud.xyz', permissions, selectedActionKeys: selected, edited: body.actionKeys !== undefined,
        authorizationContext: { token: `context-${prepares.length}`, expiresAt: Date.now() + 600000, baselineAbilitiesDigest: 'fixture-digest' },
      });
    }
    if (path === '/api/delegate') {
      approvals.push(route.request().postDataJSON());
      // Stop at the signing boundary; no fake success/confirmation is asserted.
      return json(route, { error: 'QA fixture: signing boundary reached' }, 503);
    }
    return json(route, { error: `Unmocked API: ${path}` }, 404);
  });
  const jwk = encodeBase64UrlJson({ kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
  await page.goto(`/delegate?did=did:key:z6Mk&jwk=${jwk}&permissions=${encodeBase64UrlJson({ permissions: request })}`);
  const approve = page.getByRole('button', { name: 'Approve', exact: true });
  await expect(approve).toBeEnabled();
  expect(prepares).toHaveLength(1);
  expect(prepares[0]!.permissions).toEqual(request);
  const details = page.locator('details.advanced-details');
  await details.locator(':scope > summary').click();
  await details.getByRole('button', { name: 'Edit', exact: true }).click();
  await details.locator('details[aria-label="Standard permissions"] > summary').click();
  if (process.env.TC2490_SCREEN_DIR) await page.screenshot({ path: `${process.env.TC2490_SCREEN_DIR}/consent-full-390.png`, fullPage: true });
  const grants = details.locator('li.grant');
  for (const entry of request) {
    await expect(grants.filter({ has: page.locator(`[aria-label="Exact resource: ${spaceId(entry.space)}/${entry.service.slice('tinycloud.'.length)}${entry.path ? `/${entry.path}` : ''}"]`) })).toHaveCount(1);
  }
  const revealStandard = async () => {
    const bucket = details.locator('details[aria-label="Standard permissions"]');
    if (await bucket.getAttribute('open') === null) await bucket.locator(':scope > summary').click();
  };
  const feed = grants.filter({ has: page.locator(`[title="${spaceId('applications')}/sql/xyz.tinycloud.tinychat/feed/"]`) });
  const home = grants.filter({ has: page.locator(`[title="${spaceId('applications')}/sql/xyz.tinycloud.tinychat/home_feed"]`) });
  const accountSpaces = grants.filter({ has: page.locator(`[title="${spaceId('account')}/kv/spaces/"]`) });
  const accountApps = grants.filter({ has: page.locator(`[title="${spaceId('account')}/kv/applications/"]`) });
  await feed.getByRole('checkbox', { name: 'write', exact: true }).uncheck();
  await expect(approve).toBeEnabled();
  await revealStandard();
  const removedWrite = permissions[3]!.actions.find(action => action.ability === 'tinycloud.sql/write')!.key;
  const withoutFeedWrite = fullKeys.filter(key => key !== removedWrite);
  expect(prepares.at(-1)!.actionKeys).toEqual(withoutFeedWrite);
  await expect(home.getByRole('checkbox', { name: 'write', exact: true })).toBeChecked();
  await accountSpaces.getByRole('checkbox', { name: 'get', exact: true }).uncheck();
  await expect(approve).toBeEnabled();
  await revealStandard();
  const removedGet = permissions[0]!.actions.find(action => action.ability === 'tinycloud.kv/get')!.key;
  const narrowed = withoutFeedWrite.filter(key => key !== removedGet);
  expect(prepares.at(-1)!.actionKeys).toEqual(narrowed);
  await expect(accountApps.getByRole('checkbox', { name: 'get', exact: true })).toBeChecked();
  // A removed action stays available in the original review model and restores only its own resource.
  await feed.getByRole('checkbox', { name: 'write', exact: true }).check();
  await expect(approve).toBeEnabled();
  await revealStandard();
  const restored = fullKeys.filter(key => key !== removedGet);
  expect(new Set(prepares.at(-1)!.actionKeys)).toEqual(new Set(restored));
  expect(prepares.every(body => JSON.stringify(body.permissions) === JSON.stringify(request))).toBe(true);
  expect(await page.evaluate(() => ({ width: innerWidth, overflow: document.documentElement.scrollWidth > innerWidth }))).toEqual({ width: 390, overflow: false });
  if (process.env.TC2490_SCREEN_DIR) await page.screenshot({ path: `${process.env.TC2490_SCREEN_DIR}/consent-edited-390.png`, fullPage: true });
  await approve.click();
  await expect(page.getByText('Couldn\'t approve this request. Try again. (Error 503)')).toBeVisible();
  expect(approvals).toHaveLength(1);
  expect(approvals[0]).toMatchObject({ selectedActionIds: prepares.at(-1)!.actionKeys, actionKeys: prepares.at(-1)!.actionKeys, permissions: request, prepared: { siwe: message(restored), spaceId: spaceId('applications') }, authorizationContextToken: `context-${prepares.length}` });
  expect(errors).toEqual([]);
});
