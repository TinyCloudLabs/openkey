// A command-line tool asks for ONE exact app key. The prepared sign-in page shows the app host and the exact key
// beside a plain warning that a command-line tool, not the app's website, asks; the owner chooses how long it lasts
// (1 hour to start, up to what the tool signed); and a refusal from the API is said in the owner's words with no
// way to approve. The API is mocked. Screenshots (SHOT_DIR) are the 390px phone width and the 1280px desktop width.
import { test, expect, type Page, type Route } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';
import { TERMS_ACCEPTED } from './terms-fixtures';

const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const owner = `did:pkh:eip155:1:${address}`;
const host = 'https://node.tinycloud.xyz';
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const handoffId = 'B'.repeat(43);
const state = 'A'.repeat(43);
const cancelSecret = 'C'.repeat(43);
const appId = 'xyz.tinycloud.share';
const keyName = 'xyz.tinycloud.tinyapps.contacts/seal-v1';
const keyPath = `apps/${appId}/${keyName}`;
const appKey = { appId, key: keyName };
const NOW = '2026-10-16T17:00:00.000Z';
const HOUR = 3_600_000;
const DEFAULT_END = '2026-10-16T18:00:00.000Z';
const MAX_END = '2026-10-23T17:00:00.000Z';
const E = 'tinycloud.encryption/';

function siweFor(resources: Record<string, string[]>, expires = MAX_END) {
  const attenuations = Object.fromEntries(Object.entries(resources).map(([resource, abilities]) => [resource, Object.fromEntries(abilities.map((a) => [a, [{}]]))]));
  return [
    'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
    'I further authorize these capabilities.', '',
    'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', `Issued At: ${NOW}`, `Expiration Time: ${expires}`,
    'Resources:', `- ${makeRecapResource(attenuations)}`,
  ].join('\n');
}
const resource = `urn:tinycloud:encryption:${owner}:default/${keyPath}`;
const siwe = siweFor({ [resource]: [`${E}decrypt`, `${E}key.create`] });
const decryptId = `tinycloud.encryption\0encryption\0${resource}\0${E}decrypt`;
const createId = `tinycloud.encryption\0encryption\0${resource}\0${E}key.create`;
const key = { id: 'key-one', address, publicKey: '0x', keyIndex: 0, label: null, keyType: 'MANAGED', isPrimary: true, createdAt: NOW };
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', headers: { Date: new Date(NOW).toUTCString() }, body: JSON.stringify(body) });
const admitted = {
  appId, host: 'share.tinycloud.xyz', key: keyName, resource, abilities: ['decrypt', 'key.create'],
  requestedExpiresAt: MAX_END, defaultExpiresAt: DEFAULT_END, maxExpiresAt: MAX_END,
};
const permissions = [{ service: 'tinycloud.encryption', space: 'encryption', path: resource, actions: [`${E}decrypt`, `${E}key.create`] }];

type Calls = { claim: number; prepare: Record<string, unknown>[]; preview: Record<string, unknown>[] };

/** Opens the prepared page for a tool that asks for `request.appKey`; `prepareReply` answers authorize-sign-prepare. */
async function open(page: Page, options: { request?: Record<string, unknown>; prepareReply?: () => { status: number; body: unknown }; message?: string } = {}) {
  const calls: Calls = { claim: 0, prepare: [], preview: [] };
  await page.clock.setFixedTime(new Date(NOW));
  const message = options.message ?? siwe;
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: '2026-10-16T18:00:00.000Z' }, user: { id: 'u', email: 'owner@example.test' } });
    if (path === '/api/keys') return json(route, 200, { keys: [key] });
    if (path === '/api/delegate/handoffs/available') return json(route, 200, { transportVersion: 2 });
    if (path === '/api/delegate/handoffs/claim') { calls.claim += 1; return json(route, 201, { transportVersion: 2, ticket: handoffId, expiresAt: '2026-10-16T17:05:00.000Z' }); }
    if (path === '/api/delegate/handoffs/cancel-claimed') return json(route, 200, { cancelled: true });
    if (path === '/api/delegate/authorize-sign-prepare') {
      calls.prepare.push(route.request().postDataJSON());
      const reply = options.prepareReply?.() ?? { status: 200, body: { authorizationContextToken: 'bound-context', allowedActionIds: [createId, decryptId], initialSelectionActionIds: [createId, decryptId], address, appKey: admitted } };
      return json(route, reply.status, reply.body);
    }
    if (path === '/api/delegate/authorize-sign-preview') {
      const body = route.request().postDataJSON();
      calls.preview.push(body);
      const signedMessage = message.replace(/^Expiration Time: .*$/m, `Expiration Time: ${body.expirationTime ?? DEFAULT_END}`);
      return json(route, 200, { signedMessage, previewApprovalToken: 'approved-preview', selectedActionKeys: body.selectedActionIds, permissions });
    }
    return json(route, 404, { error: `unexpected ${path}` });
  });
  await page.route('**/api/account/terms', (route) => route.fulfill({ json: TERMS_ACCEPTED }));
  const input = { transportVersion: 2, request: { protocolVersion: 1, siwe: message, jwk, host, sessionDid: 'did:key:cli-session', keyId: key.id, appKey, ...options.request }, delivery: { handoffId, state, cancelSecret } };
  await page.goto(`/delegate#tv2=${Buffer.from(JSON.stringify(input)).toString('base64url')}`);
  return calls;
}

const warning = 'This request comes from TinyCloud CLI, a command-line tool, not from share.tinycloud.xyz. Approve it only if you started it on your own device.';
const refusals: Array<[string, string]> = [
  ['app_keys_file_missing', "OpenKey can't approve this request: share.tinycloud.xyz doesn't list keys that command-line tools can ask for. Nothing was approved."],
  ['app_keys_file_invalid', "OpenKey can't approve this request: share.tinycloud.xyz's list of keys for command-line tools can't be read. Nothing was approved."],
  ['app_key_not_listed', "OpenKey can't approve this request: share.tinycloud.xyz doesn't let command-line tools ask for the key seal-v1. Nothing was approved."],
];

test.describe('a command-line tool asks for one exact app key', () => {
  test('the row names the app host and the exact key, with the warning', async ({ page }) => {
    await open(page);
    const row = page.getByTestId('ticket-app-key-row');
    await expect(page.getByTestId('ticket-app-key-warning')).toHaveText(warning);
    await expect(page.getByText('TinyCloud CLI is requesting:')).toBeVisible();
    await expect(row).toContainText('App keys');
    await expect(row.getByText('share.tinycloud.xyz', { exact: true })).toBeVisible();
    await expect(row).toContainText('Create the encryption key seal-v1 for share.tinycloud.xyz');
    await expect(row).toContainText("Decrypt data locked with share.tinycloud.xyz's key seal-v1");
    await expect(row).toContainText(`Key: ${keyPath}`);
    // The generic abilities list is not shown beside it: the two abilities are one unit.
    await expect(page.getByRole('checkbox')).toHaveCount(0);
    await expect(page.getByText('Only approve if you started this sign-in yourself')).toHaveCount(0);
  });

  test('the lifetime starts at 1 hour and the owner may choose up to what the tool signed', async ({ page }) => {
    const calls = await open(page);
    await expect(page.getByTestId('approval-expiry-line')).toHaveText("This device's access to your data lasts 1 hour.");
    await page.getByRole('button', { name: 'Preview signing message' }).click();
    await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeVisible();
    expect(calls.prepare[0]).toMatchObject({ ticket: handoffId, appKey });
    expect(calls.preview[0]).not.toHaveProperty('expirationTime');

    await page.getByRole('button', { name: 'Change access length' }).click();
    await page.getByText('How long it lasts', { exact: true }).click();
    await page.getByRole('button', { name: '7 days', exact: true }).click();
    await expect(page.getByTestId('approval-expiry-length-note')).toHaveText('TinyCloud CLI keeps this access for the time you choose.');
    await page.getByRole('button', { name: 'Preview signing message' }).click();
    await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeVisible();
    expect(calls.preview[1]!.expirationTime).toBe(new Date(Date.parse(NOW) + 7 * 24 * HOUR).toISOString());
    expect(calls.preview[1]!.selectedActionIds).toEqual(expect.arrayContaining([createId, decryptId]));
  });

  test('the access length reflects the server default', async ({ page }) => {
    await open(page, {
      prepareReply: () => ({
        status: 200,
        body: { authorizationContextToken: 'bound-context', appKey: { ...admitted, defaultExpiresAt: '2026-10-16T17:30:00.000Z' } },
      }),
    });
    await expect(page.getByTestId('approval-expiry-line')).toHaveText("This device's access to your data lasts 30 minutes.");
  });

  test('a request-level refusal uses the structured reason', async ({ page }) => {
    await open(page, {
      prepareReply: () => ({ status: 403, body: { code: 'app_key_request_invalid', reason: 'account', error: 'server words' } }),
    });
    await expect(page.getByTestId('ticket-app-key-refusal')).toHaveText('This request was made for a different account. Nothing was approved.');
    await expect(page.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(0);
  });

  for (const [code, line] of refusals) {
    test(`${code}: the owner reads why, and cannot approve`, async ({ page }) => {
      await open(page, { prepareReply: () => ({ status: 403, body: { error: 'server words', code } }) });
      await expect(page.getByTestId('ticket-app-key-refusal')).toHaveText(line);
      await expect(page.getByRole('button', { name: 'Preview signing message' })).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Cancel', exact: true })).toBeVisible();
      await expect(page.getByText('server words')).toHaveCount(0);
    });
  }

  test('a failed check of the file may be tried again', async ({ page }) => {
    let attempts = 0;
    const calls = await open(page, {
      prepareReply: () => (++attempts === 1
        ? { status: 403, body: { error: 'x', code: 'app_keys_file_unavailable' } }
        : { status: 200, body: { authorizationContextToken: 'bound-context', allowedActionIds: [createId, decryptId], initialSelectionActionIds: [createId, decryptId], address, appKey: admitted } }),
    });
    await expect(page.getByTestId('ticket-app-key-refusal')).toHaveText("OpenKey couldn't check share.tinycloud.xyz's list of keys for command-line tools. Nothing was approved. Try again.");
    await page.getByRole('button', { name: 'Try again' }).click();
    await page.getByRole('button', { name: 'Preview signing message' }).click();
    await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeVisible();
    expect(calls.prepare).toHaveLength(2);
  });

  test('a request whose signed message names another key is stopped before anything is claimed', async ({ page }) => {
    const other = `urn:tinycloud:encryption:${owner}:default/apps/${appId}/other/key`;
    const calls = await open(page, { message: siweFor({ [other]: [`${E}decrypt`, `${E}key.create`] }) });
    await expect(page.getByRole('heading', { name: 'OpenKey can’t read what this request asks for' })).toBeVisible();
    await expect(page.getByTestId('ticket-app-key-row')).toHaveCount(0);
    expect(calls.claim).toBe(0);
  });

  test('a request that adds a second key is stopped the same way', async ({ page }) => {
    const second = `urn:tinycloud:encryption:${owner}:default/apps/${appId}/second/key`;
    const calls = await open(page, { message: siweFor({ [resource]: [`${E}decrypt`, `${E}key.create`], [second]: [`${E}decrypt`, `${E}key.create`] }) });
    await expect(page.getByRole('heading', { name: 'OpenKey can’t read what this request asks for' })).toBeVisible();
    expect(calls.claim).toBe(0);
  });

  test('an admitted key that differs from the one shown is not approved', async ({ page }) => {
    const calls = await open(page, { prepareReply: () => ({ status: 200, body: { authorizationContextToken: 'c', address, appKey: { ...admitted, key: 'other/key' } } }) });
    await expect(page.locator('[data-support-line]')).toHaveText('HTTP 200');
    await expect(page.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(0);
    expect(calls.preview).toHaveLength(0);
  });

  for (const [name, size] of [['390', { width: 390, height: 844 }], ['1280', { width: 1280, height: 900 }]] as const) {
    test(`screenshot at ${name}`, async ({ page }) => {
      await page.setViewportSize(size);
      await open(page);
      await expect(page.getByTestId('approval-expiry-line')).toBeVisible();
      const shots = process.env.SHOT_DIR;
      if (shots) await page.screenshot({ path: `${shots}/ticket-app-key-${name}.png`, fullPage: true });
    });
  }
});
