// TC-2276 item 2: on a CLI prepared handoff the owner may choose LONGER than the CLI asked for only when the CLI
// opted in with `request.expiryChangeable: true`. Without it the picker stays shorter-only. The mocked API answers the
// claim, prepare and preview calls; the preview body shows what the page asked OpenKey to seal.

import { test, expect, type Page, type Route } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const siwe = [
  'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
  'I further authorize these capabilities.', '',
  'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-16T17:00:00.000Z', 'Expiration Time: 2026-10-23T17:00:00.000Z',
  'Resources:', `- ${makeRecapResource({ [`${space}/kv/notes/`]: { 'tinycloud.kv/get': [{}] } })}`,
].join('\n');
const getKey = `tinycloud.kv\0${space}\0notes/\0tinycloud.kv/get`;
const key = { id: 'key-one', address, publicKey: '0x', keyIndex: 0, label: null, keyType: 'MANAGED', isPrimary: true, createdAt: '2026-10-16T17:00:00.000Z' };
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

async function open(page: Page, extraRequest: Record<string, unknown>) {
  const previews: Array<Record<string, unknown>> = [];
  await page.clock.setFixedTime(new Date('2026-10-16T17:00:00.000Z'));
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = route.request().postDataJSON?.() ?? {};
    if (path === '/api/auth/get-session') return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: '2026-10-16T18:00:00.000Z' }, user: { id: 'u', email: 'owner@example.test' } });
    if (path === '/api/keys') return json(route, 200, { keys: [key] });
    if (path === '/api/delegate/handoffs/available') return json(route, 200, { transportVersion: 2 });
    if (path === '/api/delegate/handoffs/claim') return json(route, 201, { transportVersion: 2, ticket: 'B'.repeat(43), expiresAt: '2026-10-16T17:05:00.000Z' });
    if (path === '/api/delegate/handoffs/cancel-claimed') return json(route, 200, { cancelled: true });
    if (path === '/api/delegate/authorize-sign-prepare') return json(route, 200, { authorizationContextToken: 'bound-context', allowedActionIds: [getKey], initialSelectionActionIds: [getKey], address });
    if (path === '/api/delegate/authorize-sign-preview') {
      previews.push(body as Record<string, unknown>);
      return json(route, 200, { protocolVersion: 1, address, signature: '0xsigned', signedMessage: siwe, selectedActionKeys: [getKey], permissions: [{ service: 'tinycloud.kv', space, path: 'notes/', actions: ['tinycloud.kv/get'] }], previewApprovalToken: 'approved-preview' });
    }
    return json(route, 404, { error: `unexpected ${path}` });
  });
  const input = {
    transportVersion: 2,
    request: { protocolVersion: 1, siwe, jwk, host: 'https://node.tinycloud.xyz', sessionDid: 'did:key:cli-session', keyId: key.id, ...extraRequest },
    delivery: { handoffId: 'B'.repeat(43), state: 'A'.repeat(43), cancelSecret: 'C'.repeat(43) },
  };
  await page.goto(`/delegate#tv2=${Buffer.from(JSON.stringify(input)).toString('base64url')}`);
  await expect(page.getByText('Approval expires:')).toBeVisible();
  return previews;
}

const presets = (page: Page) => page.getByRole('button', { name: /^(1 hr|24 hr|7d|30d)$/ });

test('a handoff that does not opt in keeps the shorter-only picker', async ({ page }) => {
  const previews = await open(page, {});
  await page.getByRole('button', { name: '(Change)' }).click();
  await expect(presets(page)).toHaveText(['1 hr', '24 hr', '7d']);
  await page.getByLabel('Or type a time').fill('40d');
  await page.getByRole('button', { name: 'Set' }).click();
  await expect(page.getByRole('alert').filter({ hasText: /\S/ })).toHaveCount(1);
  await page.getByRole('button', { name: 'Preview signing message' }).click();
  await expect.poll(() => previews.length).toBe(1);
  expect(previews[0]).not.toHaveProperty('expirationTime');
});

test('a handoff that opts in offers the longer presets and accepts a typed time beyond what the CLI asked for', async ({ page }) => {
  const previews = await open(page, { expiryChangeable: true });
  await page.getByRole('button', { name: '(Change)' }).click();
  await expect(presets(page)).toHaveText(['1 hr', '24 hr', '7d', '30d']);
  await page.getByLabel('Or type a time').fill('40d');
  await page.getByRole('button', { name: 'Set' }).click();
  await expect(page.getByRole('alert')).toHaveCount(0);
  await page.getByRole('button', { name: 'Preview signing message' }).click();
  await expect.poll(() => previews.length).toBe(1);
  // 40 days after the fixed "now" (2026-10-16T17:00:00Z), longer than the 7 days the CLI asked for.
  expect(previews[0]!.expirationTime).toBe('2026-11-25T17:00:00.000Z');
});

test('an opted-in handoff picks the 30-day preset and still refuses nonsense and the far future', async ({ page }) => {
  const previews = await open(page, { expiryChangeable: true });
  await page.getByRole('button', { name: '(Change)' }).click();
  await page.getByLabel('Or type a time').fill('99999y');
  await page.getByRole('button', { name: 'Set' }).click();
  await expect(page.getByRole('alert')).toHaveCount(1);
  await page.getByRole('button', { name: '30d' }).click();
  await page.getByRole('button', { name: 'Preview signing message' }).click();
  await expect.poll(() => previews.length).toBe(1);
  expect(previews[0]!.expirationTime).toBe('2026-11-15T17:00:00.000Z');
});
