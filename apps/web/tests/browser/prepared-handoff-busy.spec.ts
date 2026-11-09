// The prepared CLI sign-in page answers a 409 or a 410 mid-approval in the
// owner's words, never the server's text. A 409 during signing (or on Cancel)
// says the request is already being approved; a 410 says it has already been
// answered or has ended. Other statuses keep the server text. The screenshot
// (SHOT_DIR) is the 390px phone width.
import { test, expect, type Page, type Route } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const host = 'https://node.tinycloud.xyz';
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const handoffId = 'B'.repeat(43);
const state = 'A'.repeat(43);
const cancelSecret = 'C'.repeat(43);
const siwe = [
  'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
  'I further authorize these capabilities.', '',
  'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-16T17:00:00.000Z', 'Expiration Time: 2026-10-23T17:00:00.000Z',
  'Resources:',
  `- ${makeRecapResource({ [`${space}/kv/notes/`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/sync': [{}] } })}`,
].join('\n');
const fullKey = `tinycloud.kv\0${space}\0notes/\0tinycloud.kv/get`;
const syncKey = `tinycloud.kv\0${space}\0notes/\0tinycloud.kv/sync`;
const key = { id: 'key-one', address, publicKey: '0x', keyIndex: 0, label: null, keyType: 'MANAGED', isPrimary: true, createdAt: '2026-10-16T17:00:00.000Z' };
const rawResult = { protocolVersion: 1, address, signature: '0xsigned', signedMessage: siwe, selectedActionKeys: [fullKey, syncKey], permissions: [{ service: 'tinycloud.kv', space, path: 'notes/', actions: ['tinycloud.kv/get', 'tinycloud.kv/sync'] }] };
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

const BUSY = 'This request is already being approved. Wait a moment.';
const ENDED = 'This request has already been answered or has ended.';

/** Opens the prepared page with `call` answered by `reply` instead of a normal response. */
async function setup(page: Page, replyFor: { call: 'prepare' | 'preview' | 'sign' | 'cancel'; reply: { status: number; body: unknown } }) {
  await page.clock.setFixedTime(new Date('2026-10-16T17:00:00.000Z'));
  const reply = (call: string, ok: { status: number; body: unknown }) => (call === replyFor.call ? replyFor.reply : ok);
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: '2026-10-16T18:00:00.000Z' }, user: { id: 'u', email: 'owner@example.test' } });
    if (path === '/api/keys') return json(route, 200, { keys: [key] });
    if (path === '/api/delegate/handoffs/available') return json(route, 200, { transportVersion: 2 });
    if (path === '/api/delegate/handoffs/claim') return json(route, 201, { transportVersion: 2, ticket: handoffId, expiresAt: '2026-10-16T17:05:00.000Z' });
    if (path === '/api/delegate/handoffs/cancel-claimed') {
      const r = reply('cancel', { status: 200, body: { cancelled: true } });
      return json(route, r.status, r.body);
    }
    if (path === '/api/delegate/authorize-sign-prepare') {
      const r = reply('prepare', { status: 200, body: { authorizationContextToken: 'bound-context', allowedActionIds: [fullKey, syncKey], initialSelectionActionIds: [fullKey, syncKey], address } });
      return json(route, r.status, r.body);
    }
    if (path === '/api/delegate/authorize-sign-preview') {
      const r = reply('preview', { status: 200, body: { ...rawResult, previewApprovalToken: 'approved-preview' } });
      return json(route, r.status, r.body);
    }
    if (path === '/api/delegate/authorize-sign') {
      const r = reply('sign', { status: 200, body: { ...rawResult, deliveryState: state, selectedKeyId: key.id } });
      return json(route, r.status, r.body);
    }
    return json(route, 404, { error: `unexpected ${path}` });
  });
  const input = { transportVersion: 2, request: { protocolVersion: 1, siwe, jwk, host, sessionDid: 'did:key:cli-session', keyId: key.id }, delivery: { handoffId, state, cancelSecret } };
  await page.goto(`/delegate#tv2=${Buffer.from(JSON.stringify(input)).toString('base64url')}`);
}

test.describe('the prepared CLI sign-in page when the request is already moving', () => {
  for (const reply of [
    { status: 409, body: { code: 'handoff_signing', error: 'Handoff is being signed' }, expect: BUSY, server: 'Handoff is being signed' },
    { status: 410, body: { code: 'expired_request', error: 'Approval request is no longer pending' }, expect: ENDED, server: 'Approval request is no longer pending' },
  ]) {
    test(`approve answered ${reply.status}: the owner's wording, not the server text`, async ({ page }) => {
      await setup(page, { call: 'sign', reply });
      await page.getByRole('button', { name: 'Preview signing message' }).click();
      await page.getByRole('button', { name: 'Approve', exact: true }).click();
      await expect(page.getByRole('alert')).toHaveText(reply.expect);
      await expect(page.getByText(reply.server)).toHaveCount(0);
    });
  }

  test('a 409 on cancel uses the same owner wording', async ({ page }) => {
    await setup(page, { call: 'cancel', reply: { status: 409, body: { code: 'handoff_signing', error: 'Handoff is being signed' } } });
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    await expect(page.getByRole('alert')).toHaveText(BUSY);
    await expect(page.getByText('Handoff is being signed')).toHaveCount(0);
  });

  test('other statuses keep the server text', async ({ page }) => {
    await setup(page, { call: 'sign', reply: { status: 500, body: { error: 'signing service unavailable' } } });
    await page.getByRole('button', { name: 'Preview signing message' }).click();
    await page.getByRole('button', { name: 'Approve', exact: true }).click();
    await expect(page.getByRole('alert')).toHaveText('signing service unavailable');
  });
});

test('screenshot at 390: the busy wording after Approve', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await setup(page, { call: 'sign', reply: { status: 409, body: { code: 'handoff_signing', error: 'Handoff is being signed' } } });
  await page.getByRole('button', { name: 'Preview signing message' }).click();
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.getByRole('alert')).toHaveText(BUSY);
  await page.getByRole('alert').scrollIntoViewIfNeeded();
  const shots = process.env.SHOT_DIR;
  if (shots) await page.screenshot({ path: `${shots}/handoff-busy-390.png`, fullPage: false });
});

test('the owner revocation page shows the busy wording on a 409', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'owner@example.test' } });
    if (path === '/api/keys') return json(route, 200, { keys: [{ id: 'key-owner', address, publicKey: '0x', keyIndex: 0, label: 'Owner key', keyType: 'MANAGED', createdAt: '2026-10-16T17:00:00.000Z' }] });
    if (path === '/api/delegate/handoffs/available') return json(route, 200, { transportVersion: 2 });
    if (path === '/api/delegate/handoffs/claim') return json(route, 201, { transportVersion: 2, ticket: handoffId, expiresAt: new Date(Date.now() + 300_000).toISOString() });
    if (path === '/api/delegate/owner-revocation/prepare') return json(route, 409, { code: 'handoff_signing', error: 'Handoff is being signed' });
    return json(route, 404, { error: `unexpected ${path}` });
  });
  const request = { kind: 'owner-revocation', ownerDid: `did:pkh:eip155:1:${address}`, cid: 'bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe', nonce: '0123456789abcdef0123456789abcdef', expiresAt: new Date(Date.now() + 590_000).toISOString() };
  await page.goto(`/delegate#tv2=${Buffer.from(JSON.stringify({ transportVersion: 2, request, delivery: { handoffId, state, cancelSecret } })).toString('base64url')}`);
  await expect(page.getByRole('alert')).toHaveText(BUSY);
  await expect(page.getByText('Handoff is being signed')).toHaveCount(0);
  const shots = process.env.SHOT_DIR;
  if (shots) await page.screenshot({ path: `${shots}/revoke-busy-390.png`, fullPage: false });
});
