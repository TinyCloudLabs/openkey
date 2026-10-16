import { test, expect, type Page, type Route } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const host = 'https://node.tinycloud.xyz';
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const siwe = [
  'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
  'I further authorize these capabilities.', '',
  'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-16T17:00:00.000Z', 'Expiration Time: 2026-10-23T17:00:00.000Z',
  'Resources:', `- ${makeRecapResource({ [`${space}/kv/notes/`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/sync': [{}] } })}`,
].join('\n');
const fullKey = `tinycloud.kv\0${space}\0notes/\0tinycloud.kv/get`;
const syncKey = `tinycloud.kv\0${space}\0notes/\0tinycloud.kv/sync`;
const key = { id: 'key-one', address, publicKey: '0x', keyIndex: 0, label: null, keyType: 'MANAGED', isPrimary: true, createdAt: '2026-10-16T17:00:00.000Z' };
const rawResult = { protocolVersion: 1, address, signature: '0xsigned', signedMessage: siwe, selectedActionKeys: [fullKey, syncKey], permissions: [{ service: 'tinycloud.kv', space, path: 'notes/', actions: ['tinycloud.kv/get', 'tinycloud.kv/sync'] }] };
const narrowedSiwe = siwe.replace(
  makeRecapResource({ [`${space}/kv/notes/`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/sync': [{}] } }),
  makeRecapResource({ [`${space}/kv/notes/`]: { 'tinycloud.kv/get': [{}] } }),
);
const narrowedResult = { ...rawResult, signedMessage: narrowedSiwe, selectedActionKeys: [fullKey], permissions: [{ service: 'tinycloud.kv', space, path: 'notes/', actions: ['tinycloud.kv/get'] }] };
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

async function setup(page: Page, options: { keyId?: string; callback?: string; narrowed?: boolean; external?: boolean } = {}) {
  const calls: Array<{ path: string; body: unknown }> = [];
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = route.request().postDataJSON?.() ?? {};
    calls.push({ path, body });
    if (path === '/api/auth/get-session') return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: '2026-10-16T18:00:00.000Z' }, user: { id: 'u', email: 'owner@example.test' } });
    if (path === '/api/keys') return json(route, 200, { keys: [{ ...key, keyType: options.external ? 'EXTERNAL' : 'MANAGED' }] });
    if (path === '/api/delegate/handoffs/resolve') return json(route, 200, { transportVersion: 2, request: { protocolVersion: 1, siwe, jwk, host, sessionDid: 'did:key:cli-session', ...options.keyId ? { keyId: options.keyId } : {} }, delivery: { ...options.callback ? { callback: options.callback } : {} }, expiresAt: '2026-10-16T18:00:00.000Z' });
    if (path === '/api/delegate/handoffs/cancel-claimed') return json(route, 200, { cancelled: true });
    if (path === '/api/delegate/authorize-sign-prepare') return json(route, 200, { authorizationContextToken: 'bound-context', allowedActionIds: [fullKey, syncKey], initialSelectionActionIds: [fullKey, syncKey], address });
    if (path === '/api/delegate/authorize-sign-preview') return json(route, 200, { ...(options.narrowed ? narrowedResult : rawResult), previewApprovalToken: 'approved-preview' });
    if (path === '/api/delegate/authorize-sign') return json(route, 200, { ...(options.narrowed ? narrowedResult : rawResult), deliveryState: 'A'.repeat(43), selectedKeyId: key.id });
    return json(route, 404, { error: `unexpected ${path}` });
  });
  await page.goto('/delegate?transportVersion=2&ticket=ticket-public');
  return calls;
}

test('v2 displays original and exact preview, signs the bound context, and pastes an unchanged S3 result', async ({ page }) => {
  const calls = await setup(page, { keyId: key.id });
  await expect(page.getByText('Only approve if you started this sign-in yourself on your own computer.')).toBeVisible();
  await expect(page.getByText('did:key:cli-session')).toBeVisible();
  await expect(page.getByText(host)).toBeVisible();
  await expect(page.getByText(siwe, { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Preview signing message' }).click();
  await expect(page.getByText(siwe, { exact: true })).toHaveCount(2);
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  const code = await page.locator('textarea').inputValue();
  const envelope = JSON.parse(Buffer.from(code, 'base64url').toString('utf8'));
  expect(envelope).toEqual({ transportVersion: 2, state: 'A'.repeat(43), selectedKeyId: key.id, result: rawResult });
  expect(calls.filter(c => c.path === '/api/delegate/prepare')).toHaveLength(0);
  expect(calls.find(c => c.path === '/api/delegate/authorize-sign-prepare')?.body).toMatchObject({ keyId: key.id, siwe, jwk, host });
  expect(calls.find(c => c.path === '/api/delegate/authorize-sign')?.body).toMatchObject({ authorizationContextToken: 'bound-context', previewApprovalToken: 'approved-preview', selectedActionIds: [fullKey, syncKey] });
});

test('v2 rejects a different requested key rather than invoking legacy prepare', async ({ page }) => {
  const calls = await setup(page, { keyId: 'different-key' });
  await expect(page.getByText(/requested signing key is not available/i)).toBeVisible();
  expect(calls.filter(c => c.path === '/api/delegate/prepare' || c.path === '/api/delegate/authorize-sign-prepare')).toHaveLength(0);
});

test('v2 narrowing previews the exact candidate and never signs a second time', async ({ page }) => {
  const calls = await setup(page, { narrowed: true });
  await page.getByRole('checkbox', { name: 'tinycloud.kv/sync' }).uncheck();
  await page.getByRole('button', { name: 'Preview signing message' }).click();
  await expect(page.getByText(narrowedSiwe, { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  expect(calls.find(c => c.path === '/api/delegate/authorize-sign-preview')?.body).toMatchObject({ selectedActionIds: [fullKey], ticket: 'ticket-public' });
  expect(calls.find(c => c.path === '/api/delegate/authorize-sign')?.body).toMatchObject({ selectedActionIds: [fullKey], ticket: 'ticket-public' });
  const narrowedCode = await page.locator('textarea').inputValue();
  expect(JSON.parse(Buffer.from(narrowedCode, 'base64url').toString('utf8')).result).toEqual(narrowedResult);
  await page.reload();
  expect(calls.filter(c => c.path === '/api/delegate/authorize-sign')).toHaveLength(1);
});

test('v2 callback delivers the envelope without exposing a paste code after CLI acceptance', async ({ page }) => {
  const callback = 'http://127.0.0.1:43210/callback/abcdefghijklmnopqrstuv';
  let delivered: unknown;
  await page.route(callback, route => {
    delivered = route.request().postDataJSON();
    return json(route, 200, { accepted: true });
  });
  await setup(page, { callback });
  await page.getByRole('button', { name: 'Preview signing message' }).click();
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.getByText('CLI accepted your sign-in. You can close this window.')).toBeVisible();
  expect(delivered).toEqual({ transportVersion: 2, state: 'A'.repeat(43), selectedKeyId: key.id, result: rawResult });
  await expect(page.locator('textarea')).toHaveCount(0);
});

test('v2 cancellation revokes the claimed handoff before signing', async ({ page }) => {
  const calls = await setup(page);
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByText(/Approval cancelled/)).toBeVisible();
  expect(calls.filter(c => c.path === '/api/delegate/handoffs/cancel-claimed')).toEqual([
    { path: '/api/delegate/handoffs/cancel-claimed', body: { ticket: 'ticket-public' } },
  ]);
  expect(calls.filter(c => c.path === '/api/delegate/authorize-sign')).toHaveLength(0);
});

test('v2 external wallet signs the preview bytes and sends externalSignature', async ({ page }) => {
  await page.addInitScript(({ owner }) => {
    Object.assign(window, { ethereum: { request: async ({ method, params }: { method: string; params?: unknown[] }) => {
      if (method === 'eth_requestAccounts') return [owner];
      if (method === 'personal_sign') {
        (window as Window & { signedText?: unknown }).signedText = params?.[0];
        return '0xwallet-signature';
      }
      throw new Error(`Unexpected wallet call ${method}`);
    } } });
  }, { owner: address });
  const calls = await setup(page, { external: true });
  await page.getByRole('button', { name: 'Preview signing message' }).click();
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.locator('textarea')).toBeVisible();
  expect(await page.evaluate(() => (window as Window & { signedText?: unknown }).signedText)).toBe(siwe);
  expect(calls.find(c => c.path === '/api/delegate/authorize-sign')?.body).toMatchObject({
    externalSignature: '0xwallet-signature',
    selectedActionIds: [fullKey, syncKey],
  });
});
