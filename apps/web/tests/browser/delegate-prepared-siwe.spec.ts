import { test, expect, type Page, type Route } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const host = 'https://node.tinycloud.xyz';
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const handoffId = 'B'.repeat(43);
const state = 'A'.repeat(43);
const cancelSecret = 'C'.repeat(43);
const pendingKey = 'openkey.delegate.tv2.pending';
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
type KeyFixture = Omit<typeof key, 'label'> & { label: string | null };
const rawResult = { protocolVersion: 1, address, signature: '0xsigned', signedMessage: siwe, selectedActionKeys: [fullKey, syncKey], permissions: [{ service: 'tinycloud.kv', space, path: 'notes/', actions: ['tinycloud.kv/get', 'tinycloud.kv/sync'] }] };
const narrowedSiwe = siwe.replace(
  makeRecapResource({ [`${space}/kv/notes/`]: { 'tinycloud.kv/get': [{}], 'tinycloud.kv/sync': [{}] } }),
  makeRecapResource({ [`${space}/kv/notes/`]: { 'tinycloud.kv/get': [{}] } }),
);
const narrowedResult = { ...rawResult, signedMessage: narrowedSiwe, selectedActionKeys: [fullKey], permissions: [{ service: 'tinycloud.kv', space, path: 'notes/', actions: ['tinycloud.kv/get'] }] };
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

async function setup(page: Page, options: { keyId?: string; callback?: string; narrowed?: boolean; external?: boolean; keys?: KeyFixture[]; siwe?: string; authenticated?: boolean } = {}) {
  const calls: Array<{ path: string; body: unknown }> = [];
  let preparedKeyId = key.id;
  await page.clock.setFixedTime(new Date('2026-10-16T17:00:00.000Z'));
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = route.request().postDataJSON?.() ?? {};
    calls.push({ path, body });
    if (path === '/api/auth/get-session') return json(route, 200, options.authenticated === false ? null : { session: { id: 's', userId: 'u', expiresAt: '2026-10-16T18:00:00.000Z' }, user: { id: 'u', email: 'owner@example.test' } });
    if (path === '/api/keys') return json(route, 200, { keys: options.keys ?? [{ ...key, keyType: options.external ? 'EXTERNAL' : 'MANAGED' }] });
    if (path === '/api/delegate/handoffs/claim') return json(route, 201, { transportVersion: 2, ticket: handoffId, expiresAt: '2026-10-16T17:05:00.000Z' });
    if (path === '/api/delegate/handoffs/cancel-claimed') return json(route, 200, { cancelled: true });
    if (path === '/api/delegate/authorize-sign-prepare') {
      if (!body || typeof body !== 'object' || !('keyId' in body) || typeof body.keyId !== 'string') throw new Error('Missing prepared keyId');
      preparedKeyId = body.keyId;
      return json(route, 200, { authorizationContextToken: 'bound-context', allowedActionIds: [fullKey, syncKey], initialSelectionActionIds: [fullKey, syncKey], address });
    }
    if (path === '/api/delegate/authorize-sign-preview') return json(route, 200, { ...(options.narrowed ? narrowedResult : rawResult), previewApprovalToken: 'approved-preview' });
    if (path === '/api/delegate/authorize-sign') return json(route, 200, { ...(options.narrowed ? narrowedResult : rawResult), deliveryState: state, selectedKeyId: preparedKeyId });
    return json(route, 404, { error: `unexpected ${path}` });
  });
  const input = { transportVersion: 2, request: { protocolVersion: 1, siwe: options.siwe ?? siwe, jwk, host, sessionDid: 'did:key:cli-session', ...options.keyId ? { keyId: options.keyId } : {} }, delivery: { handoffId, state, cancelSecret, ...options.callback ? { callback: options.callback } : {} } };
  await page.goto(`/delegate#tv2=${Buffer.from(JSON.stringify(input)).toString('base64url')}`);
  return calls;
}

test('v2 displays original and exact preview, signs the bound context, and pastes an unchanged S3 result', async ({ page }) => {
  const calls = await setup(page, { keyId: key.id });
  await expect(page.getByText('Only approve if you started this sign-in yourself on your own computer.')).toBeVisible();
  expect(new URL(page.url()).hash).toBe('');
  expect(await page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey)).toBeNull();
  expect(calls.filter(call => call.path === '/api/delegate/handoffs/claim')).toHaveLength(1);
  expect(calls.find(call => call.path === '/api/delegate/handoffs/claim')?.body).toMatchObject({
    transportVersion: 2,
    request: { siwe, jwk, host, keyId: key.id },
    delivery: { handoffId, state, cancelSecret },
  });
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

test('v2 distinguishes the approval request expiry from the exact SIWE grant expiry', async ({ page }) => {
  await page.clock.setFixedTime(new Date('2026-10-16T17:00:00.000Z'));
  await setup(page);
  const ticketExpiry = new Date('2026-10-16T17:05:00.000Z').toLocaleString();
  const grantExpiry = new Date('2026-10-23T17:00:00.000Z').toLocaleString();
  await expect(page.getByText('Approval request expires')).toBeVisible();
  await expect(page.getByText('Access granted until')).toBeVisible();
  await expect(page.getByText(ticketExpiry)).toBeVisible();
  await expect(page.getByText(`${grantExpiry} (in 7 days)`)).toBeVisible();
  await page.getByRole('button', { name: 'Preview signing message' }).click();
  await expect(page.getByText('Approval request expires')).toBeVisible();
  await expect(page.getByText(`${grantExpiry} (in 7 days)`)).toBeVisible();
});

test('v2 warns when the exact SIWE has no expiration rather than implying the ticket TTL is a grant TTL', async ({ page }) => {
  await setup(page, { siwe: siwe.replace('Expiration Time: 2026-10-23T17:00:00.000Z\n', '') });
  await expect(page.getByText('Approval request expires')).toBeVisible();
  await expect(page.getByText('No expiry set')).toBeVisible();
  await expect(page.getByText('Access granted until')).toHaveCount(0);
});

test('v2 keeps the cleared fragment only in tab storage through sign-in and removes it after claim', async ({ page }) => {
  const calls = await setup(page, { authenticated: false });
  await expect(page.getByText('Sign in to review this request.')).toBeVisible();
  expect(new URL(page.url()).hash).toBe('');
  expect(await page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey)).not.toBeNull();
  expect(calls.filter(call => call.path === '/api/delegate/handoffs/claim')).toHaveLength(0);
  await page.route('**/api/auth/get-session', route => json(route, 200, { session: { id: 's', userId: 'u', expiresAt: '2026-10-16T18:00:00.000Z' }, user: { id: 'u', email: 'owner@example.test' } }));
  await page.goto('/delegate');
  await expect(page.getByText('Only approve if you started this sign-in yourself on your own computer.')).toBeVisible();
  expect(await page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey)).toBeNull();
  expect(calls.filter(call => call.path === '/api/delegate/handoffs/claim')).toHaveLength(1);
});

test('cancel before authenticated claim clears only tab-scoped request data', async ({ page }) => {
  const calls = await setup(page, { authenticated: false });
  await expect(page.getByText('Sign in to review this request.')).toBeVisible();
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByRole('alert')).toContainText('Approval cancelled');
  expect(await page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey)).toBeNull();
  expect(calls.filter(call => call.path === '/api/delegate/handoffs/claim')).toHaveLength(0);
  await page.reload();
  await expect(page.getByRole('alert')).toContainText(/unsupported|restart/i);
});

test('invalid fragments fail explicitly and leave no pending request', async ({ page }) => {
  await page.route('**/api/auth/get-session', route => json(route, 200, { session: { id: 's', userId: 'u', expiresAt: '2026-10-16T18:00:00.000Z' }, user: { id: 'u' } }));
  await page.goto('/delegate#tv2=not-a-json-request');
  await expect(page.getByRole('alert')).toContainText(/invalid|unsupported|restart/i);
  expect(new URL(page.url()).hash).toBe('');
  expect(await page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey)).toBeNull();
});

test('an unauthenticated pending request is erased when its five-minute claim window expires', async ({ page }) => {
  await setup(page, { authenticated: false });
  await expect(page.getByText('Sign in to review this request.')).toBeVisible();
  await page.clock.fastForward(300_001);
  await expect(page.getByRole('alert')).toContainText(/expired|restart/i);
  expect(await page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey)).toBeNull();
});

test('oversized fragment and retired ticket-query transport never fall through to v1', async ({ page }) => {
  const paths: string[] = [];
  await page.route('**/api/**', route => {
    paths.push(new URL(route.request().url()).pathname);
    return json(route, 200, { session: null });
  });
  await page.goto(`/delegate#tv2=${'A'.repeat(8193)}`);
  await expect(page.getByRole('alert')).toContainText(/too large|restart/i);
  expect(new URL(page.url()).hash).toBe('');
  expect(await page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey)).toBeNull();
  await page.goto('/delegate?transportVersion=2&ticket=retired-ticket');
  await expect(page.getByRole('alert')).toContainText(/unsupported|restart/i);
  expect(paths).not.toContain('/api/delegate/prepare');
});

test('v2 rejects a different requested key rather than invoking legacy prepare', async ({ page }) => {
  const calls = await setup(page, { keyId: 'different-key' });
  await expect(page.getByText(/requested signing key is not available/i)).toBeVisible();
  expect(calls.filter(c => c.path === '/api/delegate/prepare' || c.path === '/api/delegate/authorize-sign-prepare')).toHaveLength(0);
});

test('v2 permits choosing an account-matching key when no keyId was requested', async ({ page }) => {
  const second = { ...key, id: 'key-two', keyIndex: 1, label: 'Backup owner key', isPrimary: false };
  const calls = await setup(page, { keys: [key, second] });
  await expect(page.getByText('Choose an OpenKey signing key')).toBeVisible();
  await page.getByRole('button', { name: /Backup owner key/ }).click();
  await page.getByRole('button', { name: 'Preview signing message' }).click();
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  expect(calls.find(call => call.path === '/api/delegate/authorize-sign-prepare')?.body).toMatchObject({ keyId: second.id });
  const envelope = JSON.parse(Buffer.from(await page.locator('textarea').inputValue(), 'base64url').toString('utf8'));
  expect(envelope.selectedKeyId).toBe(second.id);
  expect(envelope.result).toEqual(rawResult);
});

test('v2 narrowing previews the exact candidate and never signs a second time', async ({ page }) => {
  const calls = await setup(page, { narrowed: true });
  await page.getByRole('checkbox', { name: 'tinycloud.kv/sync' }).uncheck();
  await page.getByRole('button', { name: 'Preview signing message' }).click();
  await expect(page.getByText(narrowedSiwe, { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  expect(calls.find(c => c.path === '/api/delegate/authorize-sign-preview')?.body).toMatchObject({ selectedActionIds: [fullKey], ticket: handoffId });
  expect(calls.find(c => c.path === '/api/delegate/authorize-sign')?.body).toMatchObject({ selectedActionIds: [fullKey], ticket: handoffId });
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

test('v2 failed callback offers the same signed result as paste without re-signing', async ({ page }) => {
  const callback = 'http://127.0.0.1:43210/callback/abcdefghijklmnopqrstuv';
  let attempted: unknown;
  await page.route(callback, route => {
    attempted = route.request().postDataJSON();
    return json(route, 422, { accepted: false });
  });
  const calls = await setup(page, { callback });
  await page.getByRole('button', { name: 'Preview signing message' }).click();
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.getByText(/Could not reach the CLI automatically/)).toBeVisible();
  const paste = JSON.parse(Buffer.from(await page.locator('textarea').inputValue(), 'base64url').toString('utf8'));
  expect(paste).toEqual(attempted);
  expect(paste.result).toEqual(rawResult);
  expect(calls.filter(call => call.path === '/api/delegate/authorize-sign')).toHaveLength(1);
});

test('v2 cancellation revokes the claimed handoff before signing', async ({ page }) => {
  const calls = await setup(page);
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByText(/Approval cancelled/)).toBeVisible();
  expect(calls.filter(c => c.path === '/api/delegate/handoffs/cancel-claimed')).toEqual([
    { path: '/api/delegate/handoffs/cancel-claimed', body: { ticket: handoffId } },
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

test('v2 wallet rejection leaves the unsigned ticket cancellable', async ({ page }) => {
  await page.addInitScript(({ owner }) => {
    Object.assign(window, { ethereum: { request: async ({ method }: { method: string }) => {
      if (method === 'eth_requestAccounts') return [owner];
      if (method === 'personal_sign') throw new Error('User rejected wallet approval');
      throw new Error(`Unexpected wallet call ${method}`);
    } } });
  }, { owner: address });
  const calls = await setup(page, { external: true });
  await page.getByRole('button', { name: 'Preview signing message' }).click();
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.getByText('User rejected wallet approval')).toBeVisible();
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByText(/Approval cancelled/)).toBeVisible();
  expect(calls.filter(call => call.path === '/api/delegate/authorize-sign')).toHaveLength(0);
  expect(calls.filter(call => call.path === '/api/delegate/handoffs/cancel-claimed')).toHaveLength(1);
});
