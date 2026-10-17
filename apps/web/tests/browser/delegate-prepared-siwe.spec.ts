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

async function setup(page: Page, options: { keyId?: string; callback?: string; narrowed?: boolean; external?: boolean; keys?: KeyFixture[]; siwe?: string; authenticated?: boolean; entry?: 'client' | 'hash' | 'conflict' } = {}) {
  const calls: Array<{ path: string; body: unknown }> = [];
  let preparedKeyId = key.id;
  await page.clock.setFixedTime(new Date('2026-10-16T17:00:00.000Z'));
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = route.request().postDataJSON?.() ?? {};
    calls.push({ path, body });
    if (path === '/api/auth/get-session') return json(route, 200, options.authenticated === false ? null : { session: { id: 's', userId: 'u', expiresAt: '2026-10-16T18:00:00.000Z' }, user: { id: 'u', email: 'owner@example.test' } });
    if (path === '/api/keys') return json(route, 200, { keys: options.keys ?? [{ ...key, keyType: options.external ? 'EXTERNAL' : 'MANAGED' }] });
    if (path === '/api/delegate/handoffs/available') return json(route, 200, { transportVersion: 2 });
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
  const url = `/delegate#tv2=${Buffer.from(JSON.stringify(input)).toString('base64url')}`;
  if (options.entry === 'conflict') {
    await page.goto(`/delegate?did=did:key:z6MkLegacy&jwk=${Buffer.from(JSON.stringify(jwk)).toString('base64url')}${url.slice('/delegate'.length)}`);
  } else if (options.entry) {
    await page.goto(options.entry === 'client' ? '/auth/login' : '/delegate?transportVersion=2');
    await page.evaluate(target => {
      const link = document.createElement('a');
      link.id = 'test-v2-link';
      link.href = target;
      link.textContent = 'Continue to prepared sign-in';
      document.body.append(link);
    }, url);
    await page.locator('#test-v2-link').click();
  } else {
    await page.goto(url);
  }
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

test('v2 explains an unavailable API before claiming and never enters legacy signing', async ({ page }) => {
  const calls = await setup(page, { authenticated: false });
  await expect(page.getByText('Sign in to review this request.')).toBeVisible();
  let claims = 0;
  await page.route('**/api/delegate/handoffs/available', route => json(route, 404, { error: 'Not found' }));
  await page.route('**/api/delegate/handoffs/claim', route => {
    claims++;
    return json(route, 404, { error: 'Not found' });
  });
  await page.route('**/api/auth/get-session', route => json(route, 200, {
    session: { id: 's', userId: 'u', expiresAt: '2026-10-16T18:00:00.000Z' },
    user: { id: 'u', email: 'owner@example.test' },
  }));
  await page.goto('/delegate?transportVersion=2');
  await expect(page.getByRole('alert')).toContainText('Prepared CLI sign-in is not available yet');
  expect(claims).toBe(0);
  expect(calls.filter(call => call.path === '/api/delegate/prepare' || call.path === '/api/delegate/authorize-sign')).toHaveLength(0);
  expect(await page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey)).toBeNull();
});

test('v2 keeps the cleared fragment only in tab storage through sign-in and removes it after claim', async ({ page }) => {
  const calls = await setup(page, { authenticated: false });
  await expect(page.getByText('Sign in to review this request.')).toBeVisible();
  expect(new URL(page.url()).hash).toBe('');
  expect(await page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey)).not.toBeNull();
  expect(calls.filter(call => call.path === '/api/delegate/handoffs/claim')).toHaveLength(0);
  await page.route('**/api/auth/get-session', route => json(route, 200, { session: { id: 's', userId: 'u', expiresAt: '2026-10-16T18:00:00.000Z' }, user: { id: 'u', email: 'owner@example.test' } }));
  await page.goto('/delegate?transportVersion=2');
  await expect(page.getByText('Only approve if you started this sign-in yourself on your own computer.')).toBeVisible();
  expect(await page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey)).toBeNull();
  expect(calls.filter(call => call.path === '/api/delegate/handoffs/claim')).toHaveLength(1);
});

for (const continuation of ['same-tab', 'auth-return'] as const) {
  test(`auth refresh on a signed-out request waits for deliberate ${continuation} continuation`, async ({ page }) => {
    const calls = await setup(page, { authenticated: false });
    await expect(page.getByText('Sign in to review this request.')).toBeVisible();
    await page.route('**/api/auth/get-session', route => json(route, 200, {
      session: { id: 's', userId: 'u', expiresAt: '2026-10-16T18:00:00.000Z' },
      user: { id: 'u', email: 'owner@example.test' },
    }));
    await page.evaluate(async () => {
      const modulePath = '/src/lib/auth-client.ts';
      const { authClient } = await import(modulePath);
      authClient.$store.notify('$sessionSignal');
    });
    await expect(page.getByRole('button', { name: 'Continue to approval' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Cancel' })).toBeVisible();
    expect(calls.filter(call => call.path === '/api/delegate/handoffs/claim')).toHaveLength(0);
    if (continuation === 'same-tab') await page.getByRole('button', { name: 'Continue to approval' }).click();
    else await page.goto('/delegate?transportVersion=2');
    await expect(page.getByText('Only approve if you started this sign-in yourself on your own computer.')).toBeVisible();
    expect(calls.filter(call => call.path === '/api/delegate/handoffs/claim')).toHaveLength(1);
  });
}

for (const entry of ['client', 'hash', 'conflict'] as const) {
  test(`v2 ${entry} navigation scrubs fragment and never enters legacy approval`, async ({ page }) => {
    const calls = await setup(page, { entry });
    await expect(page.getByText('Only approve if you started this sign-in yourself on your own computer.')).toBeVisible();
    expect(new URL(page.url()).hash).toBe('');
    expect(await page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey)).toBeNull();
    expect(calls.filter(call => call.path === '/api/delegate/handoffs/claim')).toHaveLength(1);
    expect(calls.filter(call => call.path === '/api/delegate/prepare')).toHaveLength(0);
  });
}

test('an explicit v1 link replaces pending v2 after sign-in', async ({ page }) => {
  await setup(page, { authenticated: false });
  await expect(page.getByText('Sign in to review this request.')).toBeVisible();
  const legacyJwk = Buffer.from(JSON.stringify(jwk)).toString('base64url');
  await page.goto(`/delegate?did=did:key:z6MkLegacy&jwk=${legacyJwk}`);
  await expect.poll(() => page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey)).toBeNull();
  await expect(page.getByText('Prepared CLI sign-in')).toHaveCount(0);

  await page.route('**/api/auth/get-session', route => json(route, 200, {
    session: { id: 's', userId: 'u', expiresAt: '2026-10-16T18:00:00.000Z' },
    user: { id: 'u', email: 'owner@example.test' },
  }));
  const prepared: unknown[] = [];
  await page.route('**/api/delegate/prepare', route => {
    prepared.push(route.request().postDataJSON());
    return json(route, 200, {
      prepared: { siwe, spaceId: space, jwk }, spaceId: space,
      ownerDid: `did:pkh:eip155:1:${address}`, address, chainId: 1, host,
      permissions: [{ key: `tinycloud.kv\0${space}\0notes/`, service: 'kv', path: 'notes/',
        label: 'kv', resourcePath: 'kv/notes/', actions: [
          { key: fullKey, action: 'get', ability: 'tinycloud.kv/get', required: false },
          { key: syncKey, action: 'sync', ability: 'tinycloud.kv/sync', required: false },
        ] }],
      selectedActionKeys: [fullKey, syncKey], edited: false,
      authorizationContext: { token: 'legacy-context', expiresAt: Date.now() + 300_000, baselineAbilitiesDigest: 'digest' },
    });
  });
  await page.reload();
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
  expect(prepared).toEqual([expect.objectContaining({ jwk, host })]);
  expect(await page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey)).toBeNull();
});

test('a newly navigated v2 fragment replaces the previous pending request', async ({ page }) => {
  await setup(page, { authenticated: false });
  const first = await page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey);
  expect(first).not.toBeNull();
  const replacement = JSON.parse(Buffer.from(first!.slice(5), 'base64url').toString('utf8'));
  replacement.delivery.handoffId = 'D'.repeat(43);
  replacement.delivery.state = 'E'.repeat(43);
  replacement.delivery.cancelSecret = 'F'.repeat(43);
  const fragment = `#tv2=${Buffer.from(JSON.stringify(replacement)).toString('base64url')}`;
  await page.evaluate(value => {
    const link = document.createElement('a');
    link.id = 'replacement-v2-link';
    link.href = `/delegate${value}`;
    link.textContent = 'New prepared sign-in';
    document.body.append(link);
  }, fragment);
  await page.locator('#replacement-v2-link').click();
  await expect(page.getByText('Sign in to review this request.')).toBeVisible();
  expect(new URL(page.url()).hash).toBe('');
  expect(await page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey)).toBe(fragment);
});

test('a failed new-fragment storage write cannot resume the previous request', async ({ page }) => {
  const calls = await setup(page, { authenticated: false });
  const previous = await page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey);
  expect(previous).not.toBeNull();
  const replacement = JSON.parse(Buffer.from(previous!.slice(5), 'base64url').toString('utf8'));
  replacement.delivery.handoffId = 'D'.repeat(43);
  const fragment = `#tv2=${Buffer.from(JSON.stringify(replacement)).toString('base64url')}`;
  await page.evaluate(({ value, storageKey }) => {
    const original = Storage.prototype.setItem;
    Storage.prototype.setItem = function (key: string, data: string) {
      if (key === storageKey && data === value) throw new DOMException('Storage full', 'QuotaExceededError');
      return original.call(this, key, data);
    };
    const link = document.createElement('a');
    link.href = `${location.pathname}${location.search}${value}`;
    link.textContent = 'Replace prepared sign-in';
    document.body.append(link);
  }, { value: fragment, storageKey: pendingKey });
  await page.getByRole('link', { name: 'Replace prepared sign-in' }).click();
  await expect(page.getByRole('alert')).toContainText(/couldn.t save this request|restart/i);
  expect(new URL(page.url()).hash).toBe('');
  await expect.poll(() => page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey).catch(() => 'navigating')).toBeNull();
  expect(calls.filter(call => call.path === '/api/delegate/handoffs/claim')).toHaveLength(0);
  await page.reload();
  await expect(page.getByRole('alert')).toContainText(/couldn.t save this request|restart/i);
});

test('the document bootstrap also discards a previous request when storage replacement fails', async ({ page }) => {
  const calls = await setup(page, { authenticated: false });
  const previous = await page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey);
  expect(previous).not.toBeNull();
  const replacement = JSON.parse(Buffer.from(previous!.slice(5), 'base64url').toString('utf8'));
  replacement.delivery.handoffId = 'D'.repeat(43);
  const fragment = `#tv2=${Buffer.from(JSON.stringify(replacement)).toString('base64url')}`;
  await page.addInitScript(({ value, storageKey }) => {
    const original = Storage.prototype.setItem;
    Storage.prototype.setItem = function (key: string, data: string) {
      if (key === storageKey && data === value) throw new DOMException('Storage full', 'QuotaExceededError');
      return original.call(this, key, data);
    };
  }, { value: fragment, storageKey: pendingKey });
  await page.goto(`/delegate${fragment}`);
  await expect(page.getByRole('alert')).toContainText(/couldn.t save this request|restart/i);
  expect(new URL(page.url()).hash).toBe('');
  expect(await page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey)).toBeNull();
  expect(calls.filter(call => call.path === '/api/delegate/handoffs/claim')).toHaveLength(0);
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

for (const fullReload of [false, true]) {
  test(`pending v2 tab data expires during ${fullReload ? 'full-document' : 'client'} sign-in navigation`, async ({ page }) => {
    const calls = await setup(page, { authenticated: false });
    await expect(page.getByText('Sign in to review this request.')).toBeVisible();
    if (!fullReload) await page.evaluate(() => { (window as Window & { __sameDocument?: boolean }).__sameDocument = true; });
    await page.getByRole('link', { name: 'Continue with email' }).click();
    await expect(page).toHaveURL(/\/auth\/login\?redirect=/);
    if (!fullReload) expect(await page.evaluate(() => (window as Window & { __sameDocument?: boolean }).__sameDocument)).toBe(true);
    const returnTo = new URL(page.url()).searchParams.get('redirect');
    expect(returnTo).toBe('/delegate?transportVersion=2');
    if (fullReload) await page.reload();
    expect(await page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey)).not.toBeNull();
    await page.clock.fastForward(300_001);
    await expect.poll(() => page.evaluate(storageKey => sessionStorage.getItem(storageKey), pendingKey)).toBeNull();
    await page.goto(returnTo!);
    await expect(page.getByRole('alert')).toContainText(/unsupported|restart/i);
    expect(calls.filter(call => call.path === '/api/delegate/handoffs/claim')).toHaveLength(0);
  });
}

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
