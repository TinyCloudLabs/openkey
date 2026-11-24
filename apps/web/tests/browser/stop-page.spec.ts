import { expect, test, type Page, type Route } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';
import { TERMS_ACCEPTED } from './terms-fixtures';

const email = 'owner@example.test';
const wanted = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const address = '0x2222222222222222222222222222222222222222';
const key = { id: 'key-1', keyIndex: 1, label: 'Key 1', address, publicKey: '0x', keyType: 'MANAGED', isPrimary: true };
const jwk = encodeBase64UrlJson({ kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) });
const link = `/delegate?did=did:key:requester&jwk=${jwk}`;
const walletLink = `${link}&permissions=${encodeBase64UrlJson({ permissions: [
  { service: 'tinycloud.kv', space: `tinycloud:pkh:eip155:1:${wanted}:default`, path: 'notes/', actions: ['tinycloud.kv/get'] },
] })}`;
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const ability = 'tinycloud.kv/get';
const option = `tinycloud.kv\0${space}\0notes/`;
const action = `${option}\0${ability}`;

function siwe(issuedAt: Date) {
  return [
    'requester.example.test wants you to sign in with your Ethereum account:', address, '',
    '',
    'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', `Issued At: ${issuedAt.toISOString()}`,
    `Expiration Time: ${new Date(issuedAt.getTime() + 3_600_000).toISOString()}`, 'Resources:',
    `- ${makeRecapResource({ [`${space}/kv/notes/`]: { [ability]: [{}] } })}`,
  ].join('\n');
}

function prepared() {
  return {
    prepared: { siwe: siwe(new Date()), spaceId: space, jwk: {} }, spaceId: space, address, chainId: 1,
    permissions: [{ key: option, service: 'kv', path: 'notes/', label: 'kv', resourcePath: 'kv/notes/',
      actions: [{ key: action, action: 'get', ability, required: true }] }],
    selectedActionKeys: [action], authorizationContext: { token: 'context' },
  };
}

const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, json: body });

async function mock(page: Page, respond?: (path: string, route: Route) => Promise<void> | undefined) {
  const calls: string[] = [];
  let signedIn = true;
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    calls.push(path);
    if (path === '/api/auth/get-session') {
      return json(route, 200, signedIn ? {
        session: { id: 's', userId: 'owner', expiresAt: new Date(Date.now() + 3_600_000).toISOString() },
        user: { id: 'owner', email, name: 'Owner' },
      } : null);
    }
    if (path === '/api/auth/sign-out') {
      signedIn = false;
      return json(route, 200, { success: true });
    }
    if (path === '/api/keys') return json(route, 200, { keys: [key] });
    return respond?.(path, route) ?? json(route, 404, {});
  });
  await page.route('**/api/account/terms', (route) => route.fulfill({ json: TERMS_ACCEPTED }));
  return calls;
}

test('a cut-off link stops in the approval frame before sign-in, keys or preparation', async ({ page }) => {
  const calls = await mock(page);
  await page.goto('/delegate?did=did:key:requester');
  const stop = page.getByTestId('stop-page');
  const heading = stop.getByRole('heading', { name: 'This link is cut off' });
  await expect(heading).toBeFocused();
  await expect(page.getByText('Sign in · stopped', { exact: true })).toBeVisible();
  await expect(stop.getByText('Nothing was approved', { exact: true })).toBeVisible();
  await expect(stop.getByRole('button', { name: 'Close this tab' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Continue with email' })).toHaveCount(0);
  expect(calls.filter((path) => path === '/api/keys' || path.startsWith('/api/delegate'))).toEqual([]);
});

test('a missing wallet shows both addresses and switches account without changing the link', async ({ page }) => {
  const calls = await mock(page);
  await page.goto(walletLink);
  const stop = page.getByTestId('stop-page');
  await expect(stop.getByRole('heading', { name: 'This request is for a wallet this account doesn’t have' })).toBeVisible();
  await expect(stop.getByTestId('wallet-comparison')).toContainText('0xd559…f412');
  await expect(stop.getByTestId('wallet-comparison')).toContainText('0x2222…2222');
  await expect(stop.getByText('Go back to the app or terminal and start again with a different profile.')).toBeVisible();
  await stop.getByRole('button', { name: 'Switch account' }).click();
  await expect(page.getByRole('link', { name: 'Continue with email' })).toBeVisible();
  expect(new URL(page.url()).pathname + new URL(page.url()).search).toBe(walletLink);
  expect(calls).toContain('/api/auth/sign-out');
  expect(calls).not.toContain('/api/delegate/prepare');
});

test('a missing wallet can be linked from the Stop page', async ({ page }) => {
  await mock(page);
  await page.goto(walletLink);
  await page.getByRole('button', { name: 'Link wallet 0xd559…f412' }).click();
  await expect(page.getByRole('heading', { name: 'Link External Wallet' })).toBeVisible();
});

test('a key-deletion refusal replaces the key picker', async ({ page }) => {
  await mock(page, (path, route) => path === '/api/delegate/prepare'
    ? json(route, 403, { code: 'key_delete_not_grantable', error: 'raw refusal' }) : undefined);
  await page.goto(link);
  await expect(page.getByRole('heading', { name: 'Apps can’t be given permission to delete keys' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Key 1' })).toHaveCount(0);
  await expect(page.getByText('raw refusal')).toHaveCount(0);
});

test('a malformed permission list shows the developer detail as plain text', async ({ page, context }) => {
  const detail = '<strong>Invalid permission</strong>';
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await mock(page, (path, route) => path === '/api/delegate/prepare'
    ? json(route, 400, { code: 'invalid_permissions', message: detail }) : undefined);
  await page.goto(link);
  const stop = page.getByTestId('stop-page');
  await expect(stop.getByRole('heading', { name: 'The app’s request has a mistake in it' })).toBeVisible();
  await expect(stop.getByText(detail, { exact: true })).toBeVisible();
  await expect(stop.locator('strong')).toHaveCount(0);
  await expect(stop.locator('[data-support-line]')).toHaveText('HTTP 400 · invalid_permissions');
  await stop.getByRole('button', { name: 'Copy details for the developer' }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(`HTTP 400 · invalid_permissions · ${detail}`);
});

test('Try again resends the approval and the support button copies only status and code', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  let attempts = 0;
  await mock(page, (path, route) => {
    if (path === '/api/delegate/prepare') return json(route, 200, prepared());
    if (path === '/api/delegate') {
      attempts++;
      return attempts === 1 ? json(route, 500, { code: 'internal_error', error: 'raw internal error' })
        : json(route, 200, { hostActivated: true });
    }
  });
  await page.goto(link);
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  const stop = page.getByTestId('stop-page');
  await expect(stop.getByRole('heading', { name: 'The approval didn’t go through' })).toBeVisible();
  await stop.getByRole('button', { name: /Details for support/ }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('HTTP 500 · internal_error');
  await expect(stop.getByText('Copied', { exact: true })).toBeVisible();
  await stop.getByRole('button', { name: 'Try again' }).click();
  await expect(page.getByRole('heading', { name: 'Paste this into your terminal' })).toBeVisible();
  expect(attempts).toBe(2);
});

test('an already answered approval shows the Nothing new marker and removes Approve', async ({ page }) => {
  await mock(page, (path, route) => {
    if (path === '/api/delegate/prepare') return json(route, 200, prepared());
    if (path === '/api/delegate') return json(route, 410, { code: 'handoff_consumed' });
  });
  await page.goto(link);
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'This request was already answered' })).toBeVisible();
  await expect(page.getByText('Nothing new was approved', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(0);
});

test('a rate-limited prepared claim shows the shared Stop copy', async ({ page }) => {
  const now = new Date();
  const calls = await mock(page, (path, route) => {
    if (path === '/api/delegate/handoffs/available') return json(route, 200, { transportVersion: 2 });
    if (path === '/api/delegate/handoffs/claim') return json(route, 429, { code: 'rate_limited', error: 'Too many handoffs for this account' });
  });
  const input = {
    transportVersion: 2,
    request: { protocolVersion: 1, siwe: siwe(now), host: 'https://node.example.test', sessionDid: 'did:key:requester',
      jwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) } },
    delivery: { handoffId: 'B'.repeat(43), state: 'A'.repeat(43), cancelSecret: 'C'.repeat(43) },
  };
  await page.goto(`/delegate#tv2=${Buffer.from(JSON.stringify(input)).toString('base64url')}`);
  await expect(page.getByRole('heading', { name: 'Too many sign-in requests' })).toBeVisible();
  await expect(page.getByText('Too many handoffs for this account')).toHaveCount(0);
  await expect(page.locator('[data-support-line]')).toHaveText('HTTP 429 · rate_limited');
  expect(calls.filter((path) => path.endsWith('/claim'))).toHaveLength(1);
});

const cancelClaimed = '/api/delegate/handoffs/cancel-claimed';

async function openHandoffStop(page: Page, options: { revoke?: boolean; unreadable?: boolean } = {}) {
  await page.addInitScript((path) => {
    const fetchReply = window.fetch;
    window.fetch = (input, init) => {
      if (typeof input === 'string' && new URL(input, location.href).pathname === path) {
        const attempts = JSON.parse(sessionStorage.getItem('test-cancel-attempts') ?? '[]');
        attempts.push(init?.keepalive ?? false);
        sessionStorage.setItem('test-cancel-attempts', JSON.stringify(attempts));
      }
      return fetchReply(input, init);
    };
  }, cancelClaimed);
  const now = new Date();
  const message = siwe(now);
  const handoffId = 'B'.repeat(43);
  const state = 'A'.repeat(43);
  const expiresAt = new Date(now.getTime() + 300_000).toISOString();
  const { revoke, unreadable } = options;
  const calls = await mock(page, (path, route) => {
    if (path.endsWith('/available')) return json(route, 200, { transportVersion: 2 });
    if (path.endsWith('/claim')) return json(route, 201, { transportVersion: 2, ticket: handoffId, expiresAt });
    if (path.endsWith('/authorize-sign-prepare') || path.endsWith('/owner-revocation/prepare')) {
      return json(route, 200, { authorizationContextToken: 'bound-context', siwe: message });
    }
    if (path.endsWith('/authorize-sign-preview')) {
      return json(route, 200, {
        signedMessage: message, previewApprovalToken: 'preview', selectedActionKeys: [action],
        permissions: [{ service: 'tinycloud.kv', space, path: 'notes/', actions: [ability] }],
      });
    }
    if (path.endsWith('/authorize-sign') || path.endsWith('/owner-revocation/sign')) {
      return unreadable ? json(route, 200, {}) : json(route, 500, { code: 'sign_failed' });
    }
    if (path === cancelClaimed) {
      expect(route.request().postDataJSON()).toEqual({ ticket: handoffId });
      return json(route, 503, {});
    }
  });
  const request = revoke ? {
    kind: 'owner-revocation', ownerDid: `did:pkh:eip155:1:${address}`,
    cid: 'bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe',
    nonce: '0123456789abcdef0123456789abcdef', expiresAt,
  } : {
    protocolVersion: 1, siwe: message, host: 'https://node.example.test', sessionDid: 'did:key:requester',
    jwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) },
  };
  const input = { transportVersion: 2, request, delivery: { handoffId, state, cancelSecret: 'C'.repeat(43) } };
  await page.goto(`/delegate#tv2=${Buffer.from(JSON.stringify(input)).toString('base64url')}`);
  if (!revoke) await page.getByRole('button', { name: 'Preview signing message' }).click();
  await page.getByRole('button', { name: revoke ? 'Revoke' : 'Approve', exact: true }).click();
  await expect(page.getByRole('heading', {
    name: unreadable ? 'OpenKey couldn’t finish this request' : 'The approval didn’t go through',
  })).toBeVisible();
  return calls;
}

test('Close this tab cancels a released sign-in even if cancellation fails', async ({ page }) => {
  const calls = await openHandoffStop(page);
  const response = page.waitForResponse((reply) => new URL(reply.url()).pathname === cancelClaimed);
  await page.getByRole('button', { name: 'Close this tab' }).click();
  expect((await response).status()).toBe(503);
  await expect(page.getByText('Your browser kept this tab open. Close it from your browser.')).toBeVisible();
  await page.goto('/__parity_harness');
  expect(calls.filter((path) => path === cancelClaimed)).toHaveLength(1);
  expect(await page.evaluate(() => sessionStorage.getItem('test-cancel-attempts'))).toBe('[true]');
});

test('leaving a released revocation sends cancel-claimed with keepalive', async ({ page }) => {
  await openHandoffStop(page, { revoke: true });
  await page.goto('/__parity_harness');
  expect(await page.evaluate(() => sessionStorage.getItem('test-cancel-attempts'))).toBe('[true]');
});

test('closing or leaving an unreadable signing reply never cancels the claim', async ({ page }) => {
  const calls = await openHandoffStop(page, { unreadable: true });
  await page.getByRole('button', { name: 'Close this tab' }).click();
  await expect(page.getByText('Your browser kept this tab open. Close it from your browser.')).toBeVisible();
  await page.goto('/__parity_harness');
  expect(calls).not.toContain(cancelClaimed);
  expect(await page.evaluate(() => sessionStorage.getItem('test-cancel-attempts'))).toBeNull();
});
