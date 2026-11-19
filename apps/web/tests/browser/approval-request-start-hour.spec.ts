// A signed approval request starts the owner's choice at one hour, however long its signed maximum is, or at
// what it asked for when that is shorter. Every API call is answered by `page.route`; no API server runs.
import { test, expect, type Page, type Route } from '@playwright/test';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const id = 'abcdefghijklmnopqrstuvwxyz';
const fragment = `#v=4&k=${'A'.repeat(43)}&c=bafkreia${'a'.repeat(52)}`;
const path = `/a/${id}`;
const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const CAPS_READ = 'tinycloud.capabilities/read';
const KV_GET = 'tinycloud.kv/get';
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

function prepared() {
  const siwe = [
    'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
    'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-03T00:00:00.000Z', 'Expiration Time: 2026-11-03T01:00:00.000Z',
    'Resources:',
    `- ${makeRecapResource({ [`${space}/capabilities`]: { [CAPS_READ]: [{}] }, [`${space}/kv/notes/`]: { [KV_GET]: [{}] } })}`,
  ].join('\n');
  const option = (service: string, short: string, p: string, ability: string, required: boolean) => {
    const optionKey = `${service}\0${space}\0${p}`;
    return { key: optionKey, service: short, path: p, label: short, resourcePath: p ? `${short}/${p}` : short,
      actions: [{ key: `${optionKey}\0${ability}`, action: ability.split('/')[1], ability, required }] };
  };
  const permissions = [option('tinycloud.capabilities', 'capabilities', '', CAPS_READ, true), option('tinycloud.kv', 'kv', 'notes/', KV_GET, false)];
  return {
    prepared: { siwe, spaceId: space, jwk: {} }, spaceId: space, ownerDid: `did:pkh:eip155:1:${address}`, address, chainId: 1,
    host: 'https://node.tinycloud.xyz', permissions, selectedActionKeys: permissions.flatMap((p) => p.actions.map((a) => a.key)), edited: false,
    authorizationContext: { token: 't', expiresAt: Date.now() + 600_000, baselineAbilitiesDigest: 'd' },
  };
}

/** Opens the review for a signed request and returns the `expiry` each preview asked the server to prepare. */
async function openReview(page: Page, lifetime: { grantLifetimeSeconds: number; suggestedLifetimeSeconds?: number }) {
  const expiries: unknown[] = [];
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === '/api/auth/get-session') {
      return json(route, 200, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'owner@example.test' } });
    }
    if (url.pathname === '/api/keys') {
      return json(route, 200, { keys: [{ id: 'key_0', address, publicKey: '0x', keyIndex: 0, label: null, keyType: 'MANAGED', isPrimary: true, createdAt: new Date().toISOString() }] });
    }
    if (url.pathname === `/api/approval-requests/${id}/load`) {
      const requested = { targetDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) },
        nodeOrigin: 'https://node.tinycloud.xyz', permissions: [{ service: 'tinycloud.kv', space, path: 'notes/', actions: [KV_GET] }],
        reason: 'Read notes', ...lifetime };
      return json(route, 200, { requestId: id, expiresAt: new Date(Date.now() + 3600_000).toISOString(), approved: false, denied: false, request: requested });
    }
    if (url.pathname === '/api/delegate/prepare') {
      const body: unknown = request.postDataJSON?.() ?? null;
      expiries.push(typeof body === 'object' && body !== null && 'expiry' in body ? body.expiry : undefined);
      return json(route, 200, prepared());
    }
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });
  await page.goto(path + fragment);
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
  return expiries;
}

test.describe('a signed approval request starts at one hour at most', () => {
  test('a request that asks for 7 days and suggests nothing is prepared for one hour', async ({ page }) => {
    const expiries = await openReview(page, { grantLifetimeSeconds: 7 * 86_400 });
    expect(expiries.length).toBeGreaterThan(0);
    expect(expiries.every((expiry) => expiry === '3600s')).toBe(true);
  });

  test('a request that asks for 30 minutes keeps its 30 minutes', async ({ page }) => {
    const expiries = await openReview(page, { grantLifetimeSeconds: 1800 });
    expect(expiries.length).toBeGreaterThan(0);
    expect(expiries.every((expiry) => expiry === '1800s')).toBe(true);
  });

  test('a suggestion above an hour is not the start either', async ({ page }) => {
    const expiries = await openReview(page, { grantLifetimeSeconds: 30 * 86_400, suggestedLifetimeSeconds: 7 * 86_400 });
    expect(expiries.length).toBeGreaterThan(0);
    expect(expiries.every((expiry) => expiry === '3600s')).toBe(true);
  });
});
