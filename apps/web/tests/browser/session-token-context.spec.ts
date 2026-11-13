import { test, expect, type Page, type Route } from '@playwright/test';

const address = '0x1111111111111111111111111111111111111111';
const cid = 'bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe';
const opaque = (seed: number) => Buffer.alloc(32, seed).toString('base64url');
const delivery = { handoffId: opaque(1), state: opaque(2), cancelSecret: opaque(3) };
const key = { id: 'key-owner', address, publicKey: '0x', keyIndex: 0, label: 'Owner wallet', keyType: 'EXTERNAL', createdAt: '2026-10-16T17:00:00.000Z' };
const nonce = '0123456789abcdef0123456789abcdef';
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

const ownerSiwe = (statement: string) => [
  `openkey.test wants you to sign in with your Ethereum account:`, address, '', statement, '',
  `URI: ucan:${cid}`, 'Version: 1', 'Chain ID: 1', `Nonce: ${nonce}`,
  'Issued At: 2026-10-16T17:00:00.000Z', 'Expiration Time: 2026-10-16T17:09:00.000Z',
].join('\n');

interface Shown { text: string | null; innerText: string; picture: Buffer }

async function exactMessage(page: Page, siwe: string): Promise<Shown> {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') {
      return json(route, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'owner@example.test' } });
    }
    if (path === '/api/keys') return json(route, { keys: [key] });
    if (path === '/api/delegate/handoffs/available') return json(route, { transportVersion: 2 });
    if (path === '/api/delegate/handoffs/claim') return json(route, { transportVersion: 2, ticket: delivery.handoffId, expiresAt: new Date(Date.now() + 300_000).toISOString() });
    if (path === '/api/delegate/owner-revocation/prepare') return json(route, { authorizationContextToken: 'token', siwe });
    return json(route, { error: `unmocked ${path}` }, 404);
  });
  const request = { kind: 'owner-revocation', ownerDid: `did:pkh:eip155:1:${address}`, cid, nonce, expiresAt: new Date(Date.now() + 590_000).toISOString() };
  await page.goto(`/delegate#tv2=${Buffer.from(JSON.stringify({ transportVersion: 2, request, delivery })).toString('base64url')}`);
  await expect(page.getByText('Exact message to sign')).toBeVisible();
  const block = page.locator('pre');
  await expect(block).toBeVisible();
  // Take two pictures with every line in view: one at the left edge and one at the right edge.
  await block.evaluate((element) => { element.scrollLeft = 0; });
  const left = await block.screenshot();
  await block.evaluate((element) => { element.scrollLeft = element.scrollWidth; });
  const right = await block.screenshot();
  return { text: await block.textContent(), innerText: await block.innerText(), picture: Buffer.concat([left, right]) };
}

test('top-level owner revocation ignores a stale bearer and uses the cookie session', async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'stale-other-account'));
  const requests: Array<string | undefined> = [];
  page.on('request', request => {
    if (new URL(request.url()).pathname === '/api/delegate/owner-revocation/prepare') requests.push(request.headers()['authorization']);
  });
  await exactMessage(page, ownerSiwe('Revoke this permission.'));
  expect(requests).toEqual([undefined]);
});

test('session bearer persistence is confined to embedded frames', async ({ page }) => {
  await page.goto('/auth/login');
  const persist = async () => {
    const module = await import(/* @vite-ignore */ ('/src/lib/embed-passkey.ts' as string));
    sessionStorage.removeItem('openkey_session_token');
    module.setSessionToken('embedded-session');
    return sessionStorage.getItem('openkey_session_token');
  };
  expect(await page.evaluate(persist)).toBeNull();
  await page.evaluate(() => {
    const frame = document.createElement('iframe');
    frame.id = 'token-test';
    frame.src = '/auth/login';
    document.body.append(frame);
  });
  const frame = page.frameLocator('#token-test');
  await expect(frame.locator('body')).toBeVisible();
  const child = page.frames().find(frame => frame.parentFrame() !== null)!;
  expect(await child.evaluate(persist)).toBe('embedded-session');
});
