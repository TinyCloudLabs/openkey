// TC-3441 T8: the page a CLI opens to revoke a permission. It sits in the approval frame, shows the full permission
// ID in a box, names the key it signs with, gives the expiry in the viewer's own time, and ends in Cancel and Revoke.
// Every API call is answered by `page.route`; no API server runs.
import { test, expect, type Page, type Route } from '@playwright/test';
import { formatLocalAccessEnd } from '../../src/lib/access-end';

const address = '0x1111111111111111111111111111111111111111';
const cid = 'bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe';
const opaque = (seed: number) => Buffer.alloc(32, seed).toString('base64url');
const delivery = { handoffId: opaque(1), state: opaque(2), cancelSecret: opaque(3) };
const nonce = '0123456789abcdef0123456789abcdef';
const expiration = '2026-10-16T17:09:00.000Z';
const timeZone = 'Europe/Berlin';
const ownerKey = { id: 'key-owner', address, publicKey: '0x', keyIndex: 0, label: 'Owner wallet', keyType: 'MANAGED', createdAt: '2026-10-16T17:00:00.000Z' };
const secondKey = { ...ownerKey, id: 'key-second', keyIndex: 3, label: null };
const siwe = [
  'openkey.test wants you to sign in with your Ethereum account:', address, '', 'Revoke this permission.', '',
  `URI: ucan:${cid}`, 'Version: 1', 'Chain ID: 1', `Nonce: ${nonce}`,
  'Issued At: 2026-10-16T17:00:00.000Z', `Expiration Time: ${expiration}`,
].join('\n');
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

test.use({ viewport: { width: 390, height: 844 }, timezoneId: timeZone });

async function openReview(page: Page, keys: unknown[]): Promise<string[]> {
  const prepared: string[] = [];
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') {
      return json(route, { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'owner@example.test' } });
    }
    if (path === '/api/keys') return json(route, { keys });
    if (path === '/api/delegate/handoffs/available') return json(route, { transportVersion: 2 });
    if (path === '/api/delegate/handoffs/claim') return json(route, { transportVersion: 2, ticket: delivery.handoffId, expiresAt: new Date(Date.now() + 300_000).toISOString() });
    if (path === '/api/delegate/owner-revocation/prepare') {
      prepared.push(route.request().postDataJSON().keyId);
      return json(route, { authorizationContextToken: 'token', siwe });
    }
    return json(route, { error: `unmocked ${path}` }, 404);
  });
  const request = { kind: 'owner-revocation', ownerDid: `did:pkh:eip155:1:${address}`, cid, nonce, expiresAt: new Date(Date.now() + 590_000).toISOString() };
  await page.goto(`/delegate#tv2=${Buffer.from(JSON.stringify({ transportVersion: 2, request, delivery })).toString('base64url')}`);
  await expect(page.getByRole('heading', { level: 1, name: 'Revoke this permission' })).toBeVisible();
  return prepared;
}

/** The text of the row named `label` in the review's list of facts. */
const row = (page: Page, label: string) => page.locator('dl > div').filter({ has: page.locator('dt', { hasText: label }) }).locator('dd');

test('the review shows the full ID, names the key, gives a local expiry, and ends in Cancel and a dark Revoke at 390px', async ({ page }) => {
  await openReview(page, [ownerKey]);
  await expect(page.getByText('Request from your terminal')).toBeVisible();
  await expect(page.getByText('This cannot be undone.')).toBeVisible();
  await expect(page.getByText('Full permission ID', { exact: true })).toBeVisible();
  await expect(page.getByText(cid, { exact: true })).toBeVisible();
  await expect(page.getByText('Match the full permission ID with the one shown by your CLI.')).toBeVisible();
  await expect(page.getByText(`${cid.slice(0, 10)}…${cid.slice(-6)}`)).toHaveCount(0);

  await expect(row(page, 'Owner address')).toHaveText(address);
  await expect(row(page, 'Signing with')).toHaveText('Owner wallet');
  await expect(row(page, 'Signature expires')).toHaveText(formatLocalAccessEnd(expiration, timeZone));
  await expect(page.locator('summary', { hasText: 'Exact message to sign' })).toBeVisible();

  const cancel = page.getByRole('button', { name: 'Cancel', exact: true });
  const revoke = page.getByRole('button', { name: 'Revoke', exact: true });
  await expect(cancel).toBeVisible();
  await expect(revoke).toBeVisible();
  const cancelBox = (await cancel.boundingBox())!;
  const revokeBox = (await revoke.boundingBox())!;
  expect(cancelBox.x).toBeLessThan(revokeBox.x);
  const colour = (element: Element) => getComputedStyle(element).backgroundColor;
  expect(await revoke.evaluate(colour)).not.toBe(await cancel.evaluate(colour));
  expect(await cancel.evaluate(colour)).toBe('rgb(255, 255, 255)');

  await expect(page.getByRole('heading', { level: 1 })).toHaveCount(1);
  expect(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)).toBe(false);
});

test('with two matching keys the key list comes first, and nothing is prepared until one is chosen', async ({ page }) => {
  const prepared = await openReview(page, [ownerKey, secondKey]);
  const choose = page.getByRole('heading', { level: 2, name: 'Choose the owner signing key' });
  await expect(choose).toBeVisible();
  const warning = page.getByText('This cannot be undone.');
  expect((await choose.boundingBox())!.y).toBeLessThan((await warning.boundingBox())!.y);
  await expect(page.getByRole('button', { name: 'Revoke', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Cancel', exact: true })).toBeVisible();
  await expect(page.locator('summary', { hasText: 'Exact message to sign' })).toHaveCount(0);
  expect(prepared).toEqual([]);

  await page.getByRole('button', { name: /^Key 3/ }).click();
  await expect(page.getByRole('button', { name: 'Revoke', exact: true })).toBeVisible();
  expect(prepared).toEqual(['key-second']);
  await expect(row(page, 'Signing with')).toHaveText('Key 3');
  await expect(choose).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)).toBe(false);
});
