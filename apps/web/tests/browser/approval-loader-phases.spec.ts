// TC-3441 T1: the link phase of the loader on an approval link (/a/…) and on a device link, and one card height
// through every phase.
import { test, expect, type Page } from '@playwright/test';
import { approvalLink, mockApi } from './approval-end-pages-fixtures';

const deferred = () => Promise.withResolvers<void>();
const lit = (page: Page) => page.locator('[role="status"] [aria-current="step"]');
const phases = (page: Page) => page.locator('[role="status"] li');
const cardHeight = async (page: Page) => (await page.getByRole('main').boundingBox())!.height;
const allPhases = ['Checking the link', 'Checking your OpenKey account', 'Loading your keys', 'Preparing the request'];

test('an approval link lights "Checking the link" first, then each phase in turn, and the card keeps its height', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  const load = deferred();
  const session = deferred();
  const keys = deferred();
  const prepare = deferred();
  await mockApi(page, { signedIn: true, loadHeld: load.promise, sessionHeld: session.promise, keysHeld: keys.promise, prepareHeld: prepare.promise });
  await page.goto(approvalLink);

  await expect(page.getByRole('heading', { level: 1, name: 'Opening your request' })).toBeVisible();
  await expect(phases(page)).toHaveText(allPhases);
  await expect(lit(page)).toHaveText('Checking the link');
  const heights = [await cardHeight(page)];

  load.resolve();
  await expect(lit(page)).toHaveText('Checking your OpenKey account');
  await expect(phases(page)).toHaveText(allPhases);
  heights.push(await cardHeight(page));

  session.resolve();
  await expect(lit(page)).toHaveText('Loading your keys');
  heights.push(await cardHeight(page));

  keys.resolve();
  await expect(lit(page)).toHaveText('Preparing the request');
  heights.push(await cardHeight(page));

  expect(new Set(heights).size).toBe(1);
  prepare.resolve();
  await expect(page.getByRole('heading', { name: 'Opening your request' })).toHaveCount(0);
});

test('a device link lights "Checking the link" while the device request is looked up', async ({ page }) => {
  const lookup = deferred();
  await mockApi(page, { signedIn: true });
  await page.route('**/api/device-authorizations/lookup**', async (route) => {
    await lookup.promise;
    await route.fulfill({ status: 404, contentType: 'application/json', body: '{}' });
  });
  const jwk = Buffer.from(JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) })).toString('base64url');
  await page.goto(`/delegate?did=did:key:z6Mk&jwk=${jwk}&deviceTransactionId=device-fixture&deviceUserCode=ABCD-EFGH`);

  await expect(page.getByRole('heading', { level: 1, name: 'Opening your request' })).toBeVisible();
  await expect(phases(page)).toHaveText(allPhases);
  await expect(lit(page)).toHaveText('Checking the link');
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(0);
  lookup.resolve();
  await expect(page.getByRole('heading', { name: 'Opening your request' })).toHaveCount(0);
});
