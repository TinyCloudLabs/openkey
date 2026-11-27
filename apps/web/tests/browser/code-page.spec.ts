// The code page: one page for every code the person pastes into a terminal. The box is the copy target, the
// short code counts down and runs out, and the full code is one tap away. Every API call is answered by
// `page.route`; no API server runs. The clipboard is recorded, not the real one.

import { test, expect, type Page } from '@playwright/test';
import { address, delegateLink, json, mockApi, preparedLink, revokeLink } from './approval-end-pages-fixtures';
import { approve, callback, cors, delegation, lastCopied, mintShortCode, recordClipboard, refuseShortCode } from './approval-code-fixtures';

const box = (page: Page) => page.locator('[data-code-box]');

async function openCodePage(page: Page, options: { link?: string; mint?: (page: Page) => Promise<void>; failCopy?: boolean } = {}) {
  await recordClipboard(page, options.failCopy);
  await mockApi(page, { signedIn: true, approveReply: { status: 200, body: delegation } });
  await (options.mint ?? mintShortCode)(page);
  await page.goto(options.link ?? delegateLink);
  await approve(page);
}

async function expectNoAmber(page: Page) {
  expect(await page.locator('[class*="amber"]').count()).toBe(0);
}

test('the box copies the short code on click and on Enter, and so does Copy code', async ({ page }) => {
  await openCodePage(page);
  await expect(page.getByRole('heading', { name: 'Paste this code into your terminal' })).toBeVisible();
  await expect(page.getByText('TinyCloud CLI is waiting for it.')).toBeVisible();
  await expect(page.getByRole('timer')).toContainText('Valid for 5:00');

  await box(page).click();
  expect(await lastCopied(page)).toBe('SF23-22CS');
  await expect(box(page)).toContainText('Copied. Now paste it in your terminal.');

  await page.evaluate(() => (Reflect.get(window, '__copied') as string[]).splice(0));
  await box(page).focus();
  await page.keyboard.press('Enter');
  await expect.poll(() => lastCopied(page)).toBe('SF23-22CS');

  await page.evaluate(() => (Reflect.get(window, '__copied') as string[]).splice(0));
  await page.getByRole('button', { name: /^(Copy code|Copied)$/ }).click();
  await expect.poll(() => lastCopied(page)).toBe('SF23-22CS');
  await expectNoAmber(page);
});

test('the full code, once opened, copies the delegation the API returned', async ({ page }) => {
  await openCodePage(page);
  await page.getByRole('button', { name: 'Use the full delegation code instead' }).click();
  await expect(page.getByRole('heading', { name: 'Paste this into your terminal' })).toBeVisible();
  await box(page).click();
  const full = await lastCopied(page);
  expect(JSON.parse(Buffer.from(full!, 'base64').toString('utf8'))).toEqual(delegation);
  await expect(page.getByRole('timer')).toHaveCount(0);
});

test('when no short code can be made, the full code is the page and the reason sits in the support line', async ({ page }) => {
  await openCodePage(page, { mint: refuseShortCode });
  await expect(page.getByRole('heading', { name: 'Paste this into your terminal' })).toBeVisible();
  await expect(page.getByText('OpenKey couldn’t make a short code, so here is the full one. It works the same way.')).toBeVisible();
  await expect(page.locator('[data-support-line]')).toHaveText('HTTP 503 · short_code_failed');
  await expect(page.locator('body')).not.toContainText('(Error');
  await expect(page.locator('body')).not.toContainText('private broker detail');
  await box(page).click();
  expect(JSON.parse(Buffer.from((await lastCopied(page))!, 'base64').toString('utf8'))).toEqual(delegation);
  await expectNoAmber(page);
});

test('when the terminal cannot be reached, the page says so and still shows the short code', async ({ page }) => {
  await page.route(`${callback}**`, (route) => route.fulfill({ status: 500, headers: cors, body: '' }));
  await openCodePage(page, { link: `${delegateLink}&${new URLSearchParams({ callback })}` });
  await expect(page.getByText('OpenKey couldn’t reach your terminal by itself. Paste this code there instead.')).toBeVisible();
  await expect(box(page)).toContainText('SF23-22CS');
  await expectNoAmber(page);
});

test('five minutes on, the short code has run out: nothing to copy, and a new code can be asked for', async ({ page }) => {
  await page.clock.install({ time: new Date('2026-10-16T17:00:00.000Z') });
  await openCodePage(page);
  await expect(box(page)).toContainText('SF23-22CS');
  await page.clock.runFor(5 * 60_000 + 1_000);
  await expect(page.getByRole('heading', { name: 'This code ran out of time' })).toBeVisible();
  await expect(page.getByRole('timer')).toHaveText('Code expired. Get a new code, or start again in the CLI.');
  await expect(box(page)).toContainText('Expired');
  await expect(page.locator('button[data-code-box]')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Copy/ })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Get a new code', exact: true })).toBeEnabled();
  await expectNoAmber(page);
});

test('when the browser will not copy, the code becomes plain text to select and the page says so', async ({ page }) => {
  await openCodePage(page, { failCopy: true });
  await box(page).click();
  await expect(page.getByRole('alert')).toHaveText('Couldn’t copy. Select the code and copy it by hand.');
  await expect(page.locator('button[data-code-box]')).toHaveCount(0);
  await expect(box(page)).toContainText('SF23-22CS');
});

test('a prepared sign-in with no callback: the box copies the reply envelope', async ({ page }) => {
  await recordClipboard(page);
  await mockApi(page, { signedIn: true });
  await page.goto(preparedLink());
  await page.getByRole('button', { name: 'Preview signing message' }).click();
  await approve(page);
  await expect(page.getByRole('heading', { name: 'Paste this into your terminal' })).toBeVisible();
  await expect(page.getByText('Approved · one step left')).toBeVisible();
  await expect(page.getByText('cli.tinycloud.xyz is waiting for it.')).toBeVisible();
  await box(page).click();
  const envelope = JSON.parse(Buffer.from((await lastCopied(page))!, 'base64url').toString('utf8'));
  expect(envelope).toMatchObject({ transportVersion: 2, state: 'A'.repeat(43), selectedKeyId: 'key-one', result: { signature: '0xsigned' } });
  await expectNoAmber(page);
});

test('a revoke with no callback: the box copies the signed revocation', async ({ page }) => {
  const cid = 'bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe';
  const siwe = [
    'openkey.test wants you to sign in with your Ethereum account:', address, '', 'Revoke this permission.', '',
    `URI: ucan:${cid}`, 'Version: 1', 'Chain ID: 1', 'Nonce: 0123456789abcdef0123456789abcdef',
    'Issued At: 2026-10-16T17:00:00.000Z', 'Expiration Time: 2026-10-16T17:09:00.000Z',
  ].join('\n');
  const signature = `0x${'ab'.repeat(65)}`;
  await recordClipboard(page);
  await mockApi(page, { signedIn: true });
  await page.route('**/api/delegate/owner-revocation/prepare', (route) => json(route, 200, { authorizationContextToken: 'token', siwe }));
  await page.route('**/api/delegate/owner-revocation/sign', (route) => json(route, 200, { siwe, signature, deliveryState: 'A'.repeat(43), selectedKeyId: 'key-one' }));
  await page.goto(revokeLink());
  await page.getByRole('button', { name: 'Revoke', exact: true }).click();
  await expect(page.getByText('Signed · one step left')).toBeVisible();
  await expect(page.getByText('Your terminal needs it to finish revoking the permission.')).toBeVisible();
  await box(page).click();
  const envelope = JSON.parse(Buffer.from((await lastCopied(page))!, 'base64url').toString('utf8'));
  expect(envelope).toMatchObject({ transportVersion: 2, state: 'A'.repeat(43), result: { siwe, signature } });
  await expectNoAmber(page);
});
