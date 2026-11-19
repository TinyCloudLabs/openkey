// Shared set-up for the code page and done page specs, on top of the approval page fixtures.
import { expect, type Page } from '@playwright/test';
import { address, json } from './approval-end-pages-fixtures';

export const space = `tinycloud:pkh:eip155:1:${address}:default`;
export const callback = 'http://127.0.0.1:47123/callback';
export const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type' };

/** What /api/delegate answers when the owner approves a /delegate link. */
export const delegation = {
  delegationHeader: { Authorization: 'Bearer signed' },
  delegationCid: 'bafy-signed',
  spaceId: space,
  verificationMethod: 'did:key:z6Mk',
  jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
  expirationTime: '2026-11-03T01:00:00.000Z',
  hostActivated: true,
};

/**
 * Records what the page copies instead of touching the real clipboard. With `fail`, both the clipboard API and the
 * old copy command refuse.
 */
export async function recordClipboard(page: Page, fail = false) {
  await page.addInitScript((refuse) => {
    const copied: string[] = [];
    Reflect.set(window, '__copied', copied);
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async (text: string) => {
          if (refuse) throw new Error('refused');
          copied.push(text);
        },
      },
    });
    if (refuse) document.execCommand = () => false;
  }, fail);
}

export const lastCopied = (page: Page) => page.evaluate(() => (Reflect.get(window, '__copied') as string[]).at(-1) ?? null);

/**
 * The full code the code box holds, read whole from the page, after checking that copying the box puts exactly that
 * text on the clipboard. The box must show the full code; call `recordClipboard` before the page loads.
 */
export async function fullCodeFromBox(page: Page): Promise<string> {
  const box = page.locator('[data-code-box]');
  const held = box.locator('> span').first();
  await expect(held).toBeVisible();
  const code = (await held.textContent()) ?? '';
  expect(code).not.toBe('');
  await box.click();
  await expect.poll(() => lastCopied(page)).toBe(code);
  return code;
}

/** /api/delegation-codes answers with this short code, valid for five minutes on the server's clock. */
export async function mintShortCode(page: Page, code = 'sf23-22cs') {
  await page.route('**/api/delegation-codes', (route) => route.fulfill({
    status: 201,
    contentType: 'application/json',
    headers: { date: new Date('2026-10-16T17:00:00.000Z').toUTCString() },
    body: JSON.stringify({ code, expiresAt: '2026-10-16T17:05:00.000Z' }),
  }));
}

export async function refuseShortCode(page: Page) {
  await page.route('**/api/delegation-codes', (route) => json(route, 503, { code: 'short_code_failed', error: 'private broker detail' }));
}

export async function approve(page: Page) {
  const button = page.getByRole('button', { name: 'Approve', exact: true });
  await expect(button).toBeEnabled();
  await button.click();
}

/** A receipt row's value, by its label. */
export const receipt = (page: Page, label: string) => page.locator('dl > div').filter({ has: page.getByRole('term').filter({ hasText: label }) }).getByRole('definition');
