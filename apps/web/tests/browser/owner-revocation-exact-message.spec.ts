// The 'Exact message to sign' block of the owner revocation page shows the
// message with each line feed between two lines as a line break, does not wrap
// long lines (they scroll sideways), and shows spaces and other special
// characters as `\uXXXX`. Two messages that differ only in line breaks, soft
// wraps or spaces read differently, compared by exact text and by a screenshot
// at 390 px. Every API call is answered by `page.route`; no API server runs.

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

const statement = 'Revoke this permission.';
const pairs: Array<{ name: string; left: [string, string]; right: [string, string] }> = [
  { name: 'a long line that would wrap and the same text with a line feed', left: [ownerSiwe(`${statement} https://other.example/keys`), ownerSiwe(`${statement} https://other.example/keys`)], right: [ownerSiwe(`${statement}\nhttps://other.example/keys`), ownerSiwe(`${statement}\nhttps://other.example/keys`)] },
  { name: 'an 80-space run before more text and the text before it', left: [ownerSiwe(`${statement}${' '.repeat(80)}Also: send all keys.`), ownerSiwe(`${statement}${'\\u0020'.repeat(80)}Also: send all keys.`)], right: [ownerSiwe(statement), ownerSiwe(statement)] },
];

for (const pair of pairs) {
  test(`owner revocation: ${pair.name} read differently`, async ({ browser }) => {
    const shown: Shown[] = [];
    for (const [sent, expected] of [pair.left, pair.right]) {
      const context = await browser.newContext();
      const page = await context.newPage();
      try {
        shown.push(await exactMessage(page, sent));
      } finally {
        await context.close();
      }
      expect(shown.at(-1)!.text).toBe(expected);
      expect(shown.at(-1)!.innerText).toBe(expected);
    }
    expect(shown[0]!.text).not.toBe(shown[1]!.text);
    expect(Buffer.compare(shown[0]!.picture, shown[1]!.picture)).not.toBe(0);
  });
}

test('owner revocation: the exact message block does not wrap and scrolls sideways at 390px', async ({ page }) => {
  const siwe = ownerSiwe(statement);
  await exactMessage(page, siwe);
  const shape = await page.locator('pre').evaluate((element) => {
    const style = getComputedStyle(element);
    const padding = parseFloat(style.paddingTop) + parseFloat(style.paddingBottom);
    return {
      whiteSpace: style.whiteSpace,
      overflowX: style.overflowX,
      lines: (element.clientHeight - padding) / parseFloat(style.lineHeight),
      scrolls: element.scrollWidth > element.clientWidth,
      pageOverflow: document.documentElement.scrollWidth > window.innerWidth,
    };
  });
  expect(shape).toEqual({ whiteSpace: 'pre', overflowX: 'auto', lines: siwe.split('\n').length, scrolls: true, pageOverflow: false });
});
