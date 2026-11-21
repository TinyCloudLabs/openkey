// TC-3441 T5: /device asks one question, does your terminal show this code? "No" answers nothing; the typed code
// is one input drawn as eight tiles.
import { expect, test, type Page } from '@playwright/test';

test.use({ viewport: { width: 390, height: 844 } });

const address = '0x1111111111111111111111111111111111111111';
const permissions = [
  { service: 'tinycloud.kv', space: `tinycloud:pkh:eip155:1:${address}:default`, path: 'notes/', actions: ['tinycloud.kv/get'] },
];

/** Answers the API for /device; returns every API path the page called. */
async function deviceApi(page: Page, options: { signedIn?: boolean; lookupStatus?: number } = {}) {
  const calls: string[] = [];
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    calls.push(path);
    if (path === '/api/auth/get-session') {
      return route.fulfill({ json: options.signedIn ? {
        session: { id: 'session-fixture', userId: 'owner-fixture', expiresAt: new Date(Date.now() + 3_600_000).toISOString() },
        user: { id: 'owner-fixture', name: 'QA owner', email: 'owner@example.test' },
      } : null });
    }
    if (path === '/api/device-authorizations/lookup') {
      if (options.lookupStatus) return route.fulfill({ status: options.lookupStatus, json: { error: 'not_found' } });
      return route.fulfill({ json: {
        id: 'device-fixture', userCode: 'WDJBMJHT', sessionDid: 'did:key:z6MkFixture',
        publicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) }, relayPublicJwk: {},
        permissions, reason: 'Sync my notes',
        nodeOrigin: 'https://node.example.test', shareOrigin: 'https://share.example.test',
        delegationTtlSeconds: 3_600,
        transactionExpiresAt: new Date(Date.now() + 600_000).toISOString(),
        delegationExpiresAt: new Date(Date.now() + 4_200_000).toISOString(),
      } });
    }
    return route.fulfill({ json: {} });
  });
  return calls;
}

const tilesLabel = 'Code W D J B, M J H T';
const tiles = [...'WDJBMJHT'];

test('a code in the link asks whether the terminal shows it, as tiles, with both answers', async ({ page }) => {
  await deviceApi(page);
  await page.goto('/device?user_code=WDJB-MJHT');
  await expect(page.getByRole('heading', { level: 1, name: 'Does your terminal show this code?' })).toBeVisible();
  await expect(page.getByText('Sign-in request from a device')).toBeVisible();
  await expect(page.getByRole('img', { name: tilesLabel }).locator('span')).toHaveText(tiles);
  await expect(page.getByRole('textbox')).toHaveCount(0);
  await expect(page.getByRole('list', { name: 'Requested access' }).getByRole('listitem')).toHaveCount(1);
  const yes = page.getByRole('link', { name: 'Yes, it matches. Sign in to review' });
  await expect(yes).toHaveAttribute('href', /^\/delegate\?/);
  await expect(page.getByRole('button', { name: 'No, it’s different' })).toBeVisible();
});

test('signed in, the first answer reads "Review the request" and still leads to /delegate', async ({ page }) => {
  await deviceApi(page, { signedIn: true });
  await page.goto('/device?user_code=WDJB-MJHT');
  const yes = page.getByRole('link', { name: 'Yes, it matches. Review the request' });
  await expect(yes).toBeVisible();
  await expect(yes).toHaveAttribute('href', /^\/delegate\?/);
  expect(new URL(await yes.getAttribute('href') ?? '', 'https://openkey.example.test').searchParams.get('deviceUserCode')).toBe('WDJB-MJHT');
});

test('"No, it’s different" stops without calling the API, and "I misread it" brings the code back', async ({ page }) => {
  const calls = await deviceApi(page);
  await page.goto('/device?user_code=WDJB-MJHT');
  await expect(page.getByRole('img', { name: tilesLabel })).toBeVisible();
  const before = calls.length;
  await page.getByRole('button', { name: 'No, it’s different' }).click();
  const heading = page.getByRole('heading', { level: 1, name: 'Stopped. Nothing was approved.' });
  await expect(heading).toBeVisible();
  await expect(heading).toBeFocused();
  await expect(page.getByText('It has been left unanswered and will expire by itself.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Close this tab' })).toBeVisible();
  await page.waitForTimeout(300);
  const after = calls.slice(before);
  expect(after.filter((path) => /\/approve|\/deny|\/api\/delegate/.test(path))).toEqual([]);
  expect(after.filter((path) => path !== '/api/auth/get-session')).toEqual([]);
  await page.getByRole('button', { name: 'I misread it, show the code again' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Does your terminal show this code?' })).toBeVisible();
  await expect(page.getByRole('img', { name: tilesLabel })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Yes, it matches. Sign in to review' })).toBeVisible();
});

test('without a code, a pasted lower-case code fills the tiles and is looked up once', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const calls = await deviceApi(page);
  await page.goto('/device');
  await expect(page.getByRole('heading', { level: 1, name: 'Enter the code from your terminal' })).toBeVisible();
  const input = page.getByRole('textbox', { name: 'Enter the code from your terminal' });
  await expect(input).toHaveAttribute('autocomplete', 'one-time-code');
  const find = page.getByRole('button', { name: 'Find the request' });
  await expect(find).toBeDisabled();
  await page.evaluate(() => navigator.clipboard.writeText('wdjb mjht'));
  await input.focus();
  await page.keyboard.press('ControlOrMeta+V');
  await expect(input).toHaveValue('WDJB-MJHT');
  await expect(page.locator('form [aria-hidden="true"]').first().locator('span')).toHaveText(tiles);
  await expect(find).toBeEnabled();
  await find.click();
  await expect(page.getByRole('img', { name: tilesLabel })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Yes, it matches. Sign in to review' })).toBeVisible();
  expect(calls.filter((path) => path === '/api/device-authorizations/lookup')).toHaveLength(1);
});

test('a code no request has keeps the input open to fix it, with no "Try again"', async ({ page }) => {
  await deviceApi(page, { lookupStatus: 404 });
  await page.goto('/device');
  const input = page.getByRole('textbox', { name: 'Enter the code from your terminal' });
  await input.fill('WDJB-MJHT');
  await page.getByRole('button', { name: 'Find the request' }).click();
  await expect(page.getByRole('alert')).toHaveText('No request has that code. Check the terminal, or run the command again for a new one.');
  await expect(page.getByRole('button', { name: 'Try again' })).toHaveCount(0);
  await expect(input).toBeEditable();
  await input.fill('WDJB-MJHA');
  await expect(input).toHaveValue('WDJB-MJHA');
  await expect(page.getByRole('alert')).toHaveCount(0);
});
