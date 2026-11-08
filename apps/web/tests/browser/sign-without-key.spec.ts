// A sign request that names no key (the app never ran connect(), or its connection was lost) and a key that cannot be
// loaded must never end on a screen whose only way out is Cancel. The request is the exact one @openkey/sdk sends from
// `signMessage({ message })` without a keyId: `{ type: 'openkey:sign:request', message, keyId: undefined }`, unversioned,
// to `/widget/embed/sign?origin=…` (iframe) or `/widget/sign?origin=…` (popup). web-sdk's runtime grant signer
// (tcw.ts `client.signMessage({ message: siwe })`) sends the same request with a SIWE. Every API call is answered by
// `page.route`; no API server runs.
import { test, expect, type Page, type Route, type FrameLocator } from '@playwright/test';
import { HOST } from './e2e-port';

const ADDRESS_A = '0xd559cCd9EB87c530A9a349262669386dE93cf412';
const ADDRESS_B = '0x1111111111111111111111111111111111111111';
const ADDRESS_ELSEWHERE = '0x2222222222222222222222222222222222222222';

type Key = { id: string; address: string; publicKey: string; keyIndex: number; label: string | null; keyType: 'MANAGED' | 'EXTERNAL'; createdAt: string; archivedAt?: string | null; isPrimary?: boolean };
const key = (id: string, address: string, keyIndex: number, extra: Partial<Key> = {}): Key => ({
  id, address, publicKey: '0x02', keyIndex, label: null, keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z', ...extra,
});
const KEY_A = key('key_a', ADDRESS_A, 0, { isPrimary: true });
const KEY_B = key('key_b', ADDRESS_B, 1);

const PLAIN = 'Sign in to Inbox. Nonce: 7f3a91c2';
const siweFor = (address: string) => [
  `${HOST} wants you to sign in with your Ethereum account:`, address, '',
  'Grant this app permission to read your messages.', '',
  `URI: http://${HOST}`, 'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456',
  'Issued At: 2026-11-08T00:00:00.000Z', 'Expiration Time: 2026-11-08T01:00:00.000Z',
].join('\n');

interface Account {
  signedIn: boolean;
  keys: Key[];
  /** Key ids `GET /api/keys/:id` refuses (404), as for a key of another account. */
  unreadable: Set<string>;
  signed: Array<{ keyId: string; message: string }>;
}

const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

async function mockApi(page: Page, account: Account) {
  await page.context().route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    if (path === '/api/auth/get-session') {
      return json(route, 200, account.signedIn
        ? { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'owner@example.test', name: 'Owner' } }
        : null);
    }
    if (path === '/api/auth/providers') return json(route, 200, { providers: [] });
    if (path === '/api/auth/email-otp/send-verification-otp') return json(route, 200, { success: true });
    if (path === '/api/auth/sign-in/email-otp') {
      account.signedIn = true;
      return json(route, 200, { token: 'embedded-session', user: { id: 'u' } });
    }
    if (path === '/api/keys') {
      if (!account.signedIn) return json(route, 401, { error: 'Unauthorized' });
      return json(route, 200, { keys: account.keys.filter((k) => !k.archivedAt) });
    }
    const sign = path.match(/^\/api\/keys\/([^/]+)\/sign$/);
    if (sign && route.request().method() === 'POST') {
      const body = route.request().postDataJSON() as { message: string };
      account.signed.push({ keyId: sign[1]!, message: body.message });
      const signer = account.keys.find((k) => k.id === sign[1]);
      return json(route, 200, { signature: '0xsignature', address: signer?.address });
    }
    const read = path.match(/^\/api\/keys\/([^/]+)$/);
    if (read) {
      const found = account.keys.find((k) => k.id === read[1]);
      if (!account.signedIn || !found || account.unreadable.has(found.id)) return json(route, 404, { error: 'Key not found' });
      return json(route, 200, { key: found });
    }
    return json(route, 404, { error: `unmocked ${path}` });
  });
}

function newAccount(keys: Key[], signedIn = true): Account {
  return { signedIn, keys, unreadable: new Set(), signed: [] };
}

type Reply = Record<string, unknown> & { type?: string };
const replies = (page: Page) => page.evaluate(() => (window as unknown as { replies: Reply[] }).replies);

/**
 * The SDK's iframe modal around the real /widget/embed/sign page. On every `openkey:ready` (like the SDK) it posts the
 * request `signWithOpenKey` builds: `keyId` is whatever the app passed, `undefined` when it passed none.
 */
async function openEmbed(page: Page, account: Account, message: string, keyId?: string) {
  await mockApi(page, account);
  await page.goto('/__parity_harness');
  if (account.signedIn) {
    // The frame's own OpenKey session (sessionStorage is per origin, shared with the same-origin frame).
    await page.evaluate(() => sessionStorage.setItem('openkey_session_token', 'embedded-session'));
  }
  await page.evaluate(([text, selected]) => {
    const w = window as unknown as { replies: Reply[] };
    w.replies = [];
    const frame = document.createElement('iframe');
    frame.id = 'sign';
    frame.style.cssText = 'border:none;width:420px;height:760px;display:block';
    frame.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}`;
    document.body.append(frame);
    window.addEventListener('message', (event) => {
      if (event.source !== frame.contentWindow) return;
      if (event.data?.type === 'openkey:ready') {
        frame.contentWindow!.postMessage({ type: 'openkey:sign:request', message: text, keyId: selected ?? undefined }, location.origin);
        return;
      }
      if (event.data?.type === 'openkey:resize') return;
      w.replies.push(event.data);
    });
  }, [message, keyId ?? null] as const);
  return page.frameLocator('#sign');
}

/** The SDK's popup flow: the real /widget/sign page in a window this page opened, sent the same request on ready. */
async function openPopup(page: Page, account: Account, message: string, keyId?: string) {
  await mockApi(page, account);
  await page.goto('/__parity_harness');
  const [popup] = await Promise.all([
    page.waitForEvent('popup'),
    page.evaluate(([text, selected]) => {
      const w = window as unknown as { replies: Reply[] };
      w.replies = [];
      const child = window.open(`/widget/sign?origin=${encodeURIComponent(location.origin)}`, 'openkey-sign', 'popup=true,width=420,height=760')!;
      window.addEventListener('message', (event) => {
        if (event.source !== child) return;
        if (event.data?.type === 'openkey:ready') {
          child.postMessage({ type: 'openkey:sign:request', message: text, keyId: selected ?? undefined }, location.origin);
          return;
        }
        w.replies.push(event.data);
      });
    }, [message, keyId ?? null] as const),
  ]);
  return popup;
}

type Surface = FrameLocator | Page;

async function signInWithEmail(surface: Surface) {
  await surface.getByRole('button', { name: 'Continue with email' }).click();
  await surface.getByLabel('Email address').fill('owner@example.test');
  await surface.getByRole('button', { name: 'Send code' }).click();
  await surface.getByLabel('Verification code').fill('123456');
  await surface.getByRole('button', { name: 'Verify and continue' }).click();
}

/** The signing review is on screen and holds the exact bytes (under Advanced details, as for a named key). */
async function expectReview(surface: Surface, message: string) {
  await expect(surface.locator('button.approve')).toBeVisible({ timeout: 30_000 });
  await expect(surface.locator('pre.raw-bytes')).toHaveText(message);
}

async function approve(surface: Surface) {
  const button = surface.locator('button.approve');
  await expect(button).toBeEnabled({ timeout: 15_000 });
  await button.click();
}

const signResponses = async (page: Page) => (await replies(page)).filter((r) => r.type === 'openkey:sign:response');

test.describe('iframe: a sign request that names no key', () => {
  test('signed out: the owner signs in inside the dialog, then reviews and signs the same message with the only key', async ({ page }) => {
    const account = newAccount([KEY_A], false);
    const frame = await openEmbed(page, account, PLAIN);
    await signInWithEmail(frame);
    // The same review as an explicit-keyId request: the exact message on screen, nothing signed until Approve.
    await expectReview(frame, PLAIN);
    await expect(frame.getByText('Please connect first to sign messages.')).toHaveCount(0);
    expect(account.signed).toEqual([]);
    await approve(frame);
    await expect.poll(async () => (await signResponses(page)).length).toBe(1);
    expect(account.signed).toEqual([{ keyId: 'key_a', message: PLAIN }]);
    expect((await signResponses(page))[0]).toMatchObject({ success: true, signature: '0xsignature', address: ADDRESS_A });
  });

  test('connection lost but the frame is signed in, two keys, a plain message: the owner picks the key, then the same review', async ({ page }) => {
    const account = newAccount([KEY_A, KEY_B]);
    const frame = await openEmbed(page, account, PLAIN);
    // Two keys fit: OpenKey does not guess. The primary leads; the other is behind "Use a different key".
    await frame.getByRole('button', { name: /Use a different key/ }).click();
    await frame.getByRole('button', { name: new RegExp(`${ADDRESS_B.slice(0, 6)}\\.\\.\\.${ADDRESS_B.slice(-4)}`) }).click();
    await expectReview(frame, PLAIN);
    expect(account.signed).toEqual([]);
    await approve(frame);
    await expect.poll(() => account.signed).toEqual([{ keyId: 'key_b', message: PLAIN }]);
  });

  test("web-sdk runtime grant (signMessage({ message: siwe }), no keyId): the SIWE's own address picks the key; the review is the explicit-keyId review", async ({ page, browser }) => {
    const siwe = siweFor(ADDRESS_B);
    // The whole review, collapsed Advanced details (signer, exact bytes) included.
    const reviewText = async (frame: FrameLocator) => {
      await expectReview(frame, siwe);
      await expect(frame.locator('button.approve')).toBeEnabled({ timeout: 15_000 });
      return frame.locator('[role="dialog"]').first().textContent();
    };

    const resolved = newAccount([KEY_A, KEY_B]);
    const frame = await openEmbed(page, resolved, siwe);
    const resolvedReview = await reviewText(frame);
    expect(resolved.signed).toEqual([]);

    const explicitPage = await browser.newPage();
    const explicit = newAccount([KEY_A, KEY_B]);
    const explicitReview = await reviewText(await openEmbed(explicitPage, explicit, siwe, 'key_b'));
    await explicitPage.close();
    expect(resolvedReview).toBe(explicitReview);
    expect(resolvedReview).toContain(ADDRESS_B);

    await approve(frame);
    await expect.poll(() => resolved.signed).toEqual([{ keyId: 'key_b', message: siwe }]);
  });

  test('no key of the signed-in account fits (SIWE names another address; archived and wallet keys never sign): a clear error with Try again and Sign out; Cancel rejects NO_KEY', async ({ page }) => {
    const account = newAccount([
      key('key_archived', ADDRESS_ELSEWHERE, 2, { archivedAt: '2026-02-01T00:00:00Z' }),
      key('key_wallet', ADDRESS_ELSEWHERE.replace('2', '3'), 3, { keyType: 'EXTERNAL' }),
      KEY_A,
    ]);
    const frame = await openEmbed(page, account, siweFor(ADDRESS_ELSEWHERE));
    await expect(frame.getByRole('alert')).toBeVisible({ timeout: 30_000 });
    await expect(frame.getByText('Please connect first to sign messages.')).toHaveCount(0);
    await expect(frame.getByRole('button', { name: 'Try again' })).toBeVisible();
    await expect(frame.getByRole('button', { name: 'Sign out' })).toBeVisible();
    await expect(frame.locator('button.approve')).toHaveCount(0);

    // Retry after the key is added to this account: the review appears.
    account.keys.push(key('key_elsewhere', ADDRESS_ELSEWHERE, 4));
    await frame.getByRole('button', { name: 'Try again' }).click();
    await expect(frame.locator('button.approve')).toBeVisible({ timeout: 15_000 });
    expect(account.signed).toEqual([]);
  });

  test('no key fits: Cancel tells the app NO_KEY', async ({ page }) => {
    const account = newAccount([KEY_A]);
    const frame = await openEmbed(page, account, siweFor(ADDRESS_ELSEWHERE));
    await expect(frame.getByRole('button', { name: 'Try again' })).toBeVisible({ timeout: 30_000 });
    await frame.getByRole('button', { name: 'Cancel' }).click();
    await expect.poll(async () => (await signResponses(page))[0]).toMatchObject({ success: false, error: { code: 'NO_KEY' } });
    expect(account.signed).toEqual([]);
  });

  test('Sign out from the error returns to sign-in inside the dialog, and the next account continues the same request', async ({ page }) => {
    const account = newAccount([]);
    const frame = await openEmbed(page, account, PLAIN);
    await expect(frame.getByRole('button', { name: 'Sign out' })).toBeVisible({ timeout: 30_000 });
    await frame.getByRole('button', { name: 'Sign out' }).click();
    account.signedIn = false;
    account.keys = [KEY_A];
    await signInWithEmail(frame);
    await expectReview(frame, PLAIN);
    await approve(frame);
    await expect.poll(() => account.signed).toEqual([{ keyId: 'key_a', message: PLAIN }]);
  });
});

test.describe('iframe: a named key that cannot be loaded (keyId of another account)', () => {
  test('a clear error with Try again and Sign out, not only Cancel; Try again loads it once it is readable', async ({ page }) => {
    const account = newAccount([KEY_A]);
    account.unreadable.add('key_a');
    const frame = await openEmbed(page, account, PLAIN, 'key_a');
    await expect(frame.getByText('Selected key could not be loaded.')).toBeVisible({ timeout: 30_000 });
    await expect(frame.getByRole('button', { name: 'Try again' })).toBeVisible();
    await expect(frame.getByRole('button', { name: 'Sign out' })).toBeVisible();
    account.unreadable.clear();
    await frame.getByRole('button', { name: 'Try again' }).click();
    await expectReview(frame, PLAIN);
    await approve(frame);
    await expect.poll(() => account.signed).toEqual([{ keyId: 'key_a', message: PLAIN }]);
  });
});

test.describe('popup: a sign request that names no key', () => {
  test('signed in, one key: the same review with the exact message, signed only on Approve', async ({ page }) => {
    const account = newAccount([KEY_A]);
    const popup = await openPopup(page, account, PLAIN);
    await expectReview(popup, PLAIN);
    await expect(popup.getByText('Please connect first to sign messages.')).toHaveCount(0);
    expect(account.signed).toEqual([]);
    const response = page.waitForFunction(() => (window as unknown as { replies: Reply[] }).replies.some((r) => r.type === 'openkey:sign:response'));
    await approve(popup);
    await response;
    expect(account.signed).toEqual([{ keyId: 'key_a', message: PLAIN }]);
  });

  test('two keys: the owner picks one', async ({ page }) => {
    const account = newAccount([KEY_A, KEY_B]);
    const popup = await openPopup(page, account, PLAIN);
    await popup.getByRole('button', { name: new RegExp(`${ADDRESS_A.slice(0, 6)}\\.\\.\\.${ADDRESS_A.slice(-4)}`) }).click({ timeout: 30_000 });
    await expectReview(popup, PLAIN);
    expect(account.signed).toEqual([]);
  });

  test('the named key cannot be loaded: a clear error with Try again; Cancel rejects NO_KEY', async ({ page }) => {
    const account = newAccount([KEY_A]);
    account.unreadable.add('key_a');
    const popup = await openPopup(page, account, PLAIN, 'key_a');
    await expect(popup.getByText('Selected key could not be loaded.')).toBeVisible({ timeout: 30_000 });
    await expect(popup.getByRole('button', { name: 'Try again' })).toBeVisible();
    await expect(popup.getByText('Please connect first to sign messages.')).toHaveCount(0);
    const response = page.waitForFunction(() => (window as unknown as { replies: Reply[] }).replies.some((r) => r.type === 'openkey:sign:response'));
    await popup.getByRole('button', { name: 'Cancel' }).click();
    await response;
    expect((await signResponses(page))[0]).toMatchObject({ success: false, error: { code: 'NO_KEY' } });
  });

  test('no key of the account fits (SIWE names another address): a clear error; Try again finds the key once added', async ({ page }) => {
    const account = newAccount([KEY_A, KEY_B]);
    const popup = await openPopup(page, account, siweFor(ADDRESS_ELSEWHERE));
    await expect(popup.getByRole('alert')).toBeVisible({ timeout: 30_000 });
    await expect(popup.locator('button.approve')).toHaveCount(0);
    account.keys.push(key('key_elsewhere', ADDRESS_ELSEWHERE, 4));
    await popup.getByRole('button', { name: 'Try again' }).click();
    await expectReview(popup, siweFor(ADDRESS_ELSEWHERE));
    expect(account.signed).toEqual([]);
  });
});
