// A sign request that names no key (the app never ran connect(), or its connection was lost), or a key that cannot be
// used, must never end on a screen with no way on. The request is the exact one @openkey/sdk sends from
// `signMessage({ message })` without a keyId: `{ type: 'openkey:sign:request', message, keyId: undefined }`, unversioned,
// to `/widget/embed/sign?origin=…` (iframe) or `/widget/sign?origin=…` (popup). web-sdk's runtime grant signer
// (tcw.ts `client.signMessage({ message: siwe })`) sends the same request with a ReCap SIWE. Every API call is answered
// by `page.route`; no API server runs. The tests assert states, buttons and replies, not wording.
import { test, expect, type Page, type Route, type FrameLocator } from '@playwright/test';
import { EXPLORER_PERMISSION_POPUP_REQUEST } from '../../../../packages/capability-review/test/fixtures/index';
import { setTimeout as sleep } from 'node:timers/promises';
import { HOST } from './e2e-port';

const ADDRESS_A = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
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
/** A real TinyCloud ReCap SIWE (explorer's permission request), made out to this test site; it names ADDRESS_A. */
const RECAP_SIWE = EXPLORER_PERMISSION_POPUP_REQUEST.replace(/^explorer\.tinycloud\.xyz/, HOST);

interface Account {
  signedIn: boolean;
  /** The id `GET /api/auth/get-session` reports; changing it is another session. */
  sessionId: string;
  keys: Key[];
  /** Key ids `GET /api/keys/:id` refuses (404), as for a key of another account. */
  unreadable: Set<string>;
  /** `GET /api/keys` fails (500) while set. */
  listFails: boolean;
  /** Milliseconds `GET /api/keys/:id` waits before it answers. */
  keyReadDelay: number;
  signed: Array<{ keyId: string; message: string }>;
}

const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

async function mockApi(page: Page, account: Account) {
  await page.context().route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    if (path === '/api/auth/get-session') {
      return json(route, 200, account.signedIn
        ? { session: { id: account.sessionId, userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, user: { id: 'u', email: 'owner@example.test', name: 'Owner' } }
        : null);
    }
    if (path === '/api/auth/providers') return json(route, 200, { providers: [] });
    if (path === '/api/auth/sign-out') {
      account.signedIn = false;
      return json(route, 200, { success: true });
    }
    if (path === '/api/auth/email-otp/send-verification-otp') return json(route, 200, { success: true });
    if (path === '/api/auth/sign-in/email-otp') {
      account.signedIn = true;
      return json(route, 200, { token: 'embedded-session', user: { id: 'u' } });
    }
    if (path === '/api/keys') {
      if (!account.signedIn) return json(route, 401, { error: 'Unauthorized' });
      if (account.listFails) return json(route, 500, { error: 'Internal error' });
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
      if (account.keyReadDelay > 0) await sleep(account.keyReadDelay);
      const found = account.keys.find((k) => k.id === read[1]);
      if (!account.signedIn || !found || account.unreadable.has(found.id)) return json(route, 404, { error: 'Key not found' });
      return json(route, 200, { key: found });
    }
    return json(route, 404, { error: `unmocked ${path}` });
  });
}

function newAccount(keys: Key[], signedIn = true): Account {
  return { signedIn, sessionId: 's1', keys, unreadable: new Set(), listFails: false, keyReadDelay: 0, signed: [] };
}

type Reply = Record<string, unknown> & { type?: string };
const replies = (page: Page) => page.evaluate(() => (window as unknown as { replies: Reply[] }).replies);
const signResponses = async (page: Page) => (await replies(page)).filter((r) => r.type === 'openkey:sign:response');

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

/** The SDK's popup flow: the real /widget/sign page in a window this page opened, sent the same request on every ready. */
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

// Drives the existing in-dialog email sign-in (its own controls; the tests assert states, not wording).
async function signInWithEmail(surface: Surface) {
  await surface.getByRole('button', { name: 'Continue with email' }).click();
  await surface.locator('#embed-email').fill('owner@example.test');
  await surface.locator('#embed-email').press('Enter');
  await surface.locator('#embed-otp').fill('123456');
  await surface.locator('#embed-otp').press('Enter');
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

/** The key refusal, with the way on it offers: Sign out (no key of this account fits) or Try again (a failed read). */
async function expectRefusal(surface: Surface, problem: 'missing' | 'transient') {
  await expect(surface.getByTestId('signing-key-refusal')).toBeVisible({ timeout: 30_000 });
  await expect(surface.getByTestId('signing-key-back')).toBeVisible();
  await expect(surface.getByTestId('signing-key-sign-out')).toHaveCount(problem === 'missing' ? 1 : 0);
  await expect(surface.getByTestId('signing-key-retry')).toHaveCount(problem === 'transient' ? 1 : 0);
  await expect(surface.locator('button.approve')).toHaveCount(0);
}

/** A key's selection button in the key choice: KeyPicker titles it with the key's address and marks it pressable. */
const keyButton = (surface: Surface, address: string) => surface.locator(`button[title="${address}"][aria-pressed]`);

/** The whole review, collapsed Advanced details (signer, exact bytes) included. */
async function reviewText(surface: Surface, message: string) {
  await expectReview(surface, message);
  await expect(surface.locator('button.approve')).toBeEnabled({ timeout: 15_000 });
  return surface.locator('[role="dialog"]').first().textContent();
}

/**
 * Another tab of this origin reports a session change (better-auth's cross-tab `better-auth.message` storage event), so
 * the popup re-reads its session, as when the owner signs in to another account elsewhere.
 */
async function sessionChangedInAnotherTab(opener: Page) {
  await opener.evaluate(() => localStorage.setItem('better-auth.message', JSON.stringify({ event: 'session', data: { trigger: 'signin' }, timestamp: Date.now() })));
}

test.describe('iframe: a sign request that names no key', () => {
  test('signed out: the owner signs in inside the dialog, then reviews and signs the same message with the only key', async ({ page }) => {
    const account = newAccount([KEY_A], false);
    const frame = await openEmbed(page, account, PLAIN);
    await signInWithEmail(frame);
    await expectReview(frame, PLAIN);
    expect(account.signed).toEqual([]);
    await approve(frame);
    await expect.poll(async () => (await signResponses(page)).length).toBe(1);
    expect(account.signed).toEqual([{ keyId: 'key_a', message: PLAIN }]);
    expect((await signResponses(page))[0]).toMatchObject({ success: true, signature: '0xsignature', address: ADDRESS_A });
  });

  test('connection lost but the frame is signed in, two keys, a plain message: the owner picks the key, then the review', async ({ page }) => {
    const account = newAccount([{ ...KEY_A, isPrimary: false }, KEY_B]);
    const frame = await openEmbed(page, account, PLAIN);
    await expect(keyButton(frame, ADDRESS_B)).toBeVisible({ timeout: 30_000 });
    await expect(frame.locator('button.approve')).toHaveCount(0);
    await keyButton(frame, ADDRESS_B).click();
    await expectReview(frame, PLAIN);
    expect(account.signed).toEqual([]);
    await approve(frame);
    await expect.poll(() => account.signed).toEqual([{ keyId: 'key_b', message: PLAIN }]);
  });

  test('a real ReCap SIWE with no keyId (web-sdk runtime grant): its own address picks the key; the review equals the explicit-keyId review', async ({ page, browser }) => {
    const resolved = newAccount([KEY_B, KEY_A]);
    const frame = await openEmbed(page, resolved, RECAP_SIWE);
    const resolvedReview = await reviewText(frame, RECAP_SIWE);
    expect(resolved.signed).toEqual([]);

    const explicitPage = await browser.newPage();
    const explicitReview = await reviewText(await openEmbed(explicitPage, newAccount([KEY_B, KEY_A]), RECAP_SIWE, 'key_a'), RECAP_SIWE);
    await explicitPage.close();
    expect(resolvedReview).toBe(explicitReview);

    await approve(frame);
    await expect.poll(() => resolved.signed).toEqual([{ keyId: 'key_a', message: RECAP_SIWE }]);
  });

  test('a SIWE-shaped message whose address cannot be read fits no key, even when the account has only one', async ({ page }) => {
    const account = newAccount([KEY_A]);
    const frame = await openEmbed(page, account, siweFor('not-an-address'));
    await expectRefusal(frame, 'missing');
    expect(account.signed).toEqual([]);
  });

  test('no key of the account fits (SIWE names another address; archived and wallet keys never sign): Sign out is offered; Back to app tells the app NO_KEY', async ({ page }) => {
    const account = newAccount([
      key('key_archived', ADDRESS_ELSEWHERE, 2, { archivedAt: '2026-02-01T00:00:00Z' }),
      key('key_wallet', ADDRESS_ELSEWHERE.replace('2', '3'), 3, { keyType: 'EXTERNAL' }),
      KEY_A,
    ]);
    const frame = await openEmbed(page, account, siweFor(ADDRESS_ELSEWHERE));
    await expectRefusal(frame, 'missing');
    await frame.getByTestId('signing-key-back').click();
    await expect.poll(async () => (await signResponses(page))[0]).toMatchObject({ success: false, error: { code: 'NO_KEY' } });
    expect(account.signed).toEqual([]);
  });

  test("the account's keys cannot be read: Try again resolves the key and shows the review", async ({ page }) => {
    const account = newAccount([KEY_A]);
    account.listFails = true;
    const frame = await openEmbed(page, account, PLAIN);
    await expectRefusal(frame, 'transient');
    account.listFails = false;
    await frame.getByTestId('signing-key-retry').click();
    await expectReview(frame, PLAIN);
    expect(account.signed).toEqual([]);
  });

  test('a transient failure, then Back to app: the app keeps its connection (USER_CANCELLED)', async ({ page }) => {
    const account = newAccount([KEY_A]);
    account.listFails = true;
    const frame = await openEmbed(page, account, PLAIN);
    await expectRefusal(frame, 'transient');
    await frame.getByTestId('signing-key-back').click();
    await expect.poll(async () => (await signResponses(page))[0]).toMatchObject({ success: false, error: { code: 'USER_CANCELLED' } });
  });

  test('Sign out from the refusal returns to sign-in inside the dialog, and the next account signs the same request with its own key', async ({ page }) => {
    const account = newAccount([KEY_A]);
    const frame = await openEmbed(page, account, siweFor(ADDRESS_B));
    await expectRefusal(frame, 'missing');
    await frame.getByTestId('signing-key-sign-out').click();
    account.signedIn = false;
    account.sessionId = 's2';
    account.keys = [KEY_B];
    await signInWithEmail(frame);
    await expectReview(frame, siweFor(ADDRESS_B));
    await approve(frame);
    await expect.poll(() => account.signed).toEqual([{ keyId: 'key_b', message: siweFor(ADDRESS_B) }]);
  });
});

test.describe('iframe: a named key that cannot be read', () => {
  test('a key of another account (404): Sign out is offered, not a retry', async ({ page }) => {
    const account = newAccount([KEY_A]);
    account.unreadable.add('key_a');
    const frame = await openEmbed(page, account, PLAIN, 'key_a');
    await expectRefusal(frame, 'missing');
  });
});

test.describe('popup: a sign request that names no key', () => {
  test('signed in, one key: the review with the exact message, signed only on Approve', async ({ page }) => {
    const account = newAccount([KEY_A]);
    const popup = await openPopup(page, account, PLAIN);
    await expectReview(popup, PLAIN);
    expect(account.signed).toEqual([]);
    const response = page.waitForFunction(() => (window as unknown as { replies: Reply[] }).replies.some((r) => r.type === 'openkey:sign:response'));
    await approve(popup);
    await response;
    expect(account.signed).toEqual([{ keyId: 'key_a', message: PLAIN }]);
  });

  test('a real ReCap SIWE with no keyId: the review equals the explicit-keyId review', async ({ page, browser }) => {
    const popup = await openPopup(page, newAccount([KEY_B, KEY_A]), RECAP_SIWE);
    const resolvedReview = await reviewText(popup, RECAP_SIWE);
    const explicitPage = await browser.newPage();
    const explicitReview = await reviewText(await openPopup(explicitPage, newAccount([KEY_B, KEY_A]), RECAP_SIWE, 'key_a'), RECAP_SIWE);
    await explicitPage.close();
    expect(resolvedReview).toBe(explicitReview);
  });

  test('two keys: the owner picks one', async ({ page }) => {
    const account = newAccount([KEY_A, KEY_B]);
    const popup = await openPopup(page, account, PLAIN);
    await keyButton(popup, ADDRESS_A).click({ timeout: 30_000 });
    await expectReview(popup, PLAIN);
    expect(account.signed).toEqual([]);
  });

  test('the key list cannot be read: Try again resolves the key', async ({ page }) => {
    const account = newAccount([KEY_A]);
    account.listFails = true;
    const popup = await openPopup(page, account, PLAIN);
    await expectRefusal(popup, 'transient');
    account.listFails = false;
    await popup.getByTestId('signing-key-retry').click();
    await expectReview(popup, PLAIN);
  });

  test('no key fits: Sign out ends the session first; after the next account signs in, the same request is signed with its key only', async ({ page }) => {
    const account = newAccount([KEY_A]);
    const popup = await openPopup(page, account, siweFor(ADDRESS_B));
    await expectRefusal(popup, 'missing');
    await popup.getByTestId('signing-key-sign-out').click();
    // Signed out: the popup's sign-in link, which returns to this widget for the same request.
    await expect(popup.locator('a[href*="/auth/login?redirect=/widget/sign"]')).toBeVisible();
    expect(account.signedIn).toBe(false);
    // The next account signs in; the login returns to /widget/sign and the SDK sends the request again on ready.
    account.signedIn = true;
    account.sessionId = 's2';
    account.keys = [KEY_B];
    await popup.reload();
    await expectReview(popup, siweFor(ADDRESS_B));
    const response = page.waitForFunction(() => (window as unknown as { replies: Reply[] }).replies.some((r) => r.type === 'openkey:sign:response'));
    await approve(popup);
    await response;
    expect(account.signed).toEqual([{ keyId: 'key_b', message: siweFor(ADDRESS_B) }]);
  });

  test('a named key read that answers after the session changed is not used', async ({ page }) => {
    const account = newAccount([KEY_A]);
    account.keyReadDelay = 4_000;
    const reading = page.context().waitForEvent('request', (request) => new URL(request.url()).pathname === '/api/keys/key_a');
    const popup = await openPopup(page, account, PLAIN, 'key_a');
    await reading;
    account.sessionId = 's2';
    await sessionChangedInAnotherTab(page);
    await expectRefusal(popup, 'transient');
    expect(account.signed).toEqual([]);
  });

  test('a loaded key is dropped when another session takes over, before it can sign', async ({ page }) => {
    const account = newAccount([KEY_A]);
    const popup = await openPopup(page, account, PLAIN, 'key_a');
    await expectReview(popup, PLAIN);
    account.sessionId = 's2';
    await sessionChangedInAnotherTab(page);
    await expectRefusal(popup, 'transient');
    expect(account.signed).toEqual([]);
  });
});
