// TC-1232 (TC-1188 B): the Apple button and every step after Apple returns,
// on the real routes, at a phone width in light mode. Every API call is
// answered by page.route and Apple's authorize page is a stub that redirects
// straight back the way the API's callback would; no API server runs.
//
// The popup is a new page of the same context, so its routes are on the context.

import { test, expect, type Locator, type Page, type Route, type TestInfo } from '@playwright/test';
import { HOST, ORIGIN } from './e2e-port';

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

const EMAIL = 'sam@example.test';
const ADDRESS = '0x1111111111111111111111111111111111111111';
const SIWE = `${HOST} wants you to sign in with your Ethereum account:\n${ADDRESS}\n\nSign in\n\nURI: ${ORIGIN}\nVersion: 1\nChain ID: 1\nNonce: 12345678\nIssued At: 2026-10-15T00:00:00.000Z`;
const RELAY = 'x7f2k9q4bd@privaterelay.appleid.com';
const signedIn = (email = EMAIL) => ({
  session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() },
  user: { id: 'u', email, name: 'Sam' },
});

type Continuation = { outcome: 'new_account' | 'account_exists'; email: string; isPrivateEmail?: boolean };
type Body = Record<string, unknown> | null;

interface Stub {
  calls: Array<{ path: string; method: string; body: Body; url: URL }>;
  count: (path: string) => number;
  state: { signedIn: boolean; linked: Array<{ providerId: string; accountId: string }> };
}

/**
 * The API, and Apple: `appleReturn` is the query Apple's stub sends the popup
 * back with (what the API's callback hook would put on the redirect).
 */
async function stubApi(page: Page, options: {
  providers?: string[];
  providersDelay?: Promise<void>;
  /** The query Apple's stub returns with. Native returns go to the start's `errorCallbackURL`. */
  appleReturn?: string;
  native?: boolean;
  continuation?: Continuation;
  confirm?: (route: Route) => unknown;
  account?: Record<string, unknown>;
  unlink?: (route: Route) => unknown;
  linked?: Array<{ providerId: string; accountId: string }>;
} = {}): Promise<Stub> {
  const calls: Stub['calls'] = [];
  const state: Stub['state'] = { signedIn: false, linked: options.linked ?? [] };
  const context = page.context();
  await context.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const method = route.request().method();
    const body: Body = method === 'POST' ? route.request().postDataJSON() : null;
    calls.push({ path, method, body, url });
    if (path === '/api/auth/get-session') {
      return route.fulfill({
        status: 200, contentType: 'application/json',
        headers: state.signedIn ? { 'set-auth-token': 'session-cookie-token' } : {},
        body: JSON.stringify(state.signedIn ? signedIn(options.account?.email as string | undefined) : null),
      });
    }
    if (path === '/api/auth/providers') {
      await options.providersDelay;
      return json(route, { providers: options.providers ?? ['google', 'apple'] });
    }
    if (path === '/api/auth/sign-in/social' || path === '/api/auth/link-social') {
      return json(route, { url: `https://appleid.apple.com/auth/authorize?client_id=so.openkey.signin&state=st`, redirect: false });
    }
    if (path === '/api/auth/social/continuation') {
      if (!options.continuation) return json(route, { message: 'Invalid continuation' }, 400);
      return json(route, { providerId: 'apple', name: 'Sam', ...options.continuation });
    }
    if (path === '/api/auth/social/confirm') {
      if (options.confirm) return options.confirm(route);
      state.signedIn = true;
      return json(route, { token: 'apple-session', user: { id: 'u', email: options.continuation?.email } });
    }
    if (path === '/api/auth/list-accounts') {
      return json(route, [{ id: 'cred', providerId: 'credential', accountId: 'u' }, ...state.linked.map((a, i) => ({ id: `a${i}`, ...a }))]);
    }
    if (path === '/api/account' && method === 'GET') {
      return json(route, { user: { id: 'u', email: EMAIL, emailVerified: true, _count: { passkeys: 0, ethereumKeys: 1 }, ...options.account } });
    }
    if (path === '/api/account/step-up/email-otp/send') return json(route, { status: true });
    if (path === '/api/account/step-up/email-otp/verify') {
      return body?.code === '123456' ? json(route, { status: true }) : json(route, { error: 'Invalid or expired account verification code' }, 400);
    }
    if (path === '/api/account/social/unlink') {
      if (options.unlink) return options.unlink(route);
      state.linked = state.linked.filter((a) => a.providerId !== body?.providerId);
      return json(route, { status: true });
    }
    if (path === '/api/keys') return json(route, { keys: [{ id: 'key-1', address: '0xabc', keyIndex: 0 }] });
    if (path === '/api/keys/selected-key') {
      return json(route, { key: { id: 'selected-key', address: ADDRESS, publicKey: '0x02', keyIndex: 0, label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z' } });
    }
    if (path.includes('passkey/list-user-passkeys')) return json(route, []);
    if (path === '/api/account/auto-sign') return json(route, { autoSignEnabled: false });
    if (path.includes('tinycloud') && path.endsWith('/branding')) {
      return json(route, { clientId: 'exo-native', name: 'TinyCloud Home', icon: null, organization: 'TinyCloud Labs', theme: {} });
    }
    if (path.includes('tinycloud')) return json(route, { tinyCloudManageKeyEnabled: true, mode: 'APP_MANAGED', policyEpoch: 0, apps: [], activity: [] });
    if (path === '/api/auth/oauth2/authorize') {
      return route.fulfill({ status: 200, contentType: 'text/html', body: '<p>authorize</p>' });
    }
    return json(route, {});
  });
  // Apple's page: the user consents, and the API's callback redirects to the return URL with its answer.
  await context.route('https://appleid.apple.com/**', (route) => {
    const start = calls.findLast((call) => call.path === '/api/auth/sign-in/social' || call.path === '/api/auth/link-social');
    let back: string;
    if (options.native) {
      const errorCallbackURL = String(start?.body?.errorCallbackURL);
      back = options.appleReturn ? `${errorCallbackURL}&${options.appleReturn}` : String(start?.body?.callbackURL);
    } else {
      const url = new URL(`${ORIGIN}/auth/social/callback`);
      url.search = options.appleReturn ?? 'via=apple';
      back = url.href;
    }
    return route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: `<!doctype html><title>Apple</title><script>location.replace(${JSON.stringify(back)});</script>`,
    });
  });
  return { calls, state, count: (path) => calls.filter((call) => call.path === path).length };
}

async function shot(target: Page | Locator, info: TestInfo, name: string) {
  const path = info.outputPath(`${name}.png`);
  await ('goto' in target ? target.screenshot({ path, fullPage: true }) : target.screenshot({ path }));
}

async function openApplePopup(page: Page, button = page.getByRole('button', { name: 'Continue with Apple' })) {
  const popup = page.waitForEvent('popup');
  await button.click();
  const opened = await popup;
  // A popup that fails or completes at once may already be closing.
  await opened.setViewportSize({ width: 390, height: 844 }).catch(() => {});
  return opened;
}

const closed = (popup: Page) => (popup.isClosed() ? Promise.resolve() : popup.waitForEvent('close').then(() => {}));

test.use({ viewport: { width: 390, height: 844 }, colorScheme: 'light' });

test('login: the Apple button arrives with /providers and gates nothing', async ({ page }, info) => {
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  await stubApi(page, { providersDelay: held });
  await page.goto('/auth/login');
  await page.waitForLoadState('domcontentloaded');
  // Email and passkey work while /providers is still outstanding.
  await expect(page.getByRole('button', { name: 'Continue with email' })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Use a passkey instead' })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Continue with Apple' })).toHaveCount(0);
  release();
  await expect(page.getByRole('button', { name: 'Continue with Apple' })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Continue with Google' })).toBeEnabled();
  await shot(page, info, '01-login-apple-button');
});

test('new account: the popup asks first, and only Create makes the account and hands the session back', async ({ page }, info) => {
  const api = await stubApi(page, {
    appleReturn: 'via=apple&error=new_account&continuation=cont-1',
    continuation: { outcome: 'new_account', email: EMAIL, isPrivateEmail: false },
  });
  await page.goto('/auth/login');
  const popup = await openApplePopup(page);

  const confirmation = popup.getByTestId('new-account-confirmation');
  await expect(confirmation).toContainText(`No OpenKey account for ${EMAIL}`);
  await expect(confirmation.getByTestId('new-account-notice')).toHaveCount(0);
  for (const name of ['Create a new account', 'Sign in with a passkey', 'Recover your account', 'Use email instead']) {
    await expect(confirmation.getByRole('button', { name })).toBeVisible();
  }
  expect(api.count('/api/auth/social/confirm')).toBe(0);
  // The popup started Apple with a return URL that names the provider.
  const start = api.calls.find((call) => call.path === '/api/auth/sign-in/social')!;
  expect(start.body).toMatchObject({ provider: 'apple', callbackURL: `${ORIGIN}/auth/social/callback?via=apple`, disableRedirect: true });
  expect(api.calls.find((call) => call.path === '/api/auth/social/continuation')!.url.searchParams.get('continuation')).toBe('cont-1');
  await shot(popup, info, '02-new-account-confirmation');

  const closed = popup.waitForEvent('close');
  await confirmation.getByRole('button', { name: 'Create a new account' }).click();
  await closed;
  expect(api.calls.filter((call) => call.path === '/api/auth/social/confirm').map((call) => call.body)).toEqual([{ continuation: 'cont-1' }]);
  // The single handoff: the opener stored the session token and moved on.
  await expect(page).toHaveURL(/\/dashboard$/);
  expect(await page.evaluate(() => sessionStorage.getItem('openkey_session_token'))).toBe('apple-session');
});

test('Hide My Email: the confirmation says a new account is created, even from /auth/register', async ({ page }, info) => {
  const api = await stubApi(page, {
    appleReturn: 'via=apple&signup=1&error=new_account&continuation=cont-relay',
    continuation: { outcome: 'new_account', email: RELAY, isPrivateEmail: true },
  });
  await page.goto('/auth/register');
  const popup = await openApplePopup(page);
  const confirmation = popup.getByTestId('new-account-confirmation');
  await expect(confirmation.getByTestId('new-account-notice')).toHaveText(
    'Apple is hiding your email, so this creates a new OpenKey account. Already have one? Sign in to it and add Apple in Settings.',
  );
  await expect(confirmation).toContainText(RELAY);
  expect(api.calls.find((call) => call.path === '/api/auth/sign-in/social')!.body?.callbackURL)
    .toBe(`${ORIGIN}/auth/social/callback?via=apple&signup=1`);
  expect(api.count('/api/auth/social/confirm')).toBe(0);
  await shot(popup, info, '03-hide-my-email-confirmation');

  // "Use email instead" creates nothing and tells the opener why.
  const closed = popup.waitForEvent('close');
  await confirmation.getByRole('button', { name: 'Use email instead' }).click();
  await closed;
  await expect(page.getByRole('alert')).toContainText('Continue with your email instead.');
  expect(api.count('/api/auth/social/confirm')).toBe(0);
});

test('register: an explicit Apple sign-up with a shared email creates without asking again', async ({ page }) => {
  const api = await stubApi(page, {
    appleReturn: 'via=apple&signup=1&error=new_account&continuation=cont-reg',
    continuation: { outcome: 'new_account', email: EMAIL, isPrivateEmail: false },
  });
  await page.goto('/auth/register');
  const popup = await openApplePopup(page);
  await closed(popup);
  expect(api.calls.filter((call) => call.path === '/api/auth/social/confirm').map((call) => call.body)).toEqual([{ continuation: 'cont-reg' }]);
  expect(await page.evaluate(() => sessionStorage.getItem('openkey_session_token'))).toBe('apple-session');
});

test('account exists: nothing is linked; the user signs in and adds Apple after an email code (R3)', async ({ page }, info) => {
  const api = await stubApi(page, {
    appleReturn: 'via=apple&error=account_exists&continuation=cont-exists',
    continuation: { outcome: 'account_exists', email: EMAIL },
  });
  await page.goto('/auth/login');
  const popup = await openApplePopup(page);
  const step = popup.getByTestId('social-account-exists');
  await expect(step).toContainText(
    `An OpenKey account already uses ${EMAIL}. Sign in to it and verify with an email code to add Apple in Settings.`,
  );
  await expect(step.getByRole('button', { name: 'Create a new account' })).toHaveCount(0);
  await shot(popup, info, '04-account-exists');

  const closed = popup.waitForEvent('close');
  await step.getByRole('button', { name: 'Return to sign-in' }).click();
  await closed;
  await expect(page.getByRole('alert')).toContainText('Sign in to your existing account, then add Apple in Settings.');
  expect(api.count('/api/auth/social/confirm')).toBe(0);
  expect(api.count('/api/auth/link-social')).toBe(0);
  await expect(page.getByRole('button', { name: 'Continue with email' })).toBeEnabled();
});

test('apple_email_required: the opener explains, and stays signed out', async ({ page }, info) => {
  const api = await stubApi(page, { appleReturn: 'via=apple&error=apple_email_required' });
  await page.goto('/auth/login');
  const popup = await openApplePopup(page);
  // The popup reports the failure to its opener, which closes it and shows why.
  await closed(popup);
  await expect(page.getByRole('alert')).toHaveText(
    "Apple didn't share a verified email, so OpenKey can't create an account from it. Sign in with your email or passkey, then add Apple in Settings.",
  );
  await shot(page, info, '05-apple-email-required');
  expect(api.count('/api/auth/social/continuation')).toBe(0);
  expect(await page.evaluate(() => sessionStorage.getItem('openkey_session_token'))).toBeNull();
  await expect(page.getByRole('button', { name: 'Continue with email' })).toBeEnabled();
});

test('an expired or foreign continuation is refused, never shown', async ({ page }) => {
  const api = await stubApi(page, { appleReturn: 'via=apple&error=new_account&continuation=stale' });
  await page.goto('/auth/login');
  const popup = await openApplePopup(page);
  await closed(popup);
  await expect(page.getByRole('alert')).toHaveText('This Apple confirmation expired. Start sign-in again.');
  expect(api.count('/api/auth/social/confirm')).toBe(0);
});

test('a cancelled Apple popup leaves the page as it was', async ({ page }) => {
  await stubApi(page);
  await page.goto('/auth/login');
  await page.context().route('https://appleid.apple.com/**', (route) => route.fulfill({ status: 200, contentType: 'text/html', body: '<title>Apple</title>' }));
  const popup = await openApplePopup(page);
  await popup.close();
  await expect(page.getByRole('alert')).toHaveText('Apple sign-in was cancelled.');
  await expect(page.getByRole('button', { name: 'Continue with Apple' })).toBeEnabled();
});

async function settings(page: Page) {
  await page.context().addCookies([{ name: 'better-auth.session_token', value: 'cookie-session', url: ORIGIN }]);
  await page.goto('/dashboard/settings');
  return page.getByRole('heading', { name: 'Linked sign-in methods' }).locator('xpath=ancestor::*[contains(@class,"mt-6")][1]');
}

test('settings: Apple links only after an email code, and the OpenKey email is unchanged', async ({ page }, info) => {
  const api = await stubApi(page);
  api.state.signedIn = true;
  const card = await settings(page);
  await expect(card.getByTestId('linked-apple')).toContainText('Not linked');
  await shot(card, info, '06-settings-linked-methods');

  await card.getByRole('button', { name: 'Link Apple' }).click();
  await expect(card.getByLabel('Email verification code to link Apple')).toBeVisible();
  expect(api.count('/api/account/step-up/email-otp/send')).toBe(1);
  // A wrong code never reaches Apple.
  await card.getByLabel('Email verification code to link Apple').fill('000000');
  await card.getByRole('button', { name: 'Verify code' }).click();
  await expect(card.getByRole('alert')).toContainText('Incorrect or expired code');
  expect(api.count('/api/auth/link-social')).toBe(0);

  await card.getByLabel('Email verification code to link Apple').fill('123456');
  await card.getByRole('button', { name: 'Verify code' }).click();
  await expect(card.getByRole('button', { name: 'Continue to Apple' })).toBeVisible();
  expect(api.count('/api/auth/link-social')).toBe(0);
  await shot(card, info, '07-settings-link-verified');

  api.state.linked = [{ providerId: 'apple', accountId: 'apple-sub' }];
  const popup = await openApplePopup(page, card.getByRole('button', { name: 'Continue to Apple' }));
  await closed(popup);
  const link = api.calls.find((call) => call.path === '/api/auth/link-social')!;
  expect(link.body).toMatchObject({ provider: 'apple', callbackURL: `${ORIGIN}/auth/social/callback?via=apple` });
  await expect(card.getByRole('status')).toHaveText('Apple is linked to this OpenKey account. Your OpenKey email is unchanged.');
  await expect(card.getByTestId('linked-apple')).toContainText('Linked');
});

test('settings: Apple unlinks after an email code, with the Apple account named', async ({ page }) => {
  const api = await stubApi(page, { linked: [{ providerId: 'apple', accountId: 'apple-sub' }], account: { _count: { passkeys: 1 } } });
  api.state.signedIn = true;
  const card = await settings(page);
  await card.getByRole('button', { name: 'Unlink Apple' }).click();
  await card.getByLabel('Email verification code to unlink Apple').fill('123456');
  await card.getByRole('button', { name: 'Verify code' }).click();
  await expect(card.getByRole('status')).toHaveText('Apple was unlinked. You can still sign in with your email or passkey.');
  expect(api.calls.find((call) => call.path === '/api/account/social/unlink')!.body).toEqual({ providerId: 'apple', accountId: 'apple-sub' });
  await expect(card.getByTestId('linked-apple')).toContainText('Not linked');
});

test('settings: the API refusing the last sign-in method keeps Apple linked (R8)', async ({ page }) => {
  const api = await stubApi(page, {
    linked: [{ providerId: 'apple', accountId: 'apple-sub' }],
    unlink: (route) => json(route, { error: 'LAST_SIGN_IN_METHOD' }, 403),
  });
  api.state.signedIn = true;
  const card = await settings(page);
  await card.getByRole('button', { name: 'Unlink Apple' }).click();
  await card.getByLabel('Email verification code to unlink Apple').fill('123456');
  await card.getByRole('button', { name: 'Verify code' }).click();
  await expect(card.getByRole('alert')).toHaveText('Apple is your only way to sign in. Add a passkey before you remove it.');
  await expect(card.getByTestId('linked-apple')).toContainText('Linked');
});

test('settings: a relay email Apple stopped forwarding says so, and unlink is refused up front', async ({ page }, info) => {
  const api = await stubApi(page, {
    linked: [{ providerId: 'apple', accountId: 'apple-sub' }],
    account: { email: RELAY, emailUndeliverable: true },
  });
  api.state.signedIn = true;
  const card = await settings(page);
  await expect(card.getByTestId('email-undeliverable')).toContainText(`Apple has stopped forwarding email to ${RELAY}`);
  await expect(card.getByRole('button', { name: 'Unlink Apple' })).toBeDisabled();
  await expect(card.getByTestId('unlink-refused')).toContainText('Add a passkey before removing a linked method');
  await shot(card, info, '08-settings-undeliverable');
  expect(api.count('/api/account/step-up/email-otp/send')).toBe(0);
});

test('settings: a relay email that still forwards gets a quiet note', async ({ page }) => {
  const api = await stubApi(page, { linked: [{ providerId: 'apple', accountId: 'apple-sub' }], account: { email: RELAY } });
  api.state.signedIn = true;
  const card = await settings(page);
  await expect(card.getByTestId('email-relay')).toContainText('Apple Hide My Email address');
  await expect(card.getByRole('button', { name: 'Unlink Apple' })).toBeEnabled();
});

// TC-1183: the Apple button is a layout change inside the measured widget,
// the Apple popup hands its session to the iframe that opened it, and Approve
// stays gated until the host acknowledges the latest layout.
test('embedded sign: Apple is a measured layout change, signs the iframe in, and Approve waits for layout', async ({ page }, info) => {
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  const api = await stubApi(page, { providersDelay: held });
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const frame = document.createElement('iframe');
    frame.id = 'sign-v2';
    frame.style.width = '360px';
    frame.style.height = '300px';
    frame.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=phase-a&protocolVersion=2&keyId=selected-key`;
    document.body.append(frame);
    // The harness page's own record of what the frame posted.
    const harness = window as unknown as { received: unknown[] };
    harness.received = [];
    window.addEventListener('message', (event) => {
      if (event.source === frame.contentWindow) harness.received.push(event.data);
    });
  });
  const frame = page.frameLocator('#sign-v2');
  type Resize = { type: string; height: number; layoutId: number };
  const resizes = () => page.evaluate(() => {
    const harness = window as unknown as { received: Resize[] };
    return harness.received.filter((m) => m.type === 'openkey:resize');
  });
  const ack = (resize: Resize) => page.evaluate(({ height, layoutId }) => {
    const iframe = document.querySelector<HTMLIFrameElement>('#sign-v2')!;
    iframe.style.height = `${height}px`;
    iframe.contentWindow!.postMessage({ type: 'openkey:layout-applied', requestId: 'phase-a', protocolVersion: 2, height, layoutId }, location.origin);
  }, resize);

  await expect.poll(() => page.evaluate(() => {
    const harness = window as unknown as { received: Array<{ type: string }> };
    return harness.received.some((m) => m.type === 'openkey:ready');
  })).toBe(true);
  await page.evaluate((message) => {
    document.querySelector<HTMLIFrameElement>('#sign-v2')!.contentWindow!.postMessage(
      { type: 'openkey:sign:request', requestId: 'phase-a', protocolVersion: 2, keyId: 'selected-key', message }, location.origin);
  }, SIWE);

  // Email works before /providers answers.
  await expect(frame.getByRole('button', { name: 'Continue with email' })).toBeEnabled();
  await expect(frame.getByRole('button', { name: 'Continue with Apple' })).toHaveCount(0);
  await expect.poll(async () => (await resizes()).length).toBeGreaterThan(0);
  const before = (await resizes()).at(-1)!;

  release();
  await expect(frame.getByRole('button', { name: 'Continue with Apple' })).toBeVisible();
  await expect.poll(async () => (await resizes()).at(-1)!.layoutId).toBeGreaterThan(before.layoutId);
  const after = (await resizes()).at(-1)!;
  expect(after.height).toBeGreaterThan(before.height);
  await ack(after);
  await shot(page, info, '09-embedded-apple-button');

  // A returning Apple user: the API's callback signs the popup's first-party context in.
  api.state.signedIn = true;
  const popup = await openApplePopup(page, frame.getByRole('button', { name: 'Continue with Apple' }));
  await closed(popup);
  // The session token the popup handed back lives in the iframe's own storage.
  await expect.poll(() => frame.locator('body').evaluate(() => sessionStorage.getItem('openkey_session_token')))
    .toBe('session-cookie-token');
  const approve = frame.getByRole('button', { name: 'Approve', exact: true });
  await expect(approve).toBeVisible();
  // The sign-in step's acknowledged layout cannot approve the review that replaced it.
  await expect(approve).toBeDisabled();
  await expect.poll(async () => (await resizes()).at(-1)!.layoutId).toBeGreaterThan(after.layoutId);
  await ack(after);
  await expect(approve).toBeDisabled();
  await ack((await resizes()).at(-1)!);
  await expect(approve).toBeEnabled();
});

// Native (TC-1188 §1.2): the sheet returns to /auth/login?<signedQuery>, and the
// signed authorize query is kept through confirmation and on to /authorize.
const NATIVE_QUERY = new URLSearchParams({
  response_type: 'code', client_id: 'exo-native', redirect_uri: 'xyz.tinycloud.exo://openkey/callback', scope: 'openid',
  state: 'st-1', tinycloud_request: 'req-1', login_method: 'apple', exp: '9999999999', ba_iat: '1', sig: 'signed',
}).toString();
// The API's continuation is 32 random bytes, base64url.
const NATIVE_CONTINUATION = 'A'.repeat(43);

test.describe('native sheet', () => {
  test('Hide My Email: the sheet asks first, and Create carries the signed query to /authorize', async ({ page }, info) => {
    const api = await stubApi(page, {
      native: true,
      appleReturn: `error=new_account&continuation=${NATIVE_CONTINUATION}`,
      continuation: { outcome: 'new_account', email: RELAY, isPrivateEmail: true },
    });
    await page.goto(`/auth/login?${NATIVE_QUERY}`);
    await expect.poll(() => api.count('/api/auth/social/continuation')).toBe(1);
    expect(api.calls.find((call) => call.path === '/api/auth/sign-in/social')!.body).toMatchObject({
      provider: 'apple',
      callbackURL: `${ORIGIN}/auth/login?${NATIVE_QUERY}`,
      errorCallbackURL: `${ORIGIN}/auth/login?${NATIVE_QUERY}&native_social_error=apple`,
    });
    const lookup = api.calls.find((call) => call.path === '/api/auth/social/continuation')!.url.searchParams;
    expect(lookup.get('continuation')).toBe(NATIVE_CONTINUATION);
    expect(lookup.get('oauthQuery')).toBe(NATIVE_QUERY);

    await expect(page.getByTestId('new-account-notice')).toHaveText(
      'Apple is hiding your email, so this creates a new OpenKey account. Already have one? Sign in to it and add Apple in Settings.',
    );
    await expect(page.getByRole('button', { name: 'Sign in with a passkey' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Recover your account' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Use email instead' })).toBeVisible();
    expect(api.count('/api/auth/social/confirm')).toBe(0);
    await shot(page, info, '10-native-hide-my-email');

    await page.getByRole('button', { name: 'Create a new account' }).click();
    await expect(page).toHaveURL(/\/api\/auth\/oauth2\/authorize\?/);
    expect(api.calls.find((call) => call.path === '/api/auth/social/confirm')!.body)
      .toEqual({ continuation: NATIVE_CONTINUATION, oauthQuery: NATIVE_QUERY });
    expect(new URL(page.url()).search.slice(1)).toBe(NATIVE_QUERY);
  });

  test('account exists: the sheet signs in to the existing account, then continues the same request', async ({ page }, info) => {
    const api = await stubApi(page, {
      native: true,
      appleReturn: `error=account_exists&continuation=${NATIVE_CONTINUATION}`,
      continuation: { outcome: 'account_exists', email: EMAIL },
    });
    await page.goto(`/auth/login?${NATIVE_QUERY}`);
    await expect(page.getByTestId('social-account-exists')).toHaveText(
      `An OpenKey account already uses ${EMAIL}. Sign in to it and verify with an email code to add Apple in Settings.`,
    );
    await expect(page.getByRole('button', { name: 'Create a new account' })).toHaveCount(0);
    await shot(page, info, '11-native-account-exists');
    await page.getByRole('button', { name: 'Sign in to your account' }).click();
    await expect(page.locator('#email')).toHaveValue(EMAIL);
    expect(api.count('/api/auth/social/confirm')).toBe(0);
    expect(api.count('/api/auth/link-social')).toBe(0);
    // The page still serves the original signed request.
    expect(new URL(page.url()).searchParams.get('sig')).toBe('signed');
  });

  test('apple_email_required: the sheet explains on the email step', async ({ page }, info) => {
    const api = await stubApi(page, { native: true, appleReturn: 'error=apple_email_required' });
    await page.goto(`/auth/login?${NATIVE_QUERY}`);
    await expect(page.getByRole('alert')).toHaveText(
      "Apple didn't share a verified email, so OpenKey can't create an account from it. Sign in with your email or passkey, then add Apple in Settings.",
    );
    await expect(page.locator('#email')).toBeVisible();
    expect(api.count('/api/auth/social/continuation')).toBe(0);
    await shot(page, info, '12-native-apple-email-required');
  });

  test('a continuation the API refuses for this request is not shown', async ({ page }) => {
    const api = await stubApi(page, { native: true, appleReturn: `error=new_account&continuation=${NATIVE_CONTINUATION}` });
    await page.goto(`/auth/login?${NATIVE_QUERY}`);
    await expect(page.getByRole('alert')).toHaveText('This Apple confirmation expired. Start sign-in again.');
    await expect(page.getByRole('button', { name: 'Create a new account' })).toHaveCount(0);
    expect(api.count('/api/auth/social/confirm')).toBe(0);
  });
});
