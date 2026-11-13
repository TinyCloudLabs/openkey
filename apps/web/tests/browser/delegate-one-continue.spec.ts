// TC-2322: the paste-link approval (/delegate) has ONE sign-in entry. Sign-up and sign-in are the same action
// (Continue with Google / email / passkey), the Google popup returns to the SAME page (no navigation of this tab), a
// brand-new account sees one welcome line on the approval, only the pressed button is busy, and the finished
// screen says the session went back. Every API call is answered by `page.route`; no API server runs.

import { test, expect, type Page, type Route } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';

const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const space = `tinycloud:pkh:eip155:1:${address}:default`;
const KV_GET = 'tinycloud.kv/get', CAPS_READ = 'tinycloud.capabilities/read';
const siwe = [
  'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
  'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-03T00:00:00.000Z', 'Expiration Time: 2026-11-03T01:00:00.000Z',
  'Resources:',
  `- ${makeRecapResource({ [`${space}/capabilities`]: { [CAPS_READ]: [{}] }, [`${space}/kv/notes/`]: { [KV_GET]: [{}] } })}`,
].join('\n');
const option = (service: string, short: string, path: string, ability: string, required: boolean) => {
  const key = `${service}\0${space}\0${path}`;
  return { key, service: short, path, label: short, resourcePath: path ? `${short}/${path}` : short,
    actions: [{ key: `${key}\0${ability}`, action: ability.split('/')[1], ability, required }] };
};
const permissions = [option('tinycloud.capabilities', 'capabilities', '', CAPS_READ, true), option('tinycloud.kv', 'kv', 'notes/', KV_GET, false)];
const prepared = { prepared: { siwe, spaceId: space, jwk: {} }, spaceId: space, ownerDid: `did:pkh:eip155:1:${address}`, address, chainId: 1,
  host: 'https://node.tinycloud.xyz', permissions, selectedActionKeys: permissions.flatMap((p) => p.actions.map((a) => a.key)), edited: false,
  authorizationContext: { token: 't', expiresAt: Date.now() + 600_000, baselineAbilitiesDigest: 'd' } };
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const oneKey = [{ id: 'key_1', address, publicKey: '0x', keyIndex: 0, label: null, keyType: 'MANAGED', createdAt: new Date().toISOString() }];
const jwk = encodeBase64UrlJson({ kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
const link = `/delegate?did=did:key:z6Mk&jwk=${jwk}`;

type Account = 'new' | 'returning';

/** The session the popup signed in: a new account's user and first session are stamped together. */
function sessionBody(account: Account) {
  const now = Date.now();
  const userCreated = account === 'new' ? now - 400 : now - 90 * 24 * 3_600_000;
  return {
    session: { id: 's', userId: 'u', createdAt: new Date(now).toISOString(), expiresAt: new Date(now + 3_600_000).toISOString() },
    user: { id: 'u', email: 'qa@example.test', name: 'QA', createdAt: new Date(userCreated).toISOString() },
  };
}

async function mockApi(page: Page, account: Account, delegation: Record<string, unknown> = {}) {
  // `confirm`: the email has no account yet (the code is verified, then the user confirms creating one).
  const state = { signedIn: false, confirm: false, keyAuth: [] as Array<string | undefined> };
  const signedInAs = (route: Route, token: string) => {
    state.signedIn = true;
    return route.fulfill({
      status: 200, contentType: 'application/json', headers: { 'set-auth-token': token },
      body: JSON.stringify({ token, ...sessionBody(account) }),
    });
  };
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/auth/email-otp/send-verification-otp') return json(route, 200, { success: true });
    if (url.pathname === '/api/auth/sign-in/email-otp') {
      return state.confirm
        ? json(route, 403, { code: 'NEW_ACCOUNT_CONFIRMATION_REQUIRED', message: 'No OpenKey account exists for this email.', signupToken: 'signup-1' })
        : signedInAs(route, 'tok-A');
    }
    if (url.pathname === '/api/auth/sign-up/email-otp') return signedInAs(route, 'tok-A');
    if (url.pathname === '/api/auth/sign-out') { state.signedIn = false; return json(route, 200, { success: true }); }
    if (url.pathname === '/api/auth/get-session') return json(route, 200, state.signedIn ? sessionBody(account) : null);
    if (url.pathname === '/api/auth/providers') return json(route, 200, { providers: ['google'] });
    if (url.pathname === '/api/keys') { state.keyAuth.push(route.request().headers()['authorization']); return json(route, 200, { keys: oneKey }); }
    if (url.pathname === '/api/delegate/prepare') return json(route, 200, prepared);
    if (url.pathname === '/api/delegate') {
      return json(route, 200, { delegationHeader: { Authorization: 'Bearer x' }, delegationCid: 'bafy', spaceId: space, hostActivated: true, ...delegation });
    }
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });
  return state;
}

/** The popup's own page: signs the account in (server side), tells its opener, closes, as /auth/social/callback does. */
async function mockGooglePopup(page: Page, state: { signedIn: boolean }, hold = false) {
  await page.context().route('**/auth/social/callback**', (route) => {
    if (hold) return route.fulfill({ status: 200, contentType: 'text/html', body: '<!doctype html><title>Google</title><p>waiting</p>' });
    state.signedIn = true;
    return route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: '<!doctype html><script>window.opener.postMessage({ type: "openkey:social:complete", sessionToken: "popup-session" }, location.origin); window.close();</script>',
    });
  });
}

const approve = (page: Page) => page.getByRole('button', { name: 'Approve', exact: true });
const google = (page: Page) => page.getByRole('button', { name: 'Continue with Google' });
const email = (page: Page) => page.getByRole('button', { name: 'Continue with email' });
const passkey = (page: Page) => page.getByRole('button', { name: /passkey/i });

test('the signed-out approval offers one Continue entry and no Register or Login page', async ({ page }) => {
  await mockApi(page, 'new');
  await page.goto(link);
  await expect(google(page)).toBeVisible();
  await expect(email(page)).toBeVisible();
  await expect(passkey(page)).toBeVisible();
  await expect(page.getByRole('link', { name: 'Register', exact: true })).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'Recover account' })).toBeVisible();
});

test('Google sign-up returns to the same approval: this tab never navigates, one popup, no reload', async ({ page }) => {
  const state = await mockApi(page, 'new');
  await mockGooglePopup(page, state);
  const documents: string[] = [];
  page.on('framenavigated', (frame) => { if (frame === page.mainFrame()) documents.push(frame.url()); });
  let popups = 0;
  page.context().on('page', () => { popups += 1; });

  await page.goto(link);
  await expect(google(page)).toBeVisible();
  const afterFirstLoad = documents.length;
  await google(page).click();
  await expect(approve(page)).toBeEnabled();

  expect(documents.length).toBe(afterFirstLoad); // no page change of this tab from the click to the approval
  expect(popups).toBe(1);
  expect(page.url()).toBe(new URL(link, page.url()).href);
});

test('while the Google window is open only the pressed button is busy; the others are disabled, not busy', async ({ page }) => {
  const state = await mockApi(page, 'new');
  await mockGooglePopup(page, state, true);
  await page.goto(link);
  await google(page).click();
  await expect(google(page)).toHaveAttribute('aria-busy', 'true');
  await expect(google(page)).toContainText('Connecting to Google…');
  await expect(google(page)).toBeDisabled();
  await expect(email(page)).toBeDisabled();
  await expect(email(page)).not.toHaveAttribute('aria-busy', 'true');
  await expect(passkey(page)).toBeDisabled();
  await expect(passkey(page)).not.toHaveAttribute('aria-busy', 'true');
  await expect(passkey(page)).not.toContainText('Waiting for passkey');
});

test('a first-time account sees one "Welcome to OpenKey" line on the approval; a returning account sees none', async ({ page }) => {
  const state = await mockApi(page, 'new');
  await mockGooglePopup(page, state);
  await page.goto(link);
  await google(page).click();
  await expect(approve(page)).toBeEnabled();
  await expect(page.getByText('Welcome to OpenKey')).toHaveCount(1);

  const returning = await page.context().newPage();
  const back = await mockApi(returning, 'returning');
  await mockGooglePopup(returning, back);
  await returning.goto(link);
  await google(returning).click();
  await expect(approve(returning)).toBeEnabled();
  await expect(returning.getByText('Welcome to OpenKey')).toHaveCount(0);
});

test('after Approve the finished screen says the approval was sent back', async ({ page }) => {
  const state = await mockApi(page, 'new');
  await mockGooglePopup(page, state);
  await page.route('http://127.0.0.1:47123/callback', (route) => route.fulfill({
    status: 200, contentType: 'application/json',
    headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type' }, body: '{"success":true}',
  }));
  await page.goto(`${link}&callback=${encodeURIComponent('http://127.0.0.1:47123/callback')}`);
  await google(page).click();
  await approve(page).click();
  await expect(page.getByRole('heading', { name: 'Approved. Your sign-in was sent back to your agent.' })).toBeVisible();
});

test('on /auth/login, while the Google window is open, the other buttons keep their words and are only disabled', async ({ page }) => {
  const state = await mockApi(page, 'new');
  await mockGooglePopup(page, state, true);
  await page.goto('/auth/login');
  await page.getByRole('button', { name: 'Continue with Google' }).click();
  await expect(page.getByRole('button', { name: 'Continue with Google' })).toContainText('Connecting to Google…');
  const other = (name: string) => page.getByRole('button', { name });
  await expect(other('Continue with email')).toBeDisabled();
  await expect(other('Use a passkey instead')).toBeDisabled();
  await expect(page.getByText('Sending code…')).toHaveCount(0);
  await expect(page.getByText('Waiting for passkey…')).toHaveCount(0);
});

async function signInWithEmailCode(page: Page) {
  await email(page).click();
  await page.getByLabel('Email address').fill('qa@example.test');
  await page.getByRole('button', { name: 'Send code' }).click();
  await page.getByLabel('Verification code').fill('123456');
  await page.getByRole('button', { name: 'Verify and continue' }).click();
}

test('an existing email reaches the approval by code, in place, with no welcome', async ({ page }) => {
  await mockApi(page, 'returning');
  await page.goto(link);
  await signInWithEmailCode(page);
  await expect(approve(page)).toBeEnabled();
  await expect(page.getByText('Welcome to OpenKey')).toHaveCount(0);
});

test('a new email is asked before an account is created, then reaches the approval with the welcome', async ({ page }) => {
  const state = await mockApi(page, 'new');
  state.confirm = true;
  await page.goto(link);
  await signInWithEmailCode(page);
  await expect(page.getByText('No OpenKey account for')).toBeVisible();
  await expect(approve(page)).toHaveCount(0);
  await page.getByRole('button', { name: 'Create a new account' }).click();
  await expect(approve(page)).toBeEnabled();
  await expect(page.getByText('Welcome to OpenKey')).toHaveCount(1);
});

test('Sign out clears the email session token, so the next account\'s calls carry no stale bearer', async ({ page }) => {
  const state = await mockApi(page, 'returning');
  await page.goto(link);
  await signInWithEmailCode(page);
  await expect(approve(page)).toBeEnabled();
  expect(await page.evaluate(() => sessionStorage.getItem('openkey_session_token'))).toBeNull();
  expect(state.keyAuth.at(-1)).toBeUndefined();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(email(page)).toBeVisible();
  expect(await page.evaluate(() => sessionStorage.getItem('openkey_session_token'))).toBeNull();
});
