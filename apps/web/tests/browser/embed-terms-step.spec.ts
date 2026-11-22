// The embedded connect frame, on another site's page, shows the Terms in its own card when the account that just
// signed in owes them: the frame never navigates, and nothing loads /auth/login or /auth/terms (which refuse to be
// framed). Agree, once the frame has settled, records the acceptance with the frame's session token, and the
// connect flow goes on to the account's keys. Covered for each way in: an email code for a new address, an email
// code for an existing account, and a passkey. Every API call is answered by page.route; no API server runs.

import { readFileSync } from 'node:fs';
import { test, expect, type FrameLocator, type Page, type Request, type Route } from '@playwright/test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { HOST, LOOPBACK_ORIGIN, ORIGIN } from './e2e-port';

const json = (route: Route, body: unknown, status = 200, headers: Record<string, string> = {}) =>
  route.fulfill({ status, contentType: 'application/json', headers, body: JSON.stringify(body) });

const RELEASE = {
  version: '2027-03-15', effective: '2027-03-15', whatChanged: null, privacyChanged: false,
  requiresAcceptance: true, previouslyAccepted: false,
};
const key = (id: string, keyIndex: number, address: string, isPrimary: boolean) =>
  ({ id, address, publicKey: '0x', keyIndex, label: `Key ${keyIndex}`, keyType: 'MANAGED', isPrimary, createdAt: '2026-01-01T00:00:00Z' });
const KEYS = [
  key('key_0', 0, '0xd559ccd9eb87c530a9a349262669386de93cf412', true),
  key('key_1', 1, '0x2222222222222222222222222222222222222222', false),
];
const NEW_EMAIL = 'newcomer@example.test';
const EXISTING_EMAIL = 'returning@example.test';
const credentialId = randomBytes(16);

type Seen = { path: string; authorization: string | undefined; body: unknown };
/** Every API call the frame made, every page load, and whether the account has agreed. */
type MockedApi = { seen: Seen[]; pages: string[]; agreedTo: () => boolean };

async function mockApi(page: Page): Promise<MockedApi> {
  const seen: Seen[] = [];
  const pages: string[] = [];
  let agreed = false;
  let token: string | null = null;
  const signedIn = (route: Route, sessionToken: string, body: unknown = { token: sessionToken, user: { id: 'u' } }) => {
    token = sessionToken;
    return json(route, body, 200, { 'set-auth-token': sessionToken, 'access-control-expose-headers': 'set-auth-token' });
  };
  page.context().on('request', (request: Request) => {
    if (request.isNavigationRequest()) pages.push(new URL(request.url()).pathname);
  });
  await page.context().route(`${ORIGIN}/api/**`, (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const authorization = request.headers().authorization;
    seen.push({ path, authorization, body: request.postDataJSON?.() ?? null });
    const bearer = token !== null && authorization === `Bearer ${token}`;
    if (path === '/api/auth/get-session') return json(route, null);
    if (path === '/api/auth/providers') return json(route, { providers: [] });
    if (path === '/api/auth/email-otp/send-verification-otp') return json(route, { success: true });
    if (path === '/api/auth/sign-in/email-otp') {
      const { email } = request.postDataJSON() as { email: string };
      if (email === EXISTING_EMAIL) return signedIn(route, 'session-existing');
      return json(route, {
        code: 'NEW_ACCOUNT_CONFIRMATION_REQUIRED', message: 'No OpenKey account exists for this email.', signupToken: 'signup-1',
      }, 403);
    }
    if (path === '/api/auth/sign-up/email-otp') return signedIn(route, 'session-new');
    if (path === '/api/passkey/generate-authenticate-options') {
      return json(route, {
        challengeToken: 'challenge-1', challenge: randomBytes(32).toString('base64url'), rpId: 'localhost',
        userVerification: 'required', timeout: 60000, allowCredentials: [],
      });
    }
    if (path === '/api/passkey/verify-authentication') {
      return signedIn(route, 'session-passkey', { sessionToken: 'session-passkey', session: { id: 's' }, user: { id: 'u' } });
    }
    if (!bearer) return json(route, { error: 'unauthorized' }, 401);
    if (path === '/api/account/terms') return json(route, { ...RELEASE, requiresAcceptance: !agreed });
    if (path === '/api/account/terms/accept') {
      agreed = true;
      return json(route, { accepted: true, version: RELEASE.version });
    }
    if (path === '/api/keys') {
      return agreed
        ? json(route, { keys: KEYS })
        : json(route, { error: 'terms_required', terms_url: `${ORIGIN}/auth/terms` }, 403);
    }
    return json(route, { error: `unmocked ${path}` }, 404);
  });
  return { seen, pages, agreedTo: () => agreed };
}

/** Another site's page frames the connect widget, as an app embeds it. */
async function embed(page: Page): Promise<FrameLocator> {
  await page.goto(`${LOOPBACK_ORIGIN}/__parity_harness`);
  await page.evaluate(({ widget, host }) => {
    const frame = document.createElement('iframe');
    frame.id = 'openkey';
    frame.allow = 'publickey-credentials-get *';
    frame.style.width = '400px';
    frame.style.height = '720px';
    frame.src = `${widget}/widget/embed/connect?origin=${encodeURIComponent(host)}`;
    document.body.append(frame);
  }, { widget: ORIGIN, host: LOOPBACK_ORIGIN });
  return page.frameLocator('#openkey');
}

async function emailCode(frame: FrameLocator, email: string) {
  await frame.getByRole('button', { name: 'Continue with email' }).click();
  await frame.locator('#embed-email').fill(email);
  await frame.getByRole('button', { name: 'Send code' }).click();
  await frame.locator('#embed-otp').fill('123456');
  await frame.getByRole('button', { name: 'Verify and continue' }).click();
}

async function agreeInPlace(page: Page, frame: FrameLocator, api: MockedApi, sessionToken: string) {
  await expect(frame.getByRole('heading', { name: 'Accept the Terms and Privacy Policy' })).toBeVisible();
  const agree = frame.getByRole('button', { name: 'Agree and continue' });
  await expect(agree).toBeEnabled();
  expect(api.agreedTo()).toBe(false);
  await agree.click();
  await expect(frame.getByText('Connect with your primary key:')).toBeVisible();

  const accept = api.seen.find((call) => call.path === '/api/account/terms/accept');
  expect(accept).toMatchObject({ authorization: `Bearer ${sessionToken}`, body: { version: RELEASE.version, embedOrigin: LOOPBACK_ORIGIN } });
  // The frame stayed where it was: its only page load is the widget, and nothing asked for a sign-in or Terms page.
  expect(api.pages.filter((path) => path !== '/__parity_harness')).toEqual(['/widget/embed/connect']);
  expect(page.frames().map((frame) => new URL(frame.url()).pathname)).toContain('/widget/embed/connect');
  // The keys are read only once the account has agreed.
  expect(api.seen.filter((call) => call.path === '/api/keys').length).toBeGreaterThan(0);
  expect(api.seen.findIndex((call) => call.path === '/api/keys'))
    .toBeGreaterThan(api.seen.findIndex((call) => call.path === '/api/account/terms/accept'));
}

test('a new account made from an email code agrees to the Terms in the frame, and connect goes on', async ({ page }) => {
  const api = await mockApi(page);
  const frame = await embed(page);
  await emailCode(frame, NEW_EMAIL);
  await frame.getByTestId('new-account-confirmation').getByRole('button', { name: 'Create a new account' }).click();
  await agreeInPlace(page, frame, api, 'session-new');
});

test('an existing account signed in with an email code agrees in the frame', async ({ page }) => {
  const api = await mockApi(page);
  const frame = await embed(page);
  await emailCode(frame, EXISTING_EMAIL);
  await agreeInPlace(page, frame, api, 'session-existing');
});

test('an account signed in with a passkey agrees in the frame', async ({ page }) => {
  const api = await mockApi(page);
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
  } });
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  await cdp.send('WebAuthn.addCredential', { authenticatorId, credential: {
    credentialId: credentialId.toString('base64'), isResidentCredential: true, rpId: 'localhost',
    privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    userHandle: Buffer.from('u').toString('base64'), signCount: 0,
  } });
  const frame = await embed(page);
  await frame.getByRole('button', { name: 'Passkey' }).click();
  await agreeInPlace(page, frame, api, 'session-passkey');
});

/** The host page as the test drives it: the workspace SDK, the frame's messages and the request's outcome. */
type SdkHost = Window & {
  OpenKeyBeta?: new (options: { host: string; oauthHost: string; mode: 'iframe' }) => { signMessage(request: { message: string; keyId: string }): Promise<unknown> };
  widgetEvents?: string[];
  signState?: 'pending' | 'signed' | 'rejected';
};

// A Terms check with no answer never holds the frame blank: past the check's 8 s deadline the v2 Sign frame shows
// Try again and tells the host it is ready to show; Try again with an answer goes on to the review.
test('a Terms check that never answers shows Try again in a frame the host is told to show', async ({ page }) => {
  test.setTimeout(60_000);
  const address = '0x1111111111111111111111111111111111111111';
  const signingKey = { id: 'selected-key', address, publicKey: '0x02', keyIndex: 0, label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z' };
  const message = `${HOST} wants you to sign in with your Ethereum account:\n${address}\n\nSign in\n\nURI: ${ORIGIN}\nVersion: 1\nChain ID: 1\nNonce: 12345678\nIssued At: 2026-10-15T00:00:00.000Z`;
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'fixture-session'));
  await page.route('**/__sdk_beta.mjs', (route) => route.fulfill({
    contentType: 'text/javascript',
    body: readFileSync(new URL('../../../../packages/sdk/dist/index.mjs', import.meta.url)),
  }));
  await page.route('**/api/keys/**', (route) => route.request().url().endsWith('/sign')
    ? json(route, { signature: '0x00', address })
    : json(route, { key: signingKey }));
  await page.route('**/api/auth/get-session**', (route) => json(route, { session: { id: 'fixture-session' }, user: { id: 'fixture-user' } }));
  let answer = false;
  let checks = 0;
  await page.route('**/api/account/terms', (route) => {
    checks++;
    // The first check hangs: the request is never answered.
    if (answer) return json(route, { ...RELEASE, requiresAcceptance: false, previouslyAccepted: true });
  });

  // The message names this page's host (the SIWE domain), so the page is on ORIGIN and the widget on the loopback.
  await page.goto(`${ORIGIN}/__parity_harness`);
  await page.evaluate((widgetOrigin) => {
    const host = window as SdkHost;
    host.widgetEvents = [];
    window.addEventListener('message', (event) => {
      if (event.origin === widgetOrigin && event.data?.type?.startsWith('openkey:')) host.widgetEvents?.push(event.data.type);
    });
  }, LOOPBACK_ORIGIN);
  await page.addScriptTag({ type: 'module', content: `import { OpenKey } from '/__sdk_beta.mjs'; window.OpenKeyBeta = OpenKey;` });
  await expect.poll(() => page.evaluate(() => typeof (window as SdkHost).OpenKeyBeta)).toBe('function');
  await page.evaluate(([siwe, widgetOrigin]) => {
    const host = window as SdkHost;
    const sdk = new host.OpenKeyBeta!({ host: widgetOrigin, oauthHost: widgetOrigin, mode: 'iframe' });
    host.signState = 'pending';
    sdk.signMessage({ message: siwe, keyId: 'selected-key' })
      .then(() => { host.signState = 'signed'; }, () => { host.signState = 'rejected'; });
  }, [message, LOOPBACK_ORIGIN]);

  await expect.poll(() => page.frames().some((frame) => frame.url().includes('/widget/embed/sign?'))).toBe(true);
  const frame = page.frames().find((candidate) => candidate.url().includes('/widget/embed/sign?'))!;
  await expect.poll(() => checks).toBe(1);
  const started = Date.now();
  const failed = frame.getByTestId('terms-check-failed');
  await expect(failed).toBeVisible({ timeout: 15_000 });
  expect(Date.now() - started).toBeGreaterThan(6_000);
  await expect(failed).toContainText('Couldn’t check whether you’ve agreed to the Terms.');
  await expect.poll(() => page.evaluate(() => (window as SdkHost).widgetEvents?.includes('openkey:layout-ready'))).toBe(true);
  expect(await page.evaluate(() => (window as SdkHost).signState)).toBe('pending');

  answer = true;
  await failed.getByRole('button', { name: 'Try again' }).click();
  const approve = frame.locator('button:has-text("Approve")');
  await expect(approve).toBeEnabled();
  await approve.click();
  await expect.poll(() => page.evaluate(() => (window as SdkHost).signState)).toBe('signed');
  expect(checks).toBe(2);
});
