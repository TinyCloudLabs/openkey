// A click on the sign-in page after the email field's passkey sign-in has completed, while the page is still on
// /auth/login. The Chromium virtual authenticator answers the conditional request at once, as a fast authenticator
// does, and the server accepts it; the page then asks whether the terms are accepted before it leaves, and that
// answer is held for 1.5 s, so the sign-in form stays on screen with its buttons enabled. A click on the passkey
// button in that gap starts no second ceremony and no second verify request, a click on Continue sends no code, and
// a click on a social button starts no provider flow. Every API call is answered by page.route; no API server runs.

import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { test, expect, type Page, type Route } from '@playwright/test';
import { TERMS_ACCEPTED } from './terms-fixtures';

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

const VERIFY = '**/api/auth/passkey/verify-authentication';
const credentialId = randomBytes(16);

const signedQuery = () =>
  new URLSearchParams({
    response_type: 'code',
    client_id: 'exo-native',
    redirect_uri: 'xyz.tinycloud.exo://callback',
    scope: 'openid',
    state: 'st-1',
    tinycloud_request: 'req-1',
    login_method: 'email',
    exp: '9999999999',
    ba_iat: '1',
    sig: 'signed',
  }).toString();

const session = {
  session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() },
  user: { id: 'u', email: 'sam@example.test', name: 'Sam' },
};

async function mockApi(page: Page, signedIn: () => boolean, termsDelayMs: number, providers: string[]) {
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, null);
    if (path === '/api/auth/providers') return json(route, { providers });
    if (path === '/api/oauth/tinycloud/clients/exo-native/branding') {
      return json(route, { clientId: 'exo-native', name: 'Exo', icon: null, organization: 'TinyCloud Labs' });
    }
    if (path === '/api/keys') return json(route, { keys: [{ id: 'key-1', address: '0xabc' }] });
    if (path === '/api/auth/passkey/generate-authenticate-options') {
      return json(route, {
        challenge: randomBytes(32).toString('base64url'), rpId: 'localhost', allowCredentials: [], userVerification: 'preferred', timeout: 60000,
      });
    }
    if (path === '/api/auth/oauth2/authorize') {
      return route.fulfill({ status: 200, contentType: 'text/html', body: '<p>authorize</p>' });
    }
    return json(route, { error: `unmocked ${path}` }, 404);
  });
  // The terms answer that follows the sign-in is held, so the page stays on /auth/login for that long.
  await page.route('**/api/account/terms', async (route) => {
    if (signedIn()) await new Promise((resolve) => setTimeout(resolve, termsDelayMs));
    return route.fulfill({ json: TERMS_ACCEPTED });
  });
  await page.route('https://app.test/**', (route) => route.fulfill({ status: 200, contentType: 'text/html', body: '<p>app</p>' }));
}

async function virtualAuthenticator(page: Page) {
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
}

interface Get { conditional: boolean }

/**
 * Records every navigator.credentials.get call (the record outlives the navigation to the authorize page) and makes
 * conditional mediation available; the virtual authenticator answers all of them.
 */
async function watchCredentials(page: Page) {
  const gets: Get[] = [];
  await page.exposeFunction('__recordGet', (conditional: boolean) => { gets.push({ conditional }); });
  await page.addInitScript(() => {
    const record = (window as unknown as { __recordGet: (conditional: boolean) => void }).__recordGet;
    (PublicKeyCredential as unknown as { isConditionalMediationAvailable: () => Promise<boolean> }).isConditionalMediationAvailable = async () => true;
    const original = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = (options?: CredentialRequestOptions) => {
      record(options?.mediation === 'conditional');
      return original({ ...options, mediation: undefined });
    };
  });
  return gets;
}

interface SignedIn {
  gets: Get[];
  verifies: string[];
  requests: string[];
  popups: string[];
}

/**
 * Opens the sign-in page and lets the email field's passkey sign-in complete. The terms answer that follows is held,
 * so the page is on /auth/login, signed in, with its sign-in form on screen. `requests` lists every request the page
 * makes after that point.
 */
async function signedInByAutofill(page: Page, options: { native: boolean; providers: string[] }): Promise<SignedIn> {
  await virtualAuthenticator(page);
  const gets = await watchCredentials(page);
  const verifies: string[] = [];
  await mockApi(page, () => verifies.length > 0, 1500, options.providers);
  await page.route(VERIFY, (route) => {
    verifies.push(route.request().url());
    return json(route, { session: session.session, user: session.user });
  });
  const requests: string[] = [];
  page.on('request', (request) => {
    if (verifies.length > 0) requests.push(`${request.method()} ${new URL(request.url()).pathname}`);
  });
  const popups: string[] = [];
  page.context().on('page', (popup) => popups.push(popup.url()));
  await page.goto(options.native ? `/auth/login?${signedQuery()}` : '/auth/login');
  await expect.poll(() => verifies.length).toBe(1);
  expect(new URL(page.url()).pathname).toBe('/auth/login');
  return { gets, verifies, requests, popups };
}

test.describe('a click on the sign-in page after the autofill sign-in completed', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('the passkey button starts no second ceremony: one verify request, one ceremony, one authorize request', async ({ page }) => {
    const { gets, verifies, requests } = await signedInByAutofill(page, { native: true, providers: [] });
    const authorizes = () => requests.filter((request) => request === 'GET /api/auth/oauth2/authorize');
    expect(authorizes()).toHaveLength(0);

    // The sign-in form is on screen with its passkey button enabled: this is what a person can click in the gap.
    const passkey = page.getByRole('button', { name: 'Use a passkey' });
    await expect(passkey).toBeEnabled();
    await passkey.click();
    await page.waitForTimeout(600);
    expect(authorizes()).toHaveLength(0);
    expect(gets).toEqual([{ conditional: true }]);
    expect(verifies).toHaveLength(1);

    await expect.poll(() => authorizes().length).toBe(1);
    await page.waitForLoadState('networkidle');
    expect(authorizes()).toHaveLength(1);
    expect(verifies).toHaveLength(1);
    expect(gets).toEqual([{ conditional: true }]);
  });

  test('the email form sends no code', async ({ page }) => {
    const { requests } = await signedInByAutofill(page, { native: true, providers: [] });

    await page.getByLabel('Email address').fill('sam@example.test');
    await page.getByRole('button', { name: 'Continue', exact: true }).click();
    await page.waitForTimeout(600);

    expect(requests.filter((request) => request.includes('/api/auth/email-otp/'))).toEqual([]);
    expect(new URL(page.url()).pathname).toBe('/auth/login');
  });

  test('the native social button starts no provider flow', async ({ page }) => {
    const { requests } = await signedInByAutofill(page, { native: true, providers: ['google'] });

    await page.getByRole('button', { name: 'Continue with Google' }).click();
    await page.waitForTimeout(600);

    expect(requests.filter((request) => request.includes('/api/auth/sign-in/social'))).toEqual([]);
    expect(new URL(page.url()).pathname).toBe('/auth/login');
  });

  test('the social button of the plain sign-in page opens no provider window', async ({ page }) => {
    const { requests, popups } = await signedInByAutofill(page, { native: false, providers: ['google'] });

    await page.getByRole('button', { name: 'Continue with Google' }).click();
    await page.waitForTimeout(600);

    expect(popups).toEqual([]);
    expect(requests.filter((request) => request.includes('/api/auth/sign-in/social'))).toEqual([]);
    expect(new URL(page.url()).pathname).toBe('/auth/login');
  });
});
