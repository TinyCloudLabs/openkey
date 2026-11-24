// A passkey click while the autofill sign-in is being verified by the server. The email field's conditional request
// is answered by a Chromium virtual authenticator, as if the person had chosen the passkey from the autofill list, and
// the server's verify answer is held. A click on "Use a passkey" at that moment adopts the autofill sign-in: one
// verify request, one WebAuthn ceremony, one trip to the authorize endpoint. When the held verification fails, the
// click runs a ceremony of its own. Every API call is answered by page.route; no API server runs.

import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { test, expect, type Page, type Route } from '@playwright/test';
import { TERMS_ACCEPTED } from './terms-fixtures';

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

const DONE = 'https://app.test/done?code=abc';
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

async function mockApi(page: Page) {
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, null);
    if (path === '/api/auth/providers') return json(route, { providers: [] });
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
  await page.route('**/api/account/terms', (route) => route.fulfill({ json: TERMS_ACCEPTED }));
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

test.describe('a passkey click while the autofill sign-in is being verified', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('adopts the autofill sign-in: one verify request, one ceremony, one authorize request', async ({ page }) => {
    await virtualAuthenticator(page);
    const gets = await watchCredentials(page);
    await mockApi(page);
    const verifies: string[] = [];
    const release = Promise.withResolvers<void>();
    await page.route(VERIFY, async (route) => {
      verifies.push(route.request().url());
      await release.promise;
      await json(route, { session: session.session, user: session.user });
    });
    const authorizes: string[] = [];
    page.on('request', (request) => {
      if (new URL(request.url()).pathname === '/api/auth/oauth2/authorize') authorizes.push(request.url());
    });
    await page.goto(`/auth/login?${signedQuery()}`);
    await expect.poll(() => verifies.length).toBe(1);

    await page.getByRole('button', { name: 'Use a passkey' }).click();
    // The click waits for the verification; it starts no ceremony of its own.
    await page.waitForTimeout(300);
    expect(gets).toEqual([{ conditional: true }]);
    release.resolve();

    await expect.poll(() => authorizes.length).toBe(1);
    await page.waitForLoadState('networkidle');
    expect(authorizes).toHaveLength(1);
    expect(verifies).toHaveLength(1);
    expect(gets).toEqual([{ conditional: true }]);
  });

  test('a verification that fails is not adopted: the click runs its own ceremony and signs in once', async ({ page }) => {
    await virtualAuthenticator(page);
    const gets = await watchCredentials(page);
    await mockApi(page);
    const verifies: string[] = [];
    const release = Promise.withResolvers<void>();
    await page.route(VERIFY, async (route) => {
      verifies.push(route.request().url());
      if (verifies.length === 1) {
        await release.promise;
        await json(route, { code: 'AUTHENTICATION_FAILED', message: 'Authentication failed' }, 400);
        return;
      }
      await json(route, { session: session.session, user: session.user });
    });
    const authorizes: string[] = [];
    page.on('request', (request) => {
      if (new URL(request.url()).pathname === '/api/auth/oauth2/authorize') authorizes.push(request.url());
    });
    await page.goto(`/auth/login?${signedQuery()}`);
    await expect.poll(() => verifies.length).toBe(1);

    await page.getByRole('button', { name: 'Use a passkey' }).click();
    release.resolve();

    await expect.poll(() => authorizes.length).toBe(1);
    await page.waitForLoadState('networkidle');
    expect(authorizes).toHaveLength(1);
    expect(verifies).toHaveLength(2);
    expect(gets.map((get) => get.conditional)).toEqual([true, false]);
  });
});
