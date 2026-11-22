// The native sign-in sheet offers passkeys without extra taps: the email field lists the device's passkeys
// (conditional UI), and a passkey step that finds no passkey offers an email code and then the passkey offer.
// Every API call is answered by page.route; no API server runs. The two WebAuthn calls the page makes are
// observed through a wrapper around navigator.credentials.get, and a Chromium virtual authenticator holding a
// discoverable credential answers the ceremonies that are meant to succeed.

import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { test, expect, type Page, type Route } from '@playwright/test';
import { PASSKEY_FALLBACK_COPY } from '../../src/lib/passkey-fallback-copy';

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

const DONE = 'https://app.test/done?code=abc';
const SEND = '/api/auth/email-otp/send-verification-otp';
const VERIFY = '**/api/auth/passkey/verify-authentication';
const credentialId = randomBytes(16);

const signedQuery = (extra: Record<string, string> = {}) =>
  new URLSearchParams({
    response_type: 'code',
    client_id: 'exo-native',
    redirect_uri: 'xyz.tinycloud.exo://callback',
    scope: 'openid',
    state: 'st-1',
    tinycloud_request: 'req-1',
    ...extra,
    exp: '9999999999',
    ba_iat: '1',
    sig: 'signed',
  }).toString();

const session = {
  session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() },
  user: { id: 'u', email: 'sam@example.test', name: 'Sam' },
};

async function mockApi(page: Page) {
  const calls: string[] = [];
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    calls.push(path);
    if (path === '/api/auth/get-session') return json(route, null);
    if (path === '/api/auth/providers') return json(route, { providers: [] });
    if (path === '/api/oauth/tinycloud/clients/exo-native/branding') {
      return json(route, { clientId: 'exo-native', name: 'Exo', icon: null, organization: 'TinyCloud Labs' });
    }
    if (path === SEND) return json(route, { success: true });
    if (path === '/api/auth/sign-in/email-otp') return json(route, { redirect: true, url: DONE });
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
  await page.route('https://app.test/**', (route) => route.fulfill({ status: 200, contentType: 'text/html', body: '<p>app</p>' }));
  const verifyHeaders: Array<Record<string, string>> = [];
  await page.route(VERIFY, (route) => {
    verifyHeaders.push(route.request().headers());
    return json(route, { session: session.session, user: session.user });
  });
  return { calls, verifyHeaders, count: (path: string) => calls.filter((call) => call === path).length };
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

interface Get { conditional: boolean; aborted: boolean }
interface Behaviour {
  // 'authenticator': the virtual authenticator answers; 'wait': the request stays open until it is aborted.
  conditional: 'authenticator' | 'wait';
  // 'authenticator': the virtual authenticator answers; 'notAllowed': the prompt ends with no passkey used.
  modal: 'authenticator' | 'notAllowed';
}

/**
 * Records every navigator.credentials.get call (and whether its signal aborted it) and makes conditional
 * mediation available. Headless Chromium shows no autofill list, so a conditional request that should
 * succeed is answered by the virtual authenticator as if the person had chosen the passkey from the list.
 */
async function watchCredentials(page: Page, behaviour: Behaviour) {
  await page.addInitScript((mode: Behaviour) => {
    const probe = window as unknown as { __gets: Get[] };
    probe.__gets = [];
    (PublicKeyCredential as unknown as { isConditionalMediationAvailable: () => Promise<boolean> }).isConditionalMediationAvailable = async () => true;
    const original = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = (options?: CredentialRequestOptions) => {
      const entry = { conditional: options?.mediation === 'conditional', aborted: false };
      probe.__gets.push(entry);
      options?.signal?.addEventListener('abort', () => { entry.aborted = true; });
      if (entry.conditional ? mode.conditional === 'wait' : mode.modal === 'notAllowed') {
        return new Promise((_resolve, reject) => {
          if (!entry.conditional) {
            reject(new DOMException('No passkey was used.', 'NotAllowedError'));
            return;
          }
          options?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
        });
      }
      return original({ ...options, mediation: undefined });
    };
  }, behaviour);
}

const gets = (page: Page) => page.evaluate(() => (window as unknown as { __gets: Get[] }).__gets);

test.describe('native login passkey autofill', () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test('the email field offers passkeys and an autofill sign-in completes like the passkey button', async ({ page }) => {
    await virtualAuthenticator(page);
    await watchCredentials(page, { conditional: 'authenticator', modal: 'authenticator' });
    const api = await mockApi(page);
    const authorize = page.waitForRequest('**/api/auth/oauth2/authorize**');
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email' })}`);

    await expect(page.locator('#email')).toHaveAttribute('autocomplete', 'username webauthn');
    expect(new URL((await authorize).url()).searchParams.get('tinycloud_request')).toBe('req-1');
    expect(api.verifyHeaders).toHaveLength(1);
    expect(api.verifyHeaders[0]!['x-openkey-passkey-flow']).toBe('req-1');
    expect(api.count(SEND)).toBe(0);
  });

  test('the passkey button still signs in while autofill waits, and the autofill request is aborted', async ({ page }) => {
    await virtualAuthenticator(page);
    await watchCredentials(page, { conditional: 'wait', modal: 'authenticator' });
    const api = await mockApi(page);
    const authorize = page.waitForRequest('**/api/auth/oauth2/authorize**');
    const release = Promise.withResolvers<void>();
    const headers: Array<Record<string, string>> = [];
    await page.route(VERIFY, async (route) => {
      headers.push(route.request().headers());
      await release.promise;
      await json(route, { session: session.session, user: session.user });
    });
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email' })}`);
    await expect.poll(async () => (await gets(page)).length).toBe(1);
    expect((await gets(page))[0]).toEqual({ conditional: true, aborted: false });

    await page.getByRole('button', { name: 'Use a passkey' }).click();

    await expect.poll(() => headers.length).toBe(1);
    const calls = await gets(page);
    expect(calls).toHaveLength(2);
    expect(calls[0]).toEqual({ conditional: true, aborted: true });
    expect(calls[1]!.conditional).toBe(false);
    expect(headers[0]!['x-openkey-passkey-flow']).toBe('req-1');
    release.resolve();
    expect(new URL((await authorize).url()).searchParams.get('tinycloud_request')).toBe('req-1');
    expect(api.verifyHeaders).toHaveLength(0);
  });

  test('autofill ends without an error when the step changes', async ({ page }) => {
    await watchCredentials(page, { conditional: 'wait', modal: 'authenticator' });
    const api = await mockApi(page);
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email' })}`);
    await expect.poll(async () => (await gets(page)).length).toBe(1);

    await page.locator('#email').fill('sam@example.test');
    await page.getByRole('button', { name: 'Continue', exact: true }).click();

    await expect(page.locator('#otp')).toBeVisible();
    await expect.poll(async () => (await gets(page))[0]!.aborted).toBe(true);
    await expect(page.getByRole('alert')).toHaveCount(0);
    expect(await gets(page)).toHaveLength(1);
    expect(api.verifyHeaders).toHaveLength(0);
  });

  test('a client without passkeys runs no autofill and keeps the plain email field', async ({ page }) => {
    await watchCredentials(page, { conditional: 'wait', modal: 'authenticator' });
    await mockApi(page);
    await page.goto(`/auth/login?${signedQuery({ login_method: 'email', passkeys: 'false' })}`);
    await expect(page.locator('#email')).toHaveAttribute('autocomplete', 'email');
    await page.waitForLoadState('networkidle');
    expect(await gets(page)).toHaveLength(0);
  });

  test('the passkey step makes no autofill request, and a prompt with no passkey offers an email code', async ({ page }) => {
    await watchCredentials(page, { conditional: 'wait', modal: 'notAllowed' });
    const api = await mockApi(page);
    await page.goto(`/auth/login?${signedQuery({ login_method: 'passkey' })}`);
    await expect(page.getByRole('button', { name: 'Continue with passkey' })).toBeVisible();
    await page.waitForLoadState('networkidle');
    expect(await gets(page)).toHaveLength(0);

    await page.getByRole('button', { name: 'Continue with passkey' }).click();

    await expect(page.getByTestId('passkey-fallback')).toHaveText(PASSKEY_FALLBACK_COPY.message);
    await expect(page.getByRole('alert')).toHaveCount(0);
    expect(await gets(page)).toEqual([{ conditional: false, aborted: false }]);
    expect(api.verifyHeaders).toHaveLength(0);

    await page.getByRole('button', { name: PASSKEY_FALLBACK_COPY.emailButton }).click();
    await expect(page.locator('#email')).toBeVisible();
    await expect(page.getByTestId('passkey-fallback')).toHaveCount(0);
  });

  test('after the fallback, the email-code sign-in always shows the passkey offer, even for an account with passkeys', async ({ page }) => {
    await watchCredentials(page, { conditional: 'wait', modal: 'notAllowed' });
    const api = await mockApi(page);
    await page.route('**/api/auth/passkey/list-user-passkeys', (route) => json(route, [{ id: 'existing-passkey' }]));
    await page.goto(`/auth/login?${signedQuery({ login_method: 'passkey' })}`);
    await page.waitForLoadState('networkidle');
    await page.getByRole('button', { name: 'Continue with passkey' }).click();
    await page.getByRole('button', { name: PASSKEY_FALLBACK_COPY.emailButton }).click();
    await page.locator('#email').fill('sam@example.test');
    await page.getByRole('button', { name: 'Continue', exact: true }).click();
    await page.locator('#otp').fill('123456');

    await expect(page.getByText('Create a passkey for faster, phishing-resistant sign-in. You can skip this and keep using email codes.')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Create a passkey' })).toBeVisible();
    expect(page.url()).not.toContain('app.test');
    expect(api.count('/api/auth/passkey/list-user-passkeys')).toBe(0);

    await page.getByRole('button', { name: 'Skip for now' }).click();
    await page.waitForURL(DONE);
  });

  test('an email-code sign-in that did not follow the fallback shows no passkey offer', async ({ page }) => {
    await watchCredentials(page, { conditional: 'wait', modal: 'notAllowed' });
    const api = await mockApi(page);
    await page.goto(`/auth/login?${signedQuery({ login_method: 'passkey' })}`);
    await page.waitForLoadState('networkidle');
    await page.getByRole('button', { name: 'Use email instead' }).click();
    await page.locator('#email').fill('sam@example.test');
    await page.getByRole('button', { name: 'Continue', exact: true }).click();
    await page.locator('#otp').fill('123456');

    await page.waitForURL(DONE);
    expect(api.calls.filter((call) => call.includes('passkey') && !call.endsWith('generate-authenticate-options'))).toEqual([]);
  });
});
