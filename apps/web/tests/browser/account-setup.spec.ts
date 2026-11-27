import { test, expect, type Page, type Route } from '@playwright/test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { HOST, ORIGIN } from './e2e-port';
import { makeRecapResource, siweWithResources } from '../../../../packages/capability-review/test/fixtures/index';
import { TERMS_ACCEPTED } from './terms-fixtures';

// OpenKey's own account setup page: the owner sets the TinyCloud account up with one approval, from the app's popup,
// from the embedded hand-off or from the sign widget's "Finish setup" card. The app gets the outcome only.
const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const nodeDid = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const key = { id: 'selected-key', address, publicKey: '0x02', keyIndex: 0, label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z', isPrimary: true };
const record = JSON.stringify({
  version: 2, subject: `did:pkh:eip155:1:${address}`, sequence: 0, updated_at: '2026-11-25T00:00:00.000Z',
  nodes: [{ did: nodeDid, url: 'https://node.tinycloud.xyz' }], encryptionNode: nodeDid,
  spaces: ['default', 'applications'].map((name) => ({ space: `tinycloud:pkh:eip155:1:${address}:${name}`, nodes: [{ did: nodeDid, mode: 'read-write' }] })),
});
const credentialId = randomBytes(16);
const shots = process.env.OPENKEY_ACCOUNT_SETUP_SHOTS;
const VIEWPORTS = { mobile: { width: 390, height: 844 }, desktop: { width: 1280, height: 800 } } as const;

type HostWindow = Window & { received: Record<string, unknown>[]; setupWindow: Window };
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

async function shot(page: Page, name: string) {
  if (!shots) return;
  mkdirSync(shots, { recursive: true });
  await page.screenshot({ path: `${shots}/${name}.png`, fullPage: true });
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

type SetupApi = {
  prepare?: (n: number) => { status?: number; body: unknown };
  stepUp?: 'passkey' | 'email';
  approve?: (n: number) => { status?: number; body: unknown };
  finish?: (n: number) => { status?: number; body: unknown };
  signPrepare?: (n: number) => { status?: number; body: unknown };
};

async function mockApi(page: Page, api: SetupApi) {
  const calls = { prepare: [] as Record<string, unknown>[], approve: [] as Record<string, unknown>[], finish: 0, emailCodes: 0, signPrepare: 0 };
  await page.context().addCookies([{ name: 'better-auth.session_token', value: 'cookie-session', url: ORIGIN }]);
  await page.context().route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/api/auth/get-session') return json(route, { session: { id: 'test-session' }, user: { id: 'u', email: 'n@mail.com' } });
    if (path === '/api/account/terms') return json(route, TERMS_ACCEPTED);
    if (path === '/api/keys') return json(route, { keys: [key] });
    if (path === '/api/keys/selected-key') return json(route, { key });
    if (path === '/api/account-setup/prepare') {
      calls.prepare.push(request.postDataJSON());
      const answer = api.prepare?.(calls.prepare.length) ?? { body: {
        state: 'ready', id: 'setup-1', record, nodeUrl: 'https://node.tinycloud.xyz',
        expiresAt: new Date(Date.now() + 300_000).toISOString(), stepUp: api.stepUp ?? 'passkey',
      } };
      return json(route, answer.body, answer.status);
    }
    if (path === '/api/account-setup/setup-1/passkey') {
      if (api.stepUp === 'email') return json(route, { stepUp: 'email', email: 'n•••@mail.com' });
      return json(route, { stepUp: 'passkey', challengeToken: 'token-1', options: {
        challenge: randomBytes(32).toString('base64url'), rpId: 'localhost', userVerification: 'required', timeout: 60000,
        allowCredentials: [{ id: credentialId.toString('base64url'), type: 'public-key', transports: ['internal'] }],
      } });
    }
    if (path === '/api/account-setup/setup-1/email-code') {
      calls.emailCodes += 1;
      return json(route, { sent: true, email: 'n•••@mail.com' });
    }
    if (path === '/api/account-setup/setup-1/approve') {
      calls.approve.push(request.postDataJSON());
      const answer = api.approve?.(calls.approve.length) ?? { body: { state: 'published' } };
      return json(route, answer.body, answer.status);
    }
    if (path === '/api/account-setup/setup-1/finish') {
      calls.finish += 1;
      const answer = api.finish?.(calls.finish) ?? { body: { state: 'published' } };
      return json(route, answer.body, answer.status);
    }
    if (path === '/api/delegate/authorize-sign-prepare') {
      calls.signPrepare += 1;
      const answer = api.signPrepare?.(calls.signPrepare) ?? { body: {} };
      return json(route, answer.body, answer.status);
    }
    return json(route, {});
  });
  return calls;
}

/** Opens the account setup page as the SDK does and sends it one request. */
async function openSetup(page: Page, viewport: { width: number; height: number }, keyId: string | null = 'selected-key') {
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const host = window as unknown as HostWindow;
    host.received = [];
    window.addEventListener('message', (event) => {
      if (event.origin !== location.origin || event.source !== host.setupWindow) return;
      if (event.data?.type === 'openkey:ready') return;
      host.received.push(event.data);
    });
  });
  await page.evaluate((keyId) => {
    const host = window as unknown as HostWindow;
    window.addEventListener('message', (event) => {
      if (event.source === host.setupWindow && event.data?.type === 'openkey:ready') {
        host.setupWindow.postMessage({ type: 'openkey:account-setup:request', requestId: 'r1', protocolVersion: 1, keyId }, location.origin);
      }
    });
  }, keyId);
  const opened = page.waitForEvent('popup');
  await page.evaluate(() => {
    (window as unknown as HostWindow).setupWindow = window.open(`/widget/account-setup?origin=${encodeURIComponent(location.origin)}`)!;
  });
  const popup = await opened;
  await popup.setViewportSize(viewport);
  await virtualAuthenticator(popup);
  const received = () => page.evaluate(() => (window as unknown as HostWindow).received);
  return { popup, received };
}

for (const [name, viewport] of Object.entries(VIEWPORTS)) {
  test.describe(`account setup page (${name})`, () => {
    test('the passkey path sets the account up and the app gets the outcome only', async ({ page }) => {
      const calls = await mockApi(page, {
        approve: () => ({ body: { state: 'working' } }),
        finish: () => ({ body: { state: 'published' } }),
      });
      const { popup, received } = await openSetup(page, viewport);
      await expect(popup.getByRole('heading', { name: 'Set up your TinyCloud account' })).toBeVisible();
      await expect(popup.getByTestId('account-setup-requester')).toContainText(`Requested by ${HOST}`);
      await expect(popup.getByTestId('account-setup-account')).toHaveText(`Account: ${address}`);
      await expect(popup.getByText('You set up your account once, for all your apps.')).toBeVisible();
      const extraSetup = popup.getByText('Some apps need extra setup in');
      await expect(extraSetup).toHaveText('Some apps need extra setup in TinyCloud One.');
      await expect(extraSetup.getByRole('link', { name: 'TinyCloud One', exact: true })).toHaveAttribute('href', 'https://tinycloud.one/?finish-setup=registry');
      await expect(popup.locator('summary')).toHaveText(['More options']);
      await shot(popup, `default-${name}`);

      await popup.getByTestId('account-setup-set-up').click();
      await expect(popup.getByRole('heading', { name: 'Confirm setup' })).toBeVisible();
      expect(calls.prepare[0]).toEqual({ keyId: 'selected-key', placement: 'tinycloud', requestOrigin: ORIGIN });
      await popup.getByText('Advanced details').click();
      await expect(popup.getByTestId('account-setup-details')).toContainText('node.tinycloud.xyz');
      await shot(popup, `confirm-passkey-${name}`);

      await popup.getByTestId('account-setup-confirm').click();
      await expect(popup.getByRole('heading', { name: 'Your TinyCloud account is set up', exact: true })).toBeVisible();
      await expect(popup.getByText('Return to the app to continue.')).toBeVisible();
      expect(calls.approve[0]).toMatchObject({ passkeyAssertion: { challengeToken: 'token-1', response: { id: credentialId.toString('base64url') } } });
      expect(calls.finish).toBe(1);
      await shot(popup, `done-${name}`);
      await expect.poll(received).toEqual([
        { type: 'openkey:account-setup:response', requestId: 'r1', protocolVersion: 1, success: true, outcome: 'published' },
      ]);
    });

    test('the working and failed states, with Retry', async ({ page }) => {
      let release: () => void = () => {};
      const held = new Promise<void>((resolve) => { release = resolve; });
      await mockApi(page, {
        approve: () => ({ body: { state: 'working' } }),
        finish: (n) => (n === 1
          ? { body: { state: 'failed', code: 'account_setup_registry_unavailable', error: "The registry didn't answer. Retry.", retry: true } }
          : { body: { state: 'published' } }),
      });
      await page.context().route('**/api/account-setup/setup-1/finish', async (route) => {
        await held;
        await route.fallback();
      });
      const { popup } = await openSetup(page, viewport);
      await popup.getByTestId('account-setup-set-up').click();
      await popup.getByTestId('account-setup-confirm').click();
      await expect(popup.getByRole('heading', { name: 'Setting up your account' })).toBeVisible();
      await expect(popup.getByText('Create your spaces')).toBeVisible();
      await shot(popup, `working-${name}`);
      release();
      await expect(popup.getByRole('heading', { name: "Setup didn't finish", exact: true })).toBeVisible({ timeout: 10_000 });
      await expect(popup.getByText("The registry didn't answer. Retry.")).toBeVisible();
      await shot(popup, `failed-${name}`);
      await popup.getByTestId('account-setup-retry').click();
      await expect(popup.getByRole('heading', { name: 'Your TinyCloud account is set up', exact: true })).toBeVisible();
    });

    test('an account that is set up answers present only after Continue', async ({ page }) => {
      await mockApi(page, { prepare: () => ({ body: { state: 'present' } }) });
      const { popup, received } = await openSetup(page, viewport);
      await popup.getByTestId('account-setup-set-up').click();
      await expect(popup.getByRole('heading', { name: 'Your TinyCloud account is set up', exact: true })).toBeVisible();
      await shot(popup, `present-${name}`);
      expect(await received()).toEqual([]);
      const closed = popup.waitForEvent('close');
      await popup.getByTestId('account-setup-continue').click();
      await closed;
      expect(await received()).toEqual([
        { type: 'openkey:account-setup:response', requestId: 'r1', protocolVersion: 1, success: true, outcome: 'present' },
      ]);
    });

    test('the email code path sends a code only on a tap', async ({ page }) => {
      const calls = await mockApi(page, { stepUp: 'email' });
      const { popup } = await openSetup(page, viewport);
      await popup.getByTestId('account-setup-set-up').click();
      await expect(popup.getByText("We'll email a code to n•••@mail.com to confirm setup.")).toBeVisible();
      expect(calls.emailCodes).toBe(0);
      await popup.getByTestId('account-setup-send-code').click();
      await expect(popup.getByText('We sent a code to n•••@mail.com.')).toBeVisible();
      expect(calls.emailCodes).toBe(1);
      await popup.getByLabel('Code').fill('123456');
      await shot(popup, `confirm-email-${name}`);
      await popup.getByRole('button', { name: 'Confirm', exact: true }).click();
      await expect(popup.getByRole('heading', { name: 'Your TinyCloud account is set up', exact: true })).toBeVisible();
      expect(calls.approve[0]).toEqual({ emailCode: '123456' });
    });

    test('a wallet key is sent to TinyCloud One', async ({ page }) => {
      await mockApi(page, {});
      await page.context().route('**/api/keys', (route) => json(route, { keys: [{ ...key, keyType: 'EXTERNAL' }] }));
      const { popup, received } = await openSetup(page, viewport);
      await expect(popup.getByText("OpenKey can't set this up for a wallet key. Finish setup in TinyCloud One.")).toBeVisible();
      await expect(popup.getByRole('link', { name: 'Open TinyCloud One' })).toHaveAttribute('href', 'https://tinycloud.one/?finish-setup=registry');
      await shot(popup, `unavailable-wallet-${name}`);
      const closed = popup.waitForEvent('close');
      await popup.getByRole('button', { name: 'Close' }).click();
      await closed;
      expect(await received()).toMatchObject([{ success: false, error: { code: 'ACCOUNT_SETUP_UNAVAILABLE', setupUrl: 'https://tinycloud.one/?finish-setup=registry' } }]);
    });

    test('an account without a passkey or a verified email is sent to settings', async ({ page }) => {
      await mockApi(page, { prepare: () => ({ status: 403, body: {
        error: 'Add a passkey in OpenKey settings to set up your TinyCloud account.', code: 'ACCOUNT_SETUP_UNAVAILABLE', reason: 'no_step_up',
      } }) });
      const { popup } = await openSetup(page, viewport);
      await popup.getByTestId('account-setup-set-up').click();
      await expect(popup.getByText('Add a passkey in OpenKey settings to set up your TinyCloud account.')).toBeVisible();
      await expect(popup.getByRole('link', { name: 'Open OpenKey settings' })).toBeVisible();
      await shot(popup, `unavailable-passkey-${name}`);
    });
  });
}

test('opened on its own, the page names the account and creates nothing before the owner taps Set up', async ({ page }) => {
  const calls = await mockApi(page, {});
  await page.goto('/widget/account-setup');
  await expect(page.getByRole('heading', { name: 'Set up your TinyCloud account' })).toBeVisible();
  await expect(page.getByTestId('account-setup-account')).toHaveText(`Account: ${address}`);
  await expect(page.getByTestId('account-setup-requester')).toHaveCount(0);
  await expect(page.getByTestId('account-setup-card')).toHaveAttribute('data-phase', 'ready');
  expect(calls.prepare).toEqual([]);
  await shot(page, 'standalone-desktop');
  await page.getByTestId('account-setup-set-up').click();
  await expect(page.getByRole('heading', { name: 'Confirm setup' })).toBeVisible();
  expect(calls.prepare).toEqual([{ keyId: 'selected-key', placement: 'tinycloud' }]);
  expect(calls.approve).toEqual([]);
});

test('the embedded hand-off opens the setup window and relays its answer', async ({ page }) => {
  await page.setViewportSize(VIEWPORTS.mobile);
  await mockApi(page, { prepare: () => ({ body: { state: 'present' } }) });
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const host = window as unknown as HostWindow;
    host.received = [];
    const iframe = document.createElement('iframe');
    iframe.id = 'handoff';
    iframe.src = `/widget/embed/account-setup?origin=${encodeURIComponent(location.origin)}`;
    iframe.style.width = '360px';
    iframe.style.height = '260px';
    document.body.append(iframe);
    host.setupWindow = iframe.contentWindow!;
    window.addEventListener('message', (event) => {
      if (event.origin !== location.origin || event.source !== host.setupWindow) return;
      if (event.data?.type === 'openkey:loading') return; // TC-4438: the page-load signal, not an answer
      if (event.data?.type === 'openkey:ready') {
        host.setupWindow.postMessage({ type: 'openkey:account-setup:request', requestId: 'r-embed', protocolVersion: 1, keyId: 'selected-key' }, location.origin);
        return;
      }
      host.received.push(event.data);
    });
  });
  const frame = page.frameLocator('#handoff');
  await expect(frame.getByTestId('account-setup-finish')).toBeEnabled();
  await shot(page, 'handoff-mobile');
  const opened = page.waitForEvent('popup');
  await frame.getByTestId('account-setup-finish').click();
  const popup = await opened;
  expect(popup.url()).toContain('/widget/account-setup?via=embed');
  await expect(popup.getByTestId('account-setup-requester')).toContainText(`Requested by ${HOST}`);
  await expect(popup.getByTestId('account-setup-requester')).toContainText('the site that asked OpenKey to open this window');
  await popup.getByTestId('account-setup-set-up').click();
  const closed = popup.waitForEvent('close');
  await popup.getByTestId('account-setup-continue').click();
  await closed;
  await expect.poll(() => page.evaluate(() => (window as unknown as HostWindow).received)).toEqual([
    { type: 'openkey:account-setup:response', requestId: 'r-embed', protocolVersion: 1, success: true, outcome: 'present' },
  ]);
});

test("the sign widget's Finish setup card sets the account up, prepares the request a second time and tells the app the account is set up", async ({ page }) => {
  const siwe = siweWithResources([makeRecapResource({
    [`tinycloud:pkh:eip155:1:${address}:default/space`]: { 'tinycloud.space/host': [{}] },
  })], { domain: HOST, uri: `http://${HOST}` });
  const calls = await mockApi(page, {
    prepare: () => ({ body: { state: 'present' } }),
    signPrepare: (n) => ({ status: 403, body: {
      error: 'Only TinyCloud can create your TinyCloud spaces.', code: 'host_signing_first_party_only', ...(n === 1 ? { accountSetup: 'required' } : {}),
    } }),
  });
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const host = window as unknown as HostWindow;
    host.received = [];
    window.addEventListener('message', (event) => {
      if (event.origin === location.origin && event.source === host.setupWindow) host.received.push(event.data);
    });
  });
  const opened = page.waitForEvent('popup');
  await page.evaluate(() => {
    (window as unknown as HostWindow).setupWindow = window.open(`/widget/sign?origin=${encodeURIComponent(location.origin)}`)!;
  });
  const signWindow = await opened;
  await signWindow.setViewportSize(VIEWPORTS.mobile);
  await expect.poll(() => page.evaluate(() => (window as unknown as HostWindow).received.some((m) => m.type === 'openkey:ready'))).toBe(true);
  await page.evaluate((message) => {
    (window as unknown as HostWindow).setupWindow.postMessage({
      type: 'openkey:sign:request', requestId: 'r1', protocolVersion: 1,
      authorizationProtocolVersion: 1, keyId: 'selected-key', jwk: { kty: 'EC' }, message,
    }, location.origin);
  }, siwe);
  await expect(signWindow.getByTestId('account-setup-card')).toBeVisible();
  await expect(signWindow.getByText('Finish setting up your TinyCloud account')).toBeVisible();
  await shot(signWindow, 'sign-card-mobile');
  await signWindow.setViewportSize(VIEWPORTS.desktop);
  await shot(signWindow, 'sign-card-desktop');

  const setupOpened = signWindow.waitForEvent('popup');
  await signWindow.getByTestId('account-setup-finish').click();
  const setup = await setupOpened;
  await expect(setup.getByTestId('account-setup-requester')).toContainText(`Requested by ${HOST}`);
  await setup.getByTestId('account-setup-set-up').click();
  expect(calls.prepare[0]).toEqual({ keyId: 'selected-key', placement: 'tinycloud', requestOrigin: ORIGIN });
  const closed = setup.waitForEvent('close');
  await setup.getByTestId('account-setup-continue').click();
  await closed;

  await expect.poll(() => calls.signPrepare).toBe(2);
  await expect(signWindow.getByText('Your TinyCloud account is set up. Return to the app to continue.').first()).toBeVisible();
  await expect.poll(() => page.evaluate(() => (window as unknown as HostWindow).received.filter((m) => m.type === 'openkey:sign:response')))
    .toMatchObject([{ success: false, error: { code: 'UNKNOWN', message: 'ACCOUNT_SETUP_COMPLETED' } }]);
});
