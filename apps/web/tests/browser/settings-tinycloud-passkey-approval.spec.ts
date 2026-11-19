import { test, expect, type Page, type Route } from '@playwright/test';
import { ORIGIN } from './e2e-port';
import { generateKeyPairSync, randomBytes } from 'node:crypto';

// TC-3442: in Settings, taking shared control of TinyCloud signing and allowing an app may need the passkey. The
// confirm step holds the offer for its change and the confirm click sends the answer with it; blocking never asks.
// Settings has no Approve button, so a passkey refusal shows its own line, and the next try answers a fresh offer.
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const session = { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'u', email: 'owner@example.test', name: 'Owner' } };
const credentialId = randomBytes(16);
const refusal = { error: "Your passkey didn't confirm this. Tap Approve to try again.", code: 'passkey_approval_invalid' };

type Assertion = { challengeToken: string; response: { id: string } };
type Patch = { mode?: string; enabled?: boolean; expectedEpoch: number; passkeyAssertion?: Assertion };

function offer(token: string) {
  return { required: true, challengeToken: token, options: {
    challenge: randomBytes(32).toString('base64url'), rpId: 'localhost', userVerification: 'required', timeout: 60000,
    allowCredentials: [{ id: credentialId.toString('base64url'), type: 'public-key', transports: ['internal'] }],
  } };
}

async function setup(page: Page, initial: { mode: string; appEnabled: boolean }, refuseFirstPatch = false) {
  const state = { mode: initial.mode, policyEpoch: 3, appEnabled: initial.appEnabled };
  const calls = { offers: [] as unknown[], patches: [] as Patch[] };
  const preference = () => ({ mode: state.mode, policyEpoch: state.policyEpoch, tinyCloudManageKeyEnabled: state.mode !== 'USER_CONTROLLED_EXCLUSIVE' });
  await page.context().addCookies([{ name: 'better-auth.session_token', value: 'cookie-session', url: ORIGIN }]);
  await page.route('**/api/**', (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/api/auth/get-session') return json(route, session);
    if (path === '/api/auth/providers') return json(route, { providers: [] });
    if (path === '/api/keys') return json(route, { keys: [] });
    if (path.includes('passkey/list-user-passkeys')) return json(route, [{ id: 'pk-1', name: 'Laptop', deviceType: 'singleDevice', createdAt: new Date().toISOString() }]);
    if (path === '/api/account/passkey-approval') return json(route, { mode: 'SENSITIVE', effectiveMode: 'SENSITIVE', stepUpPasskeys: 1 });
    // The offers answer the way the API does: blocking never asks.
    if (path === '/api/account/tinycloud-manage-key/passkey') {
      const body = request.postDataJSON() as { mode: string };
      calls.offers.push(body);
      return json(route, body.mode === 'USER_CONTROLLED_EXCLUSIVE' ? { required: false } : offer(`token-${calls.offers.length}`));
    }
    if (path === '/api/account/tinycloud-apps/app-1/passkey') {
      const body = request.postDataJSON() as { enabled: boolean };
      calls.offers.push(body);
      return json(route, body.enabled ? offer(`token-${calls.offers.length}`) : { required: false });
    }
    if (request.method() === 'PATCH' && (path === '/api/account/tinycloud-manage-key' || path === '/api/account/tinycloud-apps/app-1')) {
      const patch = request.postDataJSON() as Patch;
      calls.patches.push(patch);
      if (refuseFirstPatch && calls.patches.length === 1) return json(route, refusal, 403);
      state.policyEpoch += 1;
      if (patch.mode) {
        state.mode = patch.mode;
        return json(route, preference());
      }
      state.appEnabled = patch.enabled === true;
      return json(route, { clientId: 'app-1', enabled: state.appEnabled, status: 'ENABLED', policyEpoch: state.policyEpoch });
    }
    if (path === '/api/account/tinycloud-manage-key') return json(route, preference());
    if (path === '/api/account/tinycloud-apps') {
      return json(route, { ...preference(), activity: [], mcpApps: [], identityApps: [], apps: [{
        clientId: 'app-1', name: 'Notes', uri: null, icon: null, disabled: false, enabled: state.appEnabled,
        nativeDelegation: false, activeNativeGrants: 0,
      }] });
    }
    return json(route, {});
  });
  return calls;
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

/** Types the confirmation once the confirm step holds its offer, then clicks the confirm button. */
async function confirm(page: Page, calls: { offers: unknown[] }, offers: number, button: string) {
  const dialog = page.getByRole('dialog');
  await expect.poll(() => calls.offers.length).toBe(offers);
  await dialog.getByLabel('Type TAKE CONTROL to confirm').fill('TAKE CONTROL');
  await dialog.getByRole('button', { name: button }).click();
  await expect(dialog).toBeHidden();
}

test('taking shared control sends the passkey assertion for its offer; blocking every app never asks', async ({ page }) => {
  await virtualAuthenticator(page);
  const calls = await setup(page, { mode: 'APP_MANAGED', appEnabled: false });
  await page.goto('/dashboard/settings');
  const card = page.locator('#tinycloud-signing');

  await card.getByRole('button', { name: 'Take shared control' }).click();
  await confirm(page, calls, 1, 'Confirm change');
  expect(calls.offers[0]).toEqual({ mode: 'USER_CONTROLLED_SHARED', expectedEpoch: 3 });
  await expect.poll(() => calls.patches.length).toBe(1);
  expect(calls.patches[0]).toMatchObject({
    mode: 'USER_CONTROLLED_SHARED', expectedEpoch: 3,
    passkeyAssertion: { challengeToken: 'token-1', response: { id: credentialId.toString('base64url') } },
  });
  await expect(card.getByText('Shared', { exact: true })).toBeVisible();

  await card.getByRole('button', { name: 'Block all apps' }).click();
  await confirm(page, calls, 2, 'Confirm change');
  await expect.poll(() => calls.patches.length).toBe(2);
  expect(calls.patches[1]).toMatchObject({ mode: 'USER_CONTROLLED_EXCLUSIVE', expectedEpoch: 4 });
  expect(calls.patches[1]).not.toHaveProperty('passkeyAssertion');
});

test("allowing an app sends the passkey assertion for its offer; blocking it never asks", async ({ page }) => {
  await virtualAuthenticator(page);
  const calls = await setup(page, { mode: 'USER_CONTROLLED_SHARED', appEnabled: false });
  await page.goto('/dashboard/settings');
  const apps = page.locator('#connected-tinycloud-apps');

  await apps.getByRole('switch', { name: 'Allow Notes' }).click();
  await confirm(page, calls, 1, 'Allow app');
  expect(calls.offers[0]).toEqual({ enabled: true, expectedEpoch: 3 });
  await expect.poll(() => calls.patches.length).toBe(1);
  expect(calls.patches[0]).toMatchObject({
    enabled: true, expectedEpoch: 3,
    passkeyAssertion: { challengeToken: 'token-1', response: { id: credentialId.toString('base64url') } },
  });

  await apps.getByRole('switch', { name: 'Block Notes' }).click();
  await confirm(page, calls, 2, 'Block app');
  await expect.poll(() => calls.patches.length).toBe(2);
  expect(calls.patches[1]).toMatchObject({ enabled: false, expectedEpoch: 4 });
  expect(calls.patches[1]).not.toHaveProperty('passkeyAssertion');
});

test('a passkey refusal shows the Settings line and the next confirm answers a fresh offer', async ({ page }) => {
  await virtualAuthenticator(page);
  const calls = await setup(page, { mode: 'APP_MANAGED', appEnabled: false }, true);
  await page.goto('/dashboard/settings');
  const card = page.locator('#tinycloud-signing');

  await card.getByRole('button', { name: 'Take shared control' }).click();
  await confirm(page, calls, 1, 'Confirm change');
  await expect(card.getByRole('alert')).toHaveText("Your passkey didn't confirm this. Try again.");
  await expect(card.getByText('App managed', { exact: true })).toBeVisible();

  await card.getByRole('button', { name: 'Take shared control' }).click();
  await confirm(page, calls, 2, 'Confirm change');
  await expect.poll(() => calls.patches.length).toBe(2);
  expect(calls.patches.map((patch) => patch.passkeyAssertion?.challengeToken)).toEqual(['token-1', 'token-2']);
  await expect(card.getByText('Shared', { exact: true })).toBeVisible();
});
