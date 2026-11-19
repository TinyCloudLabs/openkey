import { test, expect, type Page, type Route } from '@playwright/test';
import { ORIGIN } from './e2e-port';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { PASSKEY_APPROVAL_SETTING_SHOWN } from '../../src/lib/approval-passkey';

test.skip(!PASSKEY_APPROVAL_SETTING_SHOWN, 'The Settings card is hidden.');

// TC-3442: Settings chooses which approvals need a passkey. Asking on more approvals saves at once; asking on fewer
// goes through the passkey prompt and sends its assertion with the change. Without a passkey that can confirm
// approvals the choices are disabled.
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const session = { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'u', email: 'owner@example.test', name: 'Owner' } };
const credentialId = randomBytes(16);

type Patch = { mode: string; passkeyAssertion?: { challengeToken: string; response: { id: string } } };

async function setup(page: Page, initial: { mode: string; stepUpPasskeys: number }, refusePatch?: { error: string; code: string }) {
  const state = { ...initial, effectiveMode: initial.stepUpPasskeys > 0 ? initial.mode : 'NEVER' };
  const calls = { options: [] as unknown[], patches: [] as Patch[] };
  await page.context().addCookies([{ name: 'better-auth.session_token', value: 'cookie-session', url: ORIGIN }]);
  await page.route('**/api/**', (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/api/auth/get-session') return json(route, session);
    if (path === '/api/auth/providers') return json(route, { providers: [] });
    if (path === '/api/keys') return json(route, { keys: [] });
    if (path.includes('passkey/list-user-passkeys')) return json(route, [{ id: 'pk-1', name: 'Laptop', deviceType: 'singleDevice', createdAt: new Date().toISOString() }]);
    if (path === '/api/account/passkey-approval/options') {
      calls.options.push(request.postDataJSON());
      return json(route, { challengeToken: 'token-1', options: {
        challenge: randomBytes(32).toString('base64url'), rpId: 'localhost', userVerification: 'required', timeout: 60000,
        allowCredentials: [{ id: credentialId.toString('base64url'), type: 'public-key', transports: ['internal'] }],
      } });
    }
    if (path === '/api/account/passkey-approval') {
      if (request.method() === 'PATCH') {
        const patch = request.postDataJSON() as Patch;
        calls.patches.push(patch);
        if (refusePatch) return json(route, refusePatch, 403);
        Object.assign(state, { mode: patch.mode, effectiveMode: patch.mode });
      }
      return json(route, state);
    }
    if (path.includes('tinycloud')) return json(route, { tinyCloudManageKeyEnabled: true, mode: 'APP_MANAGED', policyEpoch: 0, apps: [], activity: [] });
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

test('asking on more approvals saves at once; asking on fewer sends a passkey assertion for the new choice', async ({ page }) => {
  await virtualAuthenticator(page);
  const calls = await setup(page, { mode: 'SENSITIVE', stepUpPasskeys: 1 });
  await page.goto('/dashboard/settings');
  const card = page.locator('#passkey-approvals');
  await expect(card.getByRole('radio', { name: 'Only for sensitive access (recommended)' })).toBeChecked();

  await card.getByRole('radio', { name: 'Every approval' }).check();
  await expect.poll(() => calls.patches.length).toBe(1);
  expect(calls.patches[0]).toEqual({ mode: 'ALWAYS' });
  expect(calls.options).toEqual([]);

  await card.getByRole('radio', { name: 'Never' }).check();
  await expect(card.getByText('Anyone signed in as you can approve without your passkey.')).toBeVisible();
  expect(calls.options).toEqual([{ mode: 'NEVER' }]);
  expect(calls.patches[1]).toMatchObject({
    mode: 'NEVER', passkeyAssertion: { challengeToken: 'token-1', response: { id: credentialId.toString('base64url') } },
  });
  await card.screenshot({ path: test.info().outputPath('passkey-approvals.png') });
});

test('without a passkey that can confirm approvals the choices are disabled', async ({ page }) => {
  await setup(page, { mode: 'SENSITIVE', stepUpPasskeys: 0 });
  await page.goto('/dashboard/settings');
  const card = page.locator('#passkey-approvals');
  await expect(card.getByText('Add a passkey to use this.')).toBeVisible();
  for (const name of ['Every approval', 'Only for sensitive access (recommended)', 'Never']) {
    await expect(card.getByRole('radio', { name })).toBeDisabled();
  }
});

test('a passkey the API does not accept leaves the choice where it was, with the Settings line', async ({ page }) => {
  await virtualAuthenticator(page);
  await setup(page, { mode: 'ALWAYS', stepUpPasskeys: 1 }, {
    error: "Your passkey didn't confirm this. Tap Approve to try again.", code: 'passkey_approval_invalid',
  });
  await page.goto('/dashboard/settings');
  const card = page.locator('#passkey-approvals');
  await expect(card.getByRole('radio', { name: 'Every approval' })).toBeChecked();
  await card.getByRole('radio', { name: 'Never' }).check();
  await expect(card.getByRole('alert')).toHaveText("Your passkey didn't confirm this. Try again.");
  await expect(card.getByRole('radio', { name: 'Every approval' })).toBeChecked();
  await expect(card.getByRole('radio', { name: 'Never' })).not.toBeChecked();
});
