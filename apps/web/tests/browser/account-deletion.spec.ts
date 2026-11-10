// Account deletion from Settings (App Store 5.1.1(v), plan TC-1188 §6) at phone width, against a stubbed
// API. The Settings entry is hidden for an API without the deletion step-up; a passkey-less account
// deletes with a deletion-purpose email code; a passkey account deletes after a real WebAuthn assertion
// (Chromium's virtual authenticator) on the current cookie session. Set DELETE_ACCOUNT_SHOTS_DIR to keep
// a screenshot of every step.
import { test, expect, type Page, type Route } from '@playwright/test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { ORIGIN } from './e2e-port';

const SHOTS = process.env.DELETE_ACCOUNT_SHOTS_DIR;
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const session = { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'u', email: 'owner@example.test', name: 'Owner' } };

test.use({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });

type Account = { email?: string; passkeys?: number; stepUpPasskeys?: number; emailUndeliverable?: boolean | undefined; keys?: number };
type Calls = { path: string; method: string; body: unknown; authorization: string | undefined }[];

async function setup(page: Page, account: Account, overrides: Record<string, (route: Route) => unknown> = {}) {
  const calls: Calls = [];
  let signedIn = true;
  await page.context().addCookies([{ name: 'better-auth.session_token', value: 'cookie-session', url: ORIGIN }]);
  await page.route('**/api/**', (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    calls.push({ path, method: request.method(), body: request.postDataJSON?.() ?? null, authorization: request.headers().authorization });
    if (overrides[path]) return overrides[path]!(route);
    if (path === '/api/auth/get-session') return json(route, signedIn ? { ...session, user: { ...session.user, email: account.email ?? session.user.email } } : null);
    if (path === '/api/auth/sign-out') { signedIn = false; return json(route, { success: true }); }
    if (path === '/api/auth/providers') return json(route, { providers: [] });
    if (path === '/api/auth/list-accounts') return json(route, []);
    if (path === '/api/account' && request.method() === 'GET') {
      const user: Record<string, unknown> = {
        id: 'u', email: account.email ?? session.user.email, name: 'Owner', emailVerified: true,
        _count: { ethereumKeys: account.keys ?? 2, passkeys: account.passkeys ?? 0 },
      };
      // An API without the deletion step-up omits emailUndeliverable: pass `emailUndeliverable: undefined`.
      if (!('emailUndeliverable' in account)) user.emailUndeliverable = false;
      else if (account.emailUndeliverable !== undefined) user.emailUndeliverable = account.emailUndeliverable;
      if (account.stepUpPasskeys !== undefined) user.stepUpPasskeys = account.stepUpPasskeys;
      return json(route, { user });
    }
    if (path === '/api/account/step-up/email-otp/send') return json(route, { status: true });
    if (path === '/api/account/step-up/email-otp/verify') {
      return request.postDataJSON()?.code === '246810'
        ? json(route, { status: true })
        : json(route, { error: 'Invalid or expired account verification code' }, 400);
    }
    if (path === '/api/account/delete') { signedIn = false; return json(route, { success: true, message: 'Account permanently deleted', keysDeleted: account.keys ?? 2 }); }
    if (path === '/api/keys') return json(route, { keys: [] });
    if (path.includes('passkey/list-user-passkeys')) return json(route, []);
    if (path === '/api/account/auto-sign') return json(route, { autoSignEnabled: false });
    if (path.includes('tinycloud')) return json(route, { tinyCloudManageKeyEnabled: true, mode: 'APP_MANAGED', policyEpoch: 0, apps: [], activity: [] });
    return json(route, {});
  });
  return calls;
}

async function shot(page: Page, name: string) {
  if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png`, fullPage: true });
}

async function noHorizontalScroll(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
}

test('the Settings entry stays hidden while the API has no deletion step-up', async ({ page }) => {
  await setup(page, { emailUndeliverable: undefined });
  await page.goto('/dashboard/settings');
  await expect(page.getByRole('heading', { name: 'Archived Keys' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Delete account' })).toHaveCount(0);
  await page.goto('/dashboard/settings/delete-account');
  await expect(page.getByText("Account deletion isn't available yet.")).toBeVisible();
  await shot(page, '0-unavailable');
});

test('a passkey-less account deletes with an email code, step by step', async ({ page }) => {
  const calls = await setup(page, { keys: 2 });
  await page.goto('/dashboard/settings');
  const entry = page.getByRole('link', { name: 'Delete account' });
  await expect(entry).toBeVisible();
  await entry.scrollIntoViewIfNeeded();
  await shot(page, '1-settings-entry');
  await entry.click();

  await expect(page.getByRole('heading', { name: 'Delete your OpenKey account' })).toBeVisible();
  await expect(page.getByText('Every key on this account is destroyed, including archived keys')).toBeVisible();
  await expect(page.getByText("OpenKey doesn't delete data that apps keep with other services")).toBeVisible();
  await expect(page.getByText('OpenKey revokes its Apple tokens')).toBeVisible();
  await expect(page.getByText("This can't be undone.")).toBeVisible();
  await noHorizontalScroll(page);
  await shot(page, '2-explain');
  await page.getByRole('button', { name: 'Continue' }).click();

  const confirm = page.getByRole('button', { name: 'Continue' });
  await expect(page.getByRole('heading', { name: 'Confirm deletion' })).toBeVisible();
  await page.getByLabel('Type DELETE MY ACCOUNT to confirm').fill('delete my account');
  await expect(confirm).toBeDisabled();
  await page.getByLabel('Type DELETE MY ACCOUNT to confirm').fill('DELETE MY ACCOUNT');
  await expect(confirm).toBeEnabled();
  await shot(page, '3-typed-confirmation');
  await confirm.click();

  await expect(page.getByRole('heading', { name: "Verify it's you" })).toBeVisible();
  await expect(page.getByText('We\'ll email a code to owner@example.test.')).toBeVisible();
  await shot(page, '4-email-send');
  await page.getByRole('button', { name: 'Send code' }).click();
  await expect(page.getByText('We sent a code to owner@example.test. It lasts 5 minutes.')).toBeVisible();
  // While that code is live the API sends no other, so no resend is offered yet.
  await expect(page.getByText(/You can ask for another code in [45]:\d\d/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Send a new code' })).toHaveCount(0);

  await page.getByLabel('Code from the email').fill('111111');
  await page.getByRole('button', { name: 'Verify and delete account' }).click();
  await expect(page.getByText('That code is wrong or expired.')).toBeVisible();
  expect(calls.filter((call) => call.path === '/api/account/delete')).toHaveLength(0);
  await shot(page, '5-email-wrong-code');

  await page.getByLabel('Code from the email').fill('246810');
  await shot(page, '6-email-code');
  await page.getByRole('button', { name: 'Verify and delete account' }).click();

  await expect(page.getByRole('heading', { name: 'Your account was deleted' })).toBeVisible();
  await expect(page.getByText('its keys were destroyed')).toBeVisible();
  await noHorizontalScroll(page);
  await shot(page, '7-done');

  const mutations = calls.filter((call) => call.method === 'POST' && call.path.startsWith('/api/account'));
  expect(mutations.map((call) => [call.path, call.body])).toEqual([
    ['/api/account/step-up/email-otp/send', { purpose: 'delete_account' }],
    ['/api/account/step-up/email-otp/verify', { purpose: 'delete_account', code: '111111' }],
    ['/api/account/step-up/email-otp/verify', { purpose: 'delete_account', code: '246810' }],
    ['/api/account/delete', { confirmation: 'DELETE MY ACCOUNT' }],
  ]);
  expect(mutations.every((call) => call.authorization === undefined)).toBe(true);
  // The result screen stays put after the session is gone, rather than bouncing to sign-in.
  await page.waitForTimeout(500);
  await expect(page).toHaveURL(/\/dashboard\/settings\/delete-account$/);
});

test('an Apple relay address Apple stopped forwarding to is told to turn forwarding back on', async ({ page }) => {
  await setup(page, { email: 'abc123@privaterelay.appleid.com', emailUndeliverable: true });
  await page.goto('/dashboard/settings/delete-account');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Type DELETE MY ACCOUNT to confirm').fill('DELETE MY ACCOUNT');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByText('Apple has stopped forwarding email to abc123@privaterelay.appleid.com')).toBeVisible();
  await expect(page.getByText('turn email forwarding back on')).toBeVisible();
  await expect(page.getByText('your Apple relay address, abc123@privaterelay.appleid.com')).toBeVisible();
  await noHorizontalScroll(page);
  await shot(page, '8-relay-forwarding-off');
});

test('an expired email step-up at delete time asks for a new code', async ({ page }) => {
  await setup(page, {}, {
    '/api/account/delete': (route) => json(route, { error: 'Verify with an email code again to continue', code: 'email_step_up_required' }, 403),
  });
  await page.goto('/dashboard/settings/delete-account');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Type DELETE MY ACCOUNT to confirm').fill('DELETE MY ACCOUNT');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('button', { name: 'Send code' }).click();
  await page.getByLabel('Code from the email').fill('246810');
  await page.getByRole('button', { name: 'Verify and delete account' }).click();
  await expect(page.getByText('Verify with a new email code to continue.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Send code' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Your account was deleted' })).toHaveCount(0);
});

test('a new code is offered only once the last one has expired', async ({ page }) => {
  await page.clock.install();
  const calls = await setup(page, {});
  await page.goto('/dashboard/settings/delete-account');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Type DELETE MY ACCOUNT to confirm').fill('DELETE MY ACCOUNT');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('button', { name: 'Send code' }).click();
  await expect(page.getByText('You can ask for another code in 5:00')).toBeVisible();
  await page.clock.runFor(5 * 60 * 1000);
  await page.getByRole('button', { name: 'Send a new code' }).click();
  await expect(page.getByText('You can ask for another code in 5:00')).toBeVisible();
  expect(calls.filter((call) => call.path === '/api/account/step-up/email-otp/send')).toHaveLength(2);
});

test('a passkey account before the passkey step-up ships cannot start a deletion it cannot finish', async ({ page }) => {
  const calls = await setup(page, { passkeys: 1 });
  await page.goto('/dashboard/settings/delete-account');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Type DELETE MY ACCOUNT to confirm').fill('DELETE MY ACCOUNT');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByText("Confirming with a passkey isn't available here yet")).toBeVisible();
  await expect(page.getByRole('button', { name: /Send code|Verify with passkey/ })).toHaveCount(0);
  expect(calls.some((call) => call.path.includes('step-up'))).toBe(false);
});

test('a passkey account verifies with a real passkey on this session, then deletes', async ({ page }) => {
  // A virtual platform authenticator holding one credential for rpId localhost.
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  const credentialId = randomBytes(16);
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  await cdp.send('WebAuthn.addCredential', {
    authenticatorId,
    credential: {
      credentialId: credentialId.toString('base64'),
      isResidentCredential: false,
      rpId: 'localhost',
      privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
      signCount: 0,
    },
  });

  let verified: { challengeToken?: string; response?: { id?: string; response?: { authenticatorData?: string } } } | null = null;
  const calls = await setup(page, { passkeys: 1, stepUpPasskeys: 1, keys: 1 }, {
    '/api/account/step-up/passkey/options': (route) => json(route, {
      challengeToken: 'ceremony-1',
      options: {
        challenge: randomBytes(32).toString('base64url'),
        rpId: 'localhost',
        timeout: 60000,
        userVerification: 'required',
        allowCredentials: [{ id: credentialId.toString('base64url'), type: 'public-key', transports: ['internal'] }],
      },
    }),
    '/api/account/step-up/passkey/verify': (route) => { verified = route.request().postDataJSON(); return json(route, { status: true }); },
  });

  await page.goto('/dashboard/settings/delete-account');
  await expect(page.getByText('Every key on this account is destroyed')).toBeVisible();
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Type DELETE MY ACCOUNT to confirm').fill('DELETE MY ACCOUNT');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByText('Confirm with a passkey saved for this account.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Send code' })).toHaveCount(0);
  await shot(page, '9-passkey-verify');
  await page.getByRole('button', { name: 'Verify with passkey and delete' }).click();

  await expect(page.getByRole('heading', { name: 'Your account was deleted' })).toBeVisible();
  await expect(page.getByText('its keys were destroyed')).toBeVisible();
  expect(verified!.challengeToken).toBe('ceremony-1');
  expect(verified!.response!.id).toBe(credentialId.toString('base64url'));
  expect(typeof verified!.response!.response!.authenticatorData).toBe('string');
  const paths = calls.filter((call) => call.method === 'POST' && call.path.startsWith('/api/account')).map((call) => call.path);
  expect(paths).toEqual(['/api/account/step-up/passkey/options', '/api/account/step-up/passkey/verify', '/api/account/delete']);
  expect(calls.every((call) => call.authorization === undefined)).toBe(true);
});

test('a passkey account whose API answers 404 for the passkey step-up is told it is unavailable', async ({ page }) => {
  const calls = await setup(page, { passkeys: 1, stepUpPasskeys: 1 }, {
    '/api/account/step-up/passkey/options': (route) => json(route, { error: 'Not Found' }, 404),
  });
  await page.goto('/dashboard/settings/delete-account');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Type DELETE MY ACCOUNT to confirm').fill('DELETE MY ACCOUNT');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('button', { name: 'Verify with passkey and delete' }).click();
  await expect(page.getByText("Confirming with a passkey isn't available here yet")).toHaveCount(1);
  await expect(page.getByRole('button', { name: 'Verify with passkey and delete' })).toHaveCount(0);
  expect(calls.some((call) => call.path === '/api/account/delete')).toBe(false);
});

test('a signed-out visitor is sent to sign in and back to the deletion page', async ({ page }) => {
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, null);
    return json(route, { providers: [] });
  });
  await page.goto('/dashboard/settings/delete-account');
  await expect(page).toHaveURL(/\/auth\/login\?redirect=%2Fdashboard%2Fsettings%2Fdelete-account/);
});
