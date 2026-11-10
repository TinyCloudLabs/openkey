import { test, expect, type Page, type Route } from '@playwright/test';
import { ORIGIN } from './e2e-port';
import { generateKeyPairSync, randomBytes } from 'node:crypto';

// TC-1198: adding or removing a passkey with a session alone is refused with a
// typed 403; Settings prompts for the step-up the API offers and retries.
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const session = { session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3600000).toISOString() }, user: { id: 'u', email: 'owner@example.test', name: 'Owner' } };
const passkeys = [
  { id: 'pk-1', name: 'Laptop', deviceType: 'singleDevice', createdAt: new Date().toISOString() },
  { id: 'pk-2', name: 'Phone', deviceType: 'multiDevice', createdAt: new Date().toISOString() },
];
const stepUpRequired = (methods: string[]) => ({ code: 'PASSKEY_STEP_UP_REQUIRED', message: 'Verify it is you.', methods });
const registrationOptions = {
  challenge: 'dGMtMTE5OC1yZWdpc3RyYXRpb24tY2hhbGxlbmdl',
  rp: { id: 'localhost', name: 'OpenKey' },
  user: { id: 'dGMtMTE5OC11c2Vy', name: 'owner@example.test', displayName: 'Owner' },
  pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
  timeout: 60000,
  attestation: 'none',
  excludeCredentials: [],
  authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
};

type Calls = { registerOptions: number; verifyRegistration: number; deletes: number; send: unknown[]; verify: unknown[]; passkeyOptions: number };

async function setup(page: Page, handlers: { registerOptions?: (n: number) => [unknown, number]; deletePasskey?: (n: number) => [unknown, number] }) {
  const calls: Calls = { registerOptions: 0, verifyRegistration: 0, deletes: 0, send: [], verify: [], passkeyOptions: 0 };
  await page.context().addCookies([{ name: 'better-auth.session_token', value: 'cookie-session', url: ORIGIN }]);
  await page.route('**/api/**', (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/api/auth/get-session') return json(route, session);
    if (path === '/api/auth/providers') return json(route, { providers: [] });
    if (path === '/api/keys') return json(route, { keys: [] });
    if (path.includes('passkey/list-user-passkeys')) return json(route, passkeys);
    if (path === '/api/auth/passkey/generate-register-options') {
      const [body, status] = handlers.registerOptions?.(++calls.registerOptions) ?? [registrationOptions, 200];
      return json(route, body, status);
    }
    if (path === '/api/auth/passkey/verify-registration') { calls.verifyRegistration += 1; return json(route, { id: 'pk-3' }); }
    if (path === '/api/auth/passkey/delete-passkey') {
      const [body, status] = handlers.deletePasskey?.(++calls.deletes) ?? [{ status: true }, 200];
      return json(route, body, status);
    }
    if (path === '/api/account/step-up/email-otp/send') { calls.send.push(request.postDataJSON()); return json(route, { status: true }); }
    if (path === '/api/account/step-up/email-otp/verify') { calls.verify.push(request.postDataJSON()); return json(route, { status: true }); }
    if (path === '/api/account/step-up/passkey/options') {
      calls.passkeyOptions += 1;
      return json(route, { error: 'Verify with your passkey again to continue', code: 'passkey_step_up_required' }, 403);
    }
    if (path.includes('tinycloud')) return json(route, { tinyCloudManageKeyEnabled: true, mode: 'APP_MANAGED', policyEpoch: 0, apps: [], activity: [] });
    return json(route, {});
  });
  return calls;
}

/** A CDP virtual authenticator; `withCredential` preloads a resident passkey for localhost. */
async function virtualAuthenticator(page: Page, withCredential = false) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
  } });
  if (!withCredential) return;
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  await cdp.send('WebAuthn.addCredential', { authenticatorId, credential: {
    credentialId: randomBytes(16).toString('base64'), isResidentCredential: true, rpId: 'localhost',
    privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    userHandle: Buffer.from('u').toString('base64'), signCount: 0,
  } });
}

test('adding a passkey with a session alone asks for an email code, then retries the enrolment', async ({ page }) => {
  await virtualAuthenticator(page);
  const calls = await setup(page, {
    registerOptions: (n) => (n === 1 ? [stepUpRequired(['email']), 403] : [registrationOptions, 200]),
  });
  await page.goto('/dashboard/settings');
  // The passkey list renders after hydration, so the button is live.
  await expect(page.getByText('Laptop')).toBeVisible();
  await page.getByRole('button', { name: '+ Add Passkey' }).click();
  const dialog = page.getByRole('dialog', { name: 'Confirm it’s you to add a passkey' });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('button', { name: 'Use an existing passkey' })).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Email me a code' }).click();
  await dialog.getByLabel('Email verification code').fill('123456');
  await dialog.getByRole('button', { name: 'Verify code' }).click();
  await expect(dialog).toHaveCount(0);
  await expect.poll(() => calls.verifyRegistration).toBe(1);
  expect(calls.send).toEqual([{ purpose: 'passkey_register' }]);
  expect(calls.verify).toEqual([{ purpose: 'passkey_register', code: '123456' }]);
  expect(calls.registerOptions).toBe(2);
});

test('removing a passkey that counts for step-up offers only a passkey verification', async ({ page }) => {
  const calls = await setup(page, { deletePasskey: () => [stepUpRequired(['passkey']), 403] });
  await page.goto('/dashboard/settings');
  await page.getByRole('button', { name: 'Delete' }).first().click();
  const dialog = page.getByRole('dialog', { name: 'Confirm it’s you to remove this passkey' });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText('An email code can’t confirm this change.', { exact: false })).toBeVisible();
  await expect(dialog.getByRole('button', { name: 'Email me a code' })).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Use an existing passkey' }).click();
  await expect(dialog.getByRole('alert')).toContainText('No passkey on this account can confirm this change');
  expect(calls.passkeyOptions).toBe(1);
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog).toHaveCount(0);
  expect(calls.deletes).toBe(1);
});

test('an existing passkey confirms a removal and the removal is retried', async ({ page }) => {
  await virtualAuthenticator(page, true);
  const calls = await setup(page, {
    deletePasskey: (n) => (n === 1 ? [stepUpRequired(['passkey']), 403] : [{ status: true }, 200]),
  });
  const verified: unknown[] = [];
  await page.route('**/api/account/step-up/passkey/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith('/options')) {
      return json(route, { challengeToken: 'token-1', options: {
        challenge: 'dGMtMTE5OC1zdGVwLXVwLWNoYWxsZW5nZQ', rpId: 'localhost', allowCredentials: [], userVerification: 'required', timeout: 60000,
      } });
    }
    verified.push(route.request().postDataJSON());
    return json(route, { status: true });
  });
  await page.goto('/dashboard/settings');
  await page.getByRole('button', { name: 'Delete' }).first().click();
  const dialog = page.getByRole('dialog', { name: 'Confirm it’s you to remove this passkey' });
  await dialog.getByRole('button', { name: 'Use an existing passkey' }).click();
  await expect(dialog).toHaveCount(0);
  await expect.poll(() => calls.deletes).toBe(2);
  expect(verified).toEqual([expect.objectContaining({ challengeToken: 'token-1', response: expect.objectContaining({ type: 'public-key' }) })]);
  expect(calls.send).toEqual([]);
});

test('removing a passkey that does not count accepts a removal code and retries', async ({ page }) => {
  const calls = await setup(page, {
    deletePasskey: (n) => (n === 1 ? [stepUpRequired(['passkey', 'email']), 403] : [{ status: true }, 200]),
  });
  await page.goto('/dashboard/settings');
  await page.getByRole('button', { name: 'Delete' }).first().click();
  const dialog = page.getByRole('dialog', { name: 'Confirm it’s you to remove this passkey' });
  await dialog.getByRole('button', { name: 'Email me a code' }).click();
  await dialog.getByLabel('Email verification code').fill('654321');
  await dialog.getByRole('button', { name: 'Verify code' }).click();
  await expect(dialog).toHaveCount(0);
  await expect.poll(() => calls.deletes).toBe(2);
  expect(calls.send).toEqual([{ purpose: 'passkey_remove' }]);
  expect(calls.verify).toEqual([{ purpose: 'passkey_remove', code: '654321' }]);
});

test('an API without the step-up gate adds a passkey with no prompt', async ({ page }) => {
  await virtualAuthenticator(page);
  const calls = await setup(page, {});
  await page.goto('/dashboard/settings');
  await expect(page.getByText('Laptop')).toBeVisible();
  await page.getByRole('button', { name: '+ Add Passkey' }).click();
  await expect.poll(() => calls.verifyRegistration).toBe(1);
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(calls.send).toEqual([]);
});
