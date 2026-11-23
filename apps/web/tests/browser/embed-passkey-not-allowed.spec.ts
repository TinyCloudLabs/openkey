// The embedded connect frame, on another site's page, says in plain words when its passkey prompt ends with no
// passkey used: no passkey matched, the browser refused the prompt there, or the person dismissed it. The browser
// raises all three as a NotAllowedError, here with its raw text. The words point at the frame's own other route,
// "Continue with email", which sits on the same screen and works. Every API call is answered by page.route; no API
// server runs, and the passkey prompt is replaced by a refusal.

import { randomBytes } from 'node:crypto';
import { test, expect, type FrameLocator, type Page, type Route } from '@playwright/test';
import { LOOPBACK_ORIGIN, ORIGIN } from './e2e-port';

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

const RAW = 'The operation either timed out or was not allowed. See: https://www.w3.org/TR/webauthn-2/#sctn-privacy-considerations-client.';
const PLAIN = "That passkey couldn't be used here. Try another passkey or choose Continue with email.";
const PLAIN_NEW_ACCOUNT = "That passkey couldn't be used here. Try another passkey or choose Use a different email.";

async function mockApi(page: Page): Promise<string[]> {
  const verifies: string[] = [];
  await page.context().route(`${ORIGIN}/api/**`, (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') return json(route, null);
    if (path === '/api/auth/providers') return json(route, { providers: [] });
    if (path === '/api/passkey/generate-authenticate-options') {
      return json(route, {
        challengeToken: 'challenge-1', challenge: randomBytes(32).toString('base64url'), rpId: 'localhost',
        userVerification: 'required', timeout: 60000, allowCredentials: [],
      });
    }
    if (path === '/api/passkey/verify-authentication') verifies.push(path);
    return json(route, { error: `unmocked ${path}` }, 404);
  });
  return verifies;
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

test('a passkey prompt that ends with no passkey used says so in plain words, beside the email route', async ({ page }) => {
  const verifies = await mockApi(page);
  await page.context().addInitScript((raw) => {
    navigator.credentials.get = async () => { throw new DOMException(raw, 'NotAllowedError'); };
  }, RAW);
  const frame = await embed(page);

  await frame.getByRole('button', { name: 'Passkey' }).click();

  const alert = frame.getByRole('alert');
  await expect(alert).toHaveText(PLAIN);
  await expect(frame.getByText('timed out')).toHaveCount(0);
  expect(verifies).toEqual([]);
  // The route the words name is on the screen and usable.
  await expect(frame.getByRole('button', { name: 'Passkey' })).toBeEnabled();
  await frame.getByRole('button', { name: 'Continue with email' }).click();
  await expect(frame.locator('#embed-email')).toBeVisible();
});

// The new-account step, reached by an email code for an address OpenKey does not know, has its own passkey button and
// no "Continue with email" button, so its words name the step's own way out: "Use a different email".
test('on the new-account step the same refusal names Use a different email', async ({ page }) => {
  const verifies = await mockApi(page);
  await page.context().route(`${ORIGIN}/api/auth/**`, (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/email-otp/send-verification-otp') return json(route, { success: true });
    if (path === '/api/auth/sign-in/email-otp') {
      return json(route, { code: 'NEW_ACCOUNT_CONFIRMATION_REQUIRED', message: 'No OpenKey account exists for this email.', signupToken: 'signup-1' }, 403);
    }
    return route.fallback();
  });
  await page.context().addInitScript((raw) => {
    navigator.credentials.get = async () => { throw new DOMException(raw, 'NotAllowedError'); };
  }, RAW);
  const frame = await embed(page);
  await frame.getByRole('button', { name: 'Continue with email' }).click();
  await frame.locator('#embed-email').fill('newcomer@example.test');
  await frame.getByRole('button', { name: 'Send code' }).click();
  await frame.locator('#embed-otp').fill('123456');
  await frame.getByRole('button', { name: 'Verify and continue' }).click();
  const confirmation = frame.getByTestId('new-account-confirmation');

  await confirmation.getByRole('button', { name: 'Sign in with a passkey' }).click();

  await expect(frame.getByRole('alert')).toHaveText(PLAIN_NEW_ACCOUNT);
  await expect(frame.getByText('timed out')).toHaveCount(0);
  expect(verifies).toEqual([]);
  // The route the words name is on the screen and usable; "Continue with email" is not on this step.
  await expect(frame.getByRole('button', { name: 'Continue with email' })).toHaveCount(0);
  await expect(confirmation.getByRole('button', { name: 'Sign in with a passkey' })).toBeEnabled();
  await confirmation.getByRole('button', { name: 'Use a different email' }).click();
  await expect(frame.locator('#embed-email')).toBeVisible();
});
