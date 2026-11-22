// A build with no Terms release never reads the Terms status first, so a status call that fails or never answers
// holds nothing back: the window's page and the frame's connect go on, with no request to /api/account/terms. A call
// the API refuses with terms_required (its release went live before this build) still reads the status and shows the
// Terms in place, in the frame too. A build with a release fails closed: a status it can't read shows Try again and
// never the page. The suite's dev server runs as a build with a release (playwright.config.ts); the specs here that
// need a build without one say `off` for their page (src/lib/terms-release.ts). Every API call is answered by
// page.route; no API server runs.

import { test, expect, type Page, type Route } from '@playwright/test';

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

const RELEASE = {
  version: '2027-03-15', effective: '2027-03-15', whatChanged: null, privacyChanged: false,
  requiresAcceptance: true, previouslyAccepted: false,
};
const KEYS = [{
  id: 'key_0', address: '0xd559ccd9eb87c530a9a349262669386de93cf412', publicKey: '0x', keyIndex: 0, label: 'Key 0',
  keyType: 'MANAGED', isPrimary: true, createdAt: '2026-01-01T00:00:00Z',
}];

/** This page and its frames run as a build with no Terms release. */
const releaseOff = (page: Page) => page.addInitScript(() => sessionStorage.setItem('openkey_dev_terms_release', 'off'));

/** Every request to /api/account/terms, counted; `answer` says how each is answered (none: it never is). */
async function termsStatus(page: Page, answer: (route: Route) => unknown = () => undefined) {
  const calls: string[] = [];
  await page.route('**/api/account/terms', (route) => {
    calls.push(route.request().method());
    return answer(route);
  });
  return calls;
}

/** A signed-in window on the dashboard: every other API call has an empty answer (no keys, no leases). */
async function signedInWindow(page: Page) {
  await page.route('**/api/**', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/auth/get-session') {
      return json(route, {
        session: { id: 'switch-session', userId: 'switch-user', expiresAt: new Date(Date.now() + 3_600_000).toISOString() },
        user: { id: 'switch-user', email: 'switch@example.test' },
      });
    }
    return json(route, { keys: [], leases: [], organizations: [] });
  });
}

/** The connect frame on a same-origin host page, signed in with a stored session token. */
async function connectFrame(page: Page) {
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'switch-token'));
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const frame = document.createElement('iframe');
    frame.id = 'openkey';
    frame.style.cssText = 'border:none;width:400px;height:720px;display:block';
    frame.src = `/widget/embed/connect?origin=${encodeURIComponent(location.origin)}`;
    document.body.append(frame);
  });
  return page.frameLocator('#openkey');
}

test('with no Terms release a window shows its page with no Terms request, even when the status never answers', async ({ page }) => {
  await releaseOff(page);
  await signedInWindow(page);
  const calls = await termsStatus(page);
  await page.goto('/dashboard');
  await expect(page.locator('header').getByRole('link', { name: 'Dashboard' })).toBeVisible();
  await page.waitForTimeout(500);
  await expect(page.getByTestId('terms-check-failed')).toHaveCount(0);
  expect(calls).toEqual([]);
});

test('with no Terms release the connect frame goes on to the keys with no Terms request, even when the status never answers', async ({ page }) => {
  await releaseOff(page);
  const calls = await termsStatus(page);
  await page.route('**/api/keys', (route) => json(route, { keys: KEYS }));
  const frame = await connectFrame(page);
  await expect(frame.getByText('Connect with your primary key:')).toBeVisible();
  await expect(frame.getByTestId('terms-checking')).toHaveCount(0);
  expect(calls).toEqual([]);
});

test('with no Terms release a terms_required refusal in the frame shows the Terms there, and Agree goes on to the keys', async ({ page }) => {
  await releaseOff(page);
  let agreed = false;
  const calls = await termsStatus(page, (route) => json(route, { ...RELEASE, requiresAcceptance: !agreed, previouslyAccepted: agreed }));
  const accepts: Array<string | undefined> = [];
  await page.route('**/api/account/terms/accept', (route) => {
    accepts.push(route.request().headers().authorization);
    agreed = true;
    return json(route, { accepted: true, version: RELEASE.version });
  });
  await page.route('**/api/keys', (route) => agreed
    ? json(route, { keys: KEYS })
    : json(route, { error: 'terms_required', terms_url: `${new URL(route.request().url()).origin}/auth/terms` }, 403));
  const frame = await connectFrame(page);

  await expect(frame.getByRole('heading', { name: 'Accept the Terms and Privacy Policy' })).toBeVisible();
  expect(calls).toEqual(['GET']);
  const agree = frame.getByTestId('terms-agree');
  await expect(agree).toBeEnabled();
  await agree.click();
  await expect(frame.getByText('Connect with your primary key:')).toBeVisible();
  expect(accepts).toEqual(['Bearer switch-token']);
  expect(page.frames().map((candidate) => new URL(candidate.url()).pathname)).toContain('/widget/embed/connect');
});

test('with a Terms release a window whose status call fails shows Try again and never the page', async ({ page }) => {
  await signedInWindow(page);
  const calls = await termsStatus(page, (route) => route.abort('failed'));
  await page.goto('/dashboard');
  await expect(page.getByTestId('terms-check-failed')).toContainText('Couldn’t check whether you’ve agreed to the Terms.');
  await expect(page.getByTestId('terms-check-failed').getByRole('button', { name: 'Try again' })).toBeVisible();
  await expect(page.locator('header')).toHaveCount(0);
  expect(calls.length).toBeGreaterThan(0);
});
