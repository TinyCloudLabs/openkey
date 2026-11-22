// While OpenKey is still checking whether the browser has a session, `/delegate` must not show the sign-in
// prompt: a signed-in owner would see "Sign in to review the requested access" and its buttons flash by before
// the review appears. Every API call is answered by `page.route`; no API server runs.

import { test, expect, type Page, type Route } from '@playwright/test';
import { encodeBase64UrlJson } from '../../src/lib/device-authorization';
import { makeRecapResource } from '../../../../packages/capability-review/test/fixtures/index';
import { TERMS_ACCEPTED } from './terms-fixtures';

const CAPS_READ = 'tinycloud.capabilities/read';
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const signedInKey = { id: 'key_0', address, publicKey: '0x', keyIndex: 0, label: 'Key 0', keyType: 'MANAGED', isPrimary: true, createdAt: new Date().toISOString() };
const signedInSession = {
  session: { id: 's', userId: 'u', expiresAt: new Date(Date.now() + 3_600_000).toISOString() },
  user: { id: 'u', email: 'sam@example.test', name: 'Sam' },
};

function prepared() {
  const space = `tinycloud:pkh:eip155:1:${address}:default`;
  const siwe = [
    'cli.tinycloud.xyz wants you to sign in with your Ethereum account:', address, '',
    '',
    'URI: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    'Version: 1', 'Chain ID: 1', 'Nonce: abcdef123456', 'Issued At: 2026-10-03T00:00:00.000Z', 'Expiration Time: 2026-11-03T01:00:00.000Z',
    'Resources:',
    `- ${makeRecapResource({ [`${space}/capabilities`]: { [CAPS_READ]: [{}] } })}`,
  ].join('\n');
  const optionKey = `tinycloud.capabilities\0${space}\0`;
  const permissions = [{
    key: optionKey, service: 'capabilities', path: '', label: 'capabilities', resourcePath: 'capabilities',
    actions: [{ key: `${optionKey}\0${CAPS_READ}`, action: 'read', ability: CAPS_READ, required: true }],
  }];
  return {
    prepared: { siwe, spaceId: space, jwk: {} }, spaceId: space, ownerDid: `did:pkh:eip155:1:${address}`, address, chainId: 1,
    host: 'https://node.tinycloud.xyz', permissions, selectedActionKeys: permissions.flatMap((p) => p.actions.map((a) => a.key)), edited: false,
    authorizationContext: { token: 't', expiresAt: Date.now() + 600_000, baselineAbilitiesDigest: 'd' },
  };
}

/** Answers the API; the session answer waits for `releaseSession()` and is `null` (no session) when `session` is null. */
async function mock(page: Page, session: typeof signedInSession | null) {
  let release = () => {};
  const held = new Promise<void>((resolve) => { release = resolve; });
  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/auth/get-session') {
      await held;
      return json(route, 200, session);
    }
    if (url.pathname === '/api/keys') return json(route, 200, { keys: [signedInKey] });
    if (url.pathname === '/api/delegate/prepare') return json(route, 200, prepared());
    return json(route, 404, { error: `unmocked ${url.pathname}` });
  });
  await page.route('**/api/account/terms', (route) => route.fulfill({ json: TERMS_ACCEPTED }));
  return release;
}

/** Records whether the sign-in prompt was ever in the page, however briefly. */
async function watchForSignInPrompt(page: Page) {
  await page.addInitScript(() => {
    const flag = { seen: false };
    Object.defineProperty(window, '__signInPromptSeen', { get: () => flag.seen });
    const look = () => {
      if (document.body?.innerText.includes('Sign in to review this request')) flag.seen = true;
    };
    new MutationObserver(look).observe(document, { childList: true, subtree: true, characterData: true });
  });
}
const promptSeen = (page: Page) => page.evaluate(() => (window as unknown as { __signInPromptSeen: boolean }).__signInPromptSeen);

const jwk = encodeBase64UrlJson({ kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
const link = `/delegate?did=did:key:z6Mk&jwk=${jwk}`;
const signInPrompt = (page: Page) => page.getByRole('heading', { name: 'Sign in to review this request' });

test.describe('the session check on /delegate', () => {
  test('a signed-in owner sees a checking state, never the sign-in prompt', async ({ page }) => {
    await watchForSignInPrompt(page);
    const releaseSession = await mock(page, signedInSession);
    await page.goto(link);

    await expect(page.locator('[role="status"] [aria-current="step"]')).toHaveText('Checking your OpenKey account');
    await expect(signInPrompt(page)).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Continue with email' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Use a passkey instead' })).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Create an account' })).toHaveCount(0);
    await expect(page.getByRole('link', { name: 'Recover account' })).toHaveCount(0);

    releaseSession();
    await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
    await expect(page.getByText('Checking your OpenKey account', { exact: true })).toHaveCount(0);
    expect(await promptSeen(page)).toBe(false);
  });

  test('with no session, the sign-in prompt appears once the check is done', async ({ page }) => {
    const releaseSession = await mock(page, null);
    await page.goto(link);

    await expect(page.locator('[role="status"] [aria-current="step"]')).toHaveText('Checking your OpenKey account');
    await expect(signInPrompt(page)).toHaveCount(0);

    releaseSession();
    await expect(signInPrompt(page)).toBeVisible();
    await expect(page.getByRole('link', { name: 'Continue with email' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Create an account' })).toBeVisible();
    await expect(page.getByText('Checking your OpenKey account', { exact: true })).toHaveCount(0);
  });
});
