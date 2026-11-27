import { test, expect, type Page, type Route } from '@playwright/test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { HOST, ORIGIN } from './e2e-port';
import { makeRecapResource, siweWithResources } from '../../../../packages/capability-review/test/fixtures/index';
import { TERMS_ACCEPTED } from './terms-fixtures';

// TC-3442: Approve on a message signature answers the API's passkey offer when the account's setting asks for it, and
// the approval carries the assertion. The server-authoritative path gets its offer with each preview; the exact-byte
// path asks `/sign/passkey`. A passkey refusal shows the API's words and the next Approve answers a fresh offer.
const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const recapSiwe = siweWithResources([makeRecapResource({
  [`tinycloud:pkh:eip155:1:${address}:default/capabilities`]: { 'tinycloud.capabilities/read': [{}] },
})], { domain: HOST, uri: `http://${HOST}` });
const plainMessage = 'exact legacy bytes';
const refusalText = "Your passkey didn't confirm this. Tap Approve to try again.";
const refusal = { error: refusalText, code: 'passkey_approval_invalid' };
const credentialId = randomBytes(16);
const key = { id: 'selected-key', address, publicKey: '0x02', keyIndex: 0, label: 'Selected', keyType: 'MANAGED', createdAt: '2026-01-01T00:00:00Z' };

type Body = Record<string, unknown> & { passkeyAssertion?: { challengeToken: string; response: { id: string } } };
type HostWindow = Window & { received: Body[]; signWindow: Window };
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

function offer(token: string) {
  return { required: true, challengeToken: token, options: {
    challenge: randomBytes(32).toString('base64url'), rpId: 'localhost', userVerification: 'required', timeout: 60000,
    allowCredentials: [{ id: credentialId.toString('base64url'), type: 'public-key', transports: ['internal'] }],
  } };
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

/** Mocks the API for one signing request; `required` decides every offer, `refuseFirst` refuses the first approval. */
async function mockApi(page: Page, opts: { required: boolean; refuseFirst: boolean }) {
  const calls = { offers: [] as Body[], signs: [] as Body[], previews: 0 };
  const offerFor = (n: number) => (opts.required ? offer(`token-${n}`) : { required: false });
  await page.context().addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.context().route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/api/auth/get-session') return json(route, { session: { id: 'test-session' }, user: { id: 'u' } });
    if (path === '/api/keys/selected-key') return json(route, { key });
    if (path === '/api/keys/selected-key/sign/passkey') {
      calls.offers.push(request.postDataJSON());
      return json(route, offerFor(calls.offers.length));
    }
    if (path === '/api/delegate/authorize-sign-prepare') {
      return json(route, { authorizationContextToken: 'context', expiresAt: new Date(Date.now() + 300_000).toISOString() });
    }
    if (path === '/api/delegate/authorize-sign-preview') {
      const n = ++calls.previews;
      const body = request.postDataJSON() as { selectedActionIds: string[] };
      return json(route, {
        authorizationContextToken: 'context', previewApprovalToken: `preview-${n}`,
        previewApprovalExpiresAt: new Date(Date.now() + 60_000).toISOString(),
        signedMessage: recapSiwe, selectedActionKeys: body.selectedActionIds, passkey: offerFor(n),
        permissions: body.selectedActionIds.map((id) => {
          const [service, space, path, ability] = id.split('\0');
          return { service, space, path, actions: [ability] };
        }),
      });
    }
    if (path === '/api/delegate/authorize-sign' || path === '/api/keys/selected-key/sign') {
      calls.signs.push(request.postDataJSON());
      if (opts.refuseFirst && calls.signs.length === 1) return json(route, refusal, 403);
      return json(route, { signature: `0x${'11'.repeat(65)}`, address, signedMessage: recapSiwe, selectedActionKeys: [], permissions: [] });
    }
    return json(route, {});
  });
  await page.context().route('**/api/account/terms', (route) => route.fulfill({ json: TERMS_ACCEPTED }));
  return calls;
}

/** Opens the real widget as the SDK does (popup v1, iframe v2) and sends it one signing request. */
async function openSigning(page: Page, surface: 'popup' | 'iframe', message: string) {
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const host = window as unknown as HostWindow;
    host.received = [];
    window.addEventListener('message', (event) => {
      if (event.origin === location.origin && event.source === host.signWindow) host.received.push(event.data);
    });
  });
  let signingPage = page;
  if (surface === 'popup') {
    const popup = page.waitForEvent('popup');
    await page.evaluate(() => {
      (window as unknown as HostWindow).signWindow = window.open(`/widget/sign?origin=${encodeURIComponent(location.origin)}`)!;
    });
    signingPage = await popup;
  } else {
    await page.evaluate(() => {
      const iframe = document.createElement('iframe');
      iframe.id = 'sign';
      iframe.src = `/widget/embed/sign?origin=${encodeURIComponent(location.origin)}&requestId=r1&protocolVersion=2&keyId=selected-key`;
      iframe.style.width = '700px';
      document.body.append(iframe);
      (window as unknown as HostWindow).signWindow = iframe.contentWindow!;
    });
  }
  await virtualAuthenticator(signingPage);
  const received = () => page.evaluate(() => (window as unknown as HostWindow).received);
  await expect.poll(async () => (await received()).some((m) => m.type === 'openkey:ready')).toBe(true);
  await page.evaluate(({ message, version }) => {
    (window as unknown as HostWindow).signWindow.postMessage({
      type: 'openkey:sign:request', requestId: 'r1', protocolVersion: version,
      authorizationProtocolVersion: 1, keyId: 'selected-key', jwk: { kty: 'EC' }, message,
    }, location.origin);
  }, { message, version: surface === 'iframe' ? 2 : 1 });
  const view = surface === 'popup' ? signingPage : page.frameLocator('#sign');
  const approve = view.locator('button.approve');
  // The iframe approves only once the host says it applied the frame's height.
  async function ready() {
    await expect(async () => {
      if (surface === 'iframe') {
        await page.evaluate(() => {
          const host = window as unknown as HostWindow;
          const resize = host.received.filter((m) => m.type === 'openkey:resize').at(-1);
          if (!resize) return;
          const height = Math.min(Number(resize.height), Math.floor(innerHeight * 0.85));
          document.querySelector<HTMLIFrameElement>('#sign')!.style.height = `${height}px`;
          host.signWindow.postMessage({ type: 'openkey:layout-applied', requestId: 'r1',
            protocolVersion: 2, height, layoutId: resize.layoutId }, location.origin);
        });
      }
      await expect(approve).toBeEnabled({ timeout: 500 });
    }).toPass();
  }
  const succeeded = async () => (await received()).filter((m) => m.type === 'openkey:sign:response' && m.success === true).length;
  return { view, approve, ready, succeeded };
}

for (const surface of ['popup', 'iframe'] as const) {
  for (const path of ['preview', 'exact-byte'] as const) {
    const message = path === 'preview' ? recapSiwe : plainMessage;

    test(`${surface} ${path}: Approve answers the offer; a passkey refusal shows the API text and the next Approve answers a fresh offer`, async ({ page }) => {
      const calls = await mockApi(page, { required: true, refuseFirst: true });
      const h = await openSigning(page, surface, message);
      await h.ready();
      await h.approve.click();
      await expect.poll(() => calls.signs.length).toBe(1);
      expect(calls.signs[0]!.passkeyAssertion).toMatchObject({ challengeToken: 'token-1', response: { id: credentialId.toString('base64url') } });
      await expect(h.view.getByText(refusalText)).toBeVisible();
      // The spent challenge is replaced without another tap: a new preview (with its offer) or a new offer.
      if (path === 'preview') await expect.poll(() => calls.previews).toBe(2);
      else await expect.poll(() => calls.offers.length).toBe(2);
      await h.ready();
      await expect(h.view.getByText(refusalText)).toBeVisible();
      await h.approve.click();
      await expect.poll(() => calls.signs.length).toBe(2);
      expect(calls.signs[1]!.passkeyAssertion).toMatchObject({ challengeToken: 'token-2', response: { id: credentialId.toString('base64url') } });
      if (path === 'preview') expect(calls.signs[1]!.previewApprovalToken).toBe('preview-2');
      else expect(calls.offers).toEqual([{ message, requestOrigin: ORIGIN }, { message, requestOrigin: ORIGIN }]);
      await expect.poll(h.succeeded).toBe(1);
    });

    test(`${surface} ${path}: an offer that is not required sends no assertion`, async ({ page }) => {
      const calls = await mockApi(page, { required: false, refuseFirst: false });
      const h = await openSigning(page, surface, message);
      if (path === 'exact-byte') await expect.poll(() => calls.offers.length).toBe(1);
      await h.ready();
      await h.approve.click();
      await expect.poll(() => calls.signs.length).toBe(1);
      expect(calls.signs[0]).not.toHaveProperty('passkeyAssertion');
      await expect.poll(h.succeeded).toBe(1);
    });
  }
}

test.describe('dashboard key page', () => {
  async function openKeyPage(page: Page, opts: { required: boolean; refuseFirst: boolean }) {
    await page.context().addCookies([{ name: 'better-auth.session_token', value: 'cookie-session', url: ORIGIN }]);
    const calls = await mockApi(page, opts);
    await virtualAuthenticator(page);
    await page.goto('/dashboard/keys/selected-key');
    await page.getByLabel('Message').fill('hello from the owner');
    await expect.poll(() => calls.offers.length).toBe(1);
    expect(calls.offers[0]).toEqual({ message: 'hello from the owner' });
    return { calls, sign: page.getByRole('button', { name: 'Sign Message', exact: true }) };
  }

  test('Sign answers the offer; a passkey refusal shows the API text and the next Sign answers a fresh offer', async ({ page }) => {
    const { calls, sign } = await openKeyPage(page, { required: true, refuseFirst: true });
    await sign.click();
    await expect.poll(() => calls.signs.length).toBe(1);
    expect(calls.signs[0]!.passkeyAssertion).toMatchObject({ challengeToken: 'token-1', response: { id: credentialId.toString('base64url') } });
    await expect(page.getByRole('alert')).toHaveText(refusalText);
    await expect.poll(() => calls.offers.length).toBe(2);
    await sign.click();
    await expect.poll(() => calls.signs.length).toBe(2);
    expect(calls.signs[1]!.passkeyAssertion).toMatchObject({ challengeToken: 'token-2' });
    await expect(page.getByText(`0x${'11'.repeat(65)}`)).toBeVisible();
  });

  test('an offer that is not required sends no assertion', async ({ page }) => {
    const { calls, sign } = await openKeyPage(page, { required: false, refuseFirst: false });
    await sign.click();
    await expect.poll(() => calls.signs.length).toBe(1);
    expect(calls.signs[0]).not.toHaveProperty('passkeyAssertion');
  });
});
