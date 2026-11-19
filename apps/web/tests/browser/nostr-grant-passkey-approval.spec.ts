import { test, expect, type Page, type Route } from '@playwright/test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';

// TC-3442: Approve on a Nostr signing request creates a signing grant. When the account's passkey setting asks, the
// tap answers the grant's passkey offer and the grant carries the assertion; a passkey refusal keeps the card up with
// the API's words and the next tap answers a fresh offer.
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const credentialId = randomBytes(16);
const refusal = { error: "Your passkey didn't confirm this. Tap Approve to try again.", code: 'passkey_approval_invalid' };
const event = { kind: 1, created_at: 1_790_000_000, content: 'hello', tags: [], pubkey: 'ab'.repeat(32) };

type Grant = { clientOrigin: string; kinds: number[]; passkeyAssertion?: { challengeToken: string; response: { id: string } } };

function offer(token: string) {
  return { required: true, challengeToken: token, options: {
    challenge: randomBytes(32).toString('base64url'), rpId: 'localhost', userVerification: 'required', timeout: 60000,
    allowCredentials: [{ id: credentialId.toString('base64url'), type: 'public-key', transports: ['internal'] }],
  } };
}

async function setup(page: Page, opts: { required: boolean; refuseFirstGrant?: boolean }) {
  const calls = { offers: [] as unknown[], grants: [] as Grant[] };
  let granted = false;
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'test-session'));
  await page.route('**/api/**', (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/api/auth/get-session') return json(route, { session: { id: 'test-session' }, user: { id: 'u' } });
    if (path === '/api/keys/nostr/nostr-key/grants/passkey') {
      calls.offers.push(request.postDataJSON());
      return json(route, opts.required ? offer(`token-${calls.offers.length}`) : { required: false });
    }
    if (path === '/api/keys/nostr/nostr-key/grants') {
      calls.grants.push(request.postDataJSON() as Grant);
      if (opts.refuseFirstGrant && calls.grants.length === 1) return json(route, refusal, 403);
      granted = true;
      return json(route, { grant: { id: 'g1' } }, 201);
    }
    if (path === '/api/keys/nostr/nostr-key/sign-event') {
      if (!granted) return json(route, { error: 'interaction_required' }, 403);
      return json(route, { event: { ...event, id: 'e'.repeat(64), sig: 'f'.repeat(128) } });
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

type Received = { type: string; success?: boolean };

/** Frames the real widget route and sends it a signing request, the way the SDK does. */
async function requestSignature(page: Page) {
  await page.goto('/__parity_harness');
  await page.evaluate(() => {
    const frame = document.createElement('iframe');
    frame.id = 'nostr';
    frame.setAttribute('allow', 'publickey-credentials-get *');
    frame.src = `/widget/embed/nostr/approve?origin=${encodeURIComponent(location.origin)}`;
    document.body.append(frame);
    (window as unknown as { received: unknown[] }).received = [];
    window.addEventListener('message', (message) => {
      if (message.source === frame.contentWindow) (window as unknown as { received: unknown[] }).received.push(message.data);
    });
  });
  const received = () => page.evaluate(() => (window as unknown as { received: Received[] }).received);
  await expect.poll(async () => (await received()).some((m) => m.type === 'openkey:ready')).toBe(true);
  await page.evaluate((evt) => {
    document.querySelector<HTMLIFrameElement>('#nostr')?.contentWindow?.postMessage(
      { type: 'openkey:nostr:sign:request', requestId: 'r1', protocolVersion: 1, keyId: 'nostr-key', event: evt }, location.origin,
    );
  }, event);
  return { frame: page.frameLocator('#nostr'), received };
}

const signResponse = (messages: Received[]) => messages.find((m) => m.type === 'openkey:nostr:sign:response');

test('a grant the setting asks the passkey for sends the assertion for the offer it was shown', async ({ page }) => {
  await virtualAuthenticator(page);
  const calls = await setup(page, { required: true });
  const { frame, received } = await requestSignature(page);
  await expect.poll(() => calls.offers.length).toBe(1);
  expect(calls.offers[0]).toEqual({ clientOrigin: new URL(page.url()).origin, kinds: [1] });

  await frame.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect.poll(async () => signResponse(await received())?.success).toBe(true);
  expect(calls.grants).toHaveLength(1);
  expect(calls.grants[0]).toMatchObject({
    kinds: [1], passkeyAssertion: { challengeToken: 'token-1', response: { id: credentialId.toString('base64url') } },
  });
});

test('a grant the setting does not ask for carries no assertion', async ({ page }) => {
  const calls = await setup(page, { required: false });
  const { frame, received } = await requestSignature(page);
  await expect.poll(() => calls.offers.length).toBe(1);
  await frame.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect.poll(async () => signResponse(await received())?.success).toBe(true);
  expect(calls.grants).toHaveLength(1);
  expect(calls.grants[0]).not.toHaveProperty('passkeyAssertion');
});

test('a passkey refusal shows the API text and the next Approve answers a fresh offer', async ({ page }) => {
  await virtualAuthenticator(page);
  const calls = await setup(page, { required: true, refuseFirstGrant: true });
  const { frame, received } = await requestSignature(page);
  await expect.poll(() => calls.offers.length).toBe(1);

  const approve = frame.getByRole('button', { name: 'Approve', exact: true });
  await approve.click();
  await expect(frame.getByRole('alert')).toHaveText(refusal.error);
  await expect.poll(() => calls.offers.length).toBe(2);
  expect(signResponse(await received())).toBeUndefined();

  await approve.click();
  await expect.poll(async () => signResponse(await received())?.success).toBe(true);
  expect(calls.grants.map((grant) => grant.passkeyAssertion?.challengeToken)).toEqual(['token-1', 'token-2']);
});
