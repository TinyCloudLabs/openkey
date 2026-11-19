import { test, expect, type Page, type Route } from '@playwright/test';
import { generateKeyPairSync, randomBytes } from 'node:crypto';

// TC-3442: Sign Data answers the API's `/sign-typed-data/passkey` offer when the account's setting asks for it, and the
// signature request carries the assertion. A passkey refusal shows the API's words and the next tap answers a fresh offer.
const refusalText = "Your passkey didn't confirm this. Tap Approve to try again.";
const credentialId = randomBytes(16);
const key = { id: 'typed-key', keyIndex: 1, isPrimary: true, keyType: 'MANAGED', label: 'Key 1', address: `0x${'2'.repeat(40)}`, publicKey: '0x', createdAt: '2026-01-01T00:00:00Z' };
const typedData = { domain: { name: 'QA' }, types: { Note: [{ name: 'text', type: 'string' }] }, primaryType: 'Note', message: { text: 'passkey please' } };
type Body = Record<string, unknown> & { passkeyAssertion?: { challengeToken: string; response: { id: string } } };
type Recording = Window & { received: { type: string; success?: boolean }[] };
const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

async function setup(page: Page, surface: string, opts: { required: boolean; refuseFirst: boolean }) {
  const calls = { offers: [] as Body[], signs: [] as Body[] };
  await page.addInitScript(() => sessionStorage.setItem('openkey_session_token', 'qa-session'));
  await page.route('**/api/**', (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/api/auth/get-session') return json(route, { session: { id: 'qa-session', userId: 'u' }, user: { id: 'u' } });
    if (path === '/api/keys') return json(route, { keys: [key] });
    if (path === '/api/keys/typed-key/sign-typed-data/passkey') {
      calls.offers.push(request.postDataJSON());
      return json(route, opts.required ? { required: true, challengeToken: `token-${calls.offers.length}`, options: {
        challenge: randomBytes(32).toString('base64url'), rpId: 'localhost', userVerification: 'required', timeout: 60000,
        allowCredentials: [{ id: credentialId.toString('base64url'), type: 'public-key', transports: ['internal'] }],
      } } : { required: false });
    }
    if (path === '/api/keys/typed-key/sign-typed-data') {
      calls.signs.push(request.postDataJSON());
      if (opts.refuseFirst && calls.signs.length === 1) return json(route, { error: refusalText, code: 'passkey_approval_invalid' }, 403);
      return json(route, { signature: '0x1234', address: key.address });
    }
    return json(route, {});
  });
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
  await page.goto('/__parity_harness');
  await page.evaluate(({ surface, typedData }) => {
    const iframe = document.createElement('iframe');
    iframe.id = 'typed-data';
    iframe.style.width = '600px';
    iframe.style.height = '900px';
    iframe.src = `/widget/${surface}?origin=${encodeURIComponent(location.origin)}`;
    (window as unknown as Recording).received = [];
    window.addEventListener('message', (event) => {
      if (event.source !== iframe.contentWindow || event.origin !== location.origin) return;
      (window as unknown as Recording).received.push(event.data);
      if (event.data?.type === 'openkey:ready') {
        iframe.contentWindow?.postMessage({ type: 'openkey:signTypedData:request', data: typedData }, location.origin);
      }
    });
    document.body.append(iframe);
  }, { surface, typedData });
  const frame = page.frameLocator('#typed-data');
  await expect.poll(() => calls.offers.length).toBe(1);
  expect(calls.offers[0]).toEqual(typedData);
  const succeeded = async () => (await page.evaluate(() => (window as unknown as Recording).received))
    .filter((m) => m.type === 'openkey:signTypedData:response' && m.success === true).length;
  return { calls, frame, sign: frame.getByRole('button', { name: 'Sign Data', exact: true }), succeeded };
}

for (const surface of ['sign-typed-data', 'embed/sign-typed-data']) {
  test(`${surface}: Sign answers the offer; a passkey refusal shows the API text and the next Sign answers a fresh offer`, async ({ page }) => {
    const { calls, frame, sign, succeeded } = await setup(page, surface, { required: true, refuseFirst: true });
    await sign.click();
    await expect.poll(() => calls.signs.length).toBe(1);
    expect(calls.signs[0]!.passkeyAssertion).toMatchObject({ challengeToken: 'token-1', response: { id: credentialId.toString('base64url') } });
    await expect(frame.getByText(refusalText)).toBeVisible();
    await expect.poll(() => calls.offers.length).toBe(2);
    await sign.click();
    await expect.poll(() => calls.signs.length).toBe(2);
    expect(calls.signs[1]!.passkeyAssertion).toMatchObject({ challengeToken: 'token-2', response: { id: credentialId.toString('base64url') } });
    await expect.poll(succeeded).toBe(1);
  });

  test(`${surface}: an offer that is not required sends no assertion`, async ({ page }) => {
    const { calls, sign, succeeded } = await setup(page, surface, { required: false, refuseFirst: false });
    await sign.click();
    await expect.poll(() => calls.signs.length).toBe(1);
    expect(calls.signs[0]).not.toHaveProperty('passkeyAssertion');
    await expect.poll(succeeded).toBe(1);
  });
}
