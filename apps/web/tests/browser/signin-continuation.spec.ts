import { readFileSync } from 'node:fs';
import { test, expect } from '@playwright/test';
import { EXPLORER_PERMISSION_POPUP_REQUEST } from '../../../../packages/capability-review/test/fixtures/index';
import { HOST, ORIGIN } from './e2e-port';

// Real SDK + identity/sign widgets and browser clicks; synthetic sessions,
// WebAuthn response and API signing. This is not live account/TEE evidence.
const address = '0xd559CCd9EB87c530A9a349262669386dE93cf412';
const key = { id: 'selected', address, keyType: 'MANAGED', publicKey: '0x02', keyIndex: 0, createdAt: '2026-01-01' };
const siwe = EXPLORER_PERMISSION_POPUP_REQUEST.replace(/^explorer\.tinycloud\.xyz/, HOST);

for (const initiallyAuthenticated of [true, false]) {
test(`unknown app address (${initiallyAuthenticated ? 'existing' : 'cold'} OpenKey session): one clicked popup and one approval`, async ({ page, context }, testInfo) => {
  await context.addInitScript(() => {
    Object.defineProperty(globalThis, 'PublicKeyCredential', { configurable: true, value: function PublicKeyCredential() {} });
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: async () => ({
      id: 'credential', rawId: new Uint8Array([1]).buffer, type: 'public-key',
      response: { clientDataJSON: new Uint8Array([1]).buffer, authenticatorData: new Uint8Array([1]).buffer,
        signature: new Uint8Array([1]).buffer, userHandle: null }, getClientExtensionResults: () => ({}),
    }) } });
  });
  let selected: string[] = [];
  await context.route('**/__signin-sdk.mjs', route => route.fulfill({ contentType: 'text/javascript',
    body: readFileSync(new URL('../../../../packages/sdk/dist/index.mjs', import.meta.url)) }));
  let authenticated = initiallyAuthenticated;
  const authSession = { session: { id: 'session', token: 'session-token' }, user: { id: 'owner', email: 'owner@example.test' } };
  await context.route('**/api/auth/get-session**', route => route.fulfill({ json: authenticated ? authSession : null }));
  await context.route('**/api/auth/providers', route => route.fulfill({ json: { providers: [] } }));
  await context.route('**/api/auth/passkey/**', route => {
    if (route.request().url().includes('generate-authenticate-options')) return route.fulfill({ json: {
      challenge: 'AQ', rpId: 'localhost', userVerification: 'required', allowCredentials: [{ id: 'AQ', type: 'public-key' }],
    } });
    authenticated = true;
    return route.fulfill({ json: { token: 'session-token', user: authSession.user, session: authSession.session } });
  });
  await context.route('**/api/keys', route => route.fulfill({ json: { keys: [key] } }));
  await context.route('**/api/keys/*', route => route.fulfill({ json: { key } }));
  await context.route('**/api/delegate/signin/*', route => {
    if (route.request().url().endsWith('/cancel')) return route.fulfill({ json: { cancelled: true } });
    const body = route.request().postDataJSON();
    if (route.request().url().endsWith('/options')) return route.fulfill({ json: {
      token: 'token', options: { challenge: 'AQ', rpId: 'localhost', userVerification: 'required',
        allowCredentials: [{ id: 'AQ', type: 'public-key' }] },
    } });
    return route.fulfill({ json: { ...key, keyId: key.id, chainId: 1, token: 'token', requestId: body.requestId } });
  });
  await context.route('**/api/delegate/authorize-sign-prepare', route => {
    expect(route.request().postDataJSON().signInContinuation.token).toBe('token');
    return route.fulfill({ json: { authorizationContextToken: 'context', expiresAt: new Date(Date.now() + 300_000).toISOString() } });
  });
  await context.route('**/api/delegate/authorize-sign-preview', route => {
    selected = route.request().postDataJSON().selectedActionIds;
    return route.fulfill({ json: { authorizationContextToken: 'context', previewApprovalToken: 'preview',
      previewApprovalExpiresAt: new Date(Date.now() + 60_000).toISOString(), signedMessage: siwe,
      selectedActionKeys: selected, permissions: selected.map(id => {
        const [service, space, path, ability] = id.split('\0');
        return { service, space, path, actions: [ability] };
      }) } });
  });
  await context.route('**/api/delegate/authorize-sign', route => route.fulfill({ json: {
    protocolVersion: 1, address, keyId: key.id, keyType: key.keyType, signature: '0xsynthetic', signedMessage: siwe,
    selectedActionKeys: selected, permissions: [],
  } }));
  await page.goto('/__parity_harness');
  await page.evaluate(async ({ origin, siwe }) => {
    const sdkPath = '/__signin-sdk.mjs';
    const { OpenKey } = await import(sdkPath);
    window.addEventListener('message', event => { if (event.data?.type === 'openkey:signin:error') (window as any).identityFailure = event.data.error; });
    const button = document.createElement('button');
    button.textContent = 'Start TinyCloud';
    button.onclick = () => {
      const sdk = new OpenKey({ host: origin, mode: 'popup' });
      const handle = sdk.beginTinyCloudSignIn({ chainId: 1 });
      (window as any).outcome = 'pending';
      handle.authorize(async () => {
        await new Promise(resolve => setTimeout(resolve, 1200));
        return { protocolVersion: 1, siwe, jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, host: 'https://node.test' };
      }).then(() => { (window as any).outcome = 'signed'; }, (error: unknown) => { (window as any).outcome = String(error); });
    };
    document.body.append(button);
  }, { origin: ORIGIN, siwe });
  const pages: unknown[] = [];
  context.on('page', popup => pages.push(popup));
  const popupPromise = page.waitForEvent('popup');
  await page.getByRole('button', { name: 'Start TinyCloud' }).click();
  const popup = await popupPromise;
  await popup.waitForURL('**/widget/signin?**');
  expect(await popup.evaluate(() => typeof globalThis.PublicKeyCredential)).toBe('function');
  if (!initiallyAuthenticated) await popup.getByRole('button', { name: 'Passkey', exact: true }).click();
  await popup.getByRole('button', { name: 'Continue with passkey' }).click();
  await popup.waitForURL('**/widget/sign?**').catch(async () => { throw new Error(await page.evaluate(() => (window as any).identityFailure ?? (window as any).outcome)); });
  const approve = popup.getByRole('button', { name: 'Approve', exact: true });
  await expect(approve).toBeEnabled();
  await popup.screenshot({ path: testInfo.outputPath('approval.png'), fullPage: true });
  await approve.click();
  await expect.poll(() => page.evaluate(() => (window as any).outcome)).toBe('signed');
  expect(pages).toHaveLength(1);
});

}
