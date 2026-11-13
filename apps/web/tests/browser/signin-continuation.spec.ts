import { privateKeyToAccount } from 'viem/accounts';
import { sessionDidForPublicKey } from '@openkey/core';
import { readFileSync } from 'node:fs';
import { test, expect } from '@playwright/test';
import { EXPLORER_PERMISSION_POPUP_REQUEST } from '../../../../packages/capability-review/test/fixtures/index';
import { HOST, ORIGIN, LOOPBACK_ORIGIN } from './e2e-port';

// Real SDK + identity/sign widgets and browser clicks; synthetic sessions,
// WebAuthn response and API signing. This is not live account/TEE evidence.
const account = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
const address = account.address;
const did = sessionDidForPublicKey(new Uint8Array(32));
const keyTemplate = { id: 'selected', address, keyType: 'MANAGED', publicKey: '0x02', keyIndex: 0, createdAt: '2026-01-01' };
const siwe = EXPLORER_PERMISSION_POPUP_REQUEST.replace(/^explorer\.tinycloud\.xyz/, HOST)
  .replace('0xd559CCd9EB87c530A9a349262669386dE93cf412', address).replace(/^URI:.*$/m, `URI: ${did}#${did.slice(8)}`);

const scenarios = (['MANAGED', 'EXTERNAL'] as const).flatMap(keyType =>
  [true, false].map(initiallyAuthenticated => ({ keyType, initiallyAuthenticated, mode: 'success' })));
scenarios.push({ keyType: 'MANAGED', initiallyAuthenticated: true, mode: 'bad-handoff' },
  { keyType: 'EXTERNAL', initiallyAuthenticated: true, mode: 'bad-verifier' });
for (const { keyType, initiallyAuthenticated, mode } of scenarios) {
test(`${keyType}/${mode}: unknown app address (${initiallyAuthenticated ? 'existing' : 'cold'} OpenKey session): one clicked popup and one approval`, async ({ page, context }, testInfo) => {
  const key = { ...keyTemplate, keyType };
  await context.addInitScript(() => {
    Object.defineProperty(globalThis, 'PublicKeyCredential', { configurable: true, value: function PublicKeyCredential() {} });
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: async () => ({
      id: 'credential', rawId: new Uint8Array([1]).buffer, type: 'public-key',
      response: { clientDataJSON: new Uint8Array([1]).buffer, authenticatorData: new Uint8Array([1]).buffer,
        signature: new Uint8Array([1]).buffer, userHandle: null }, getClientExtensionResults: () => ({}),
    }) } });
  });
  let selected: string[] = [];
  let cancellations = 0;
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
    if (route.request().url().endsWith('/capabilities')) return route.fulfill({ headers: { 'access-control-allow-origin': '*' }, json: { enabled: true, protocolVersion: 1 } });
    if (route.request().url().endsWith('/resume')) return route.fulfill({ json: { resumed: true } });
    if (route.request().url().endsWith('/cancel')) { cancellations++; return route.fulfill({ json: { cancelled: true } }); }
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
  await context.route('**/__fixture-wallet-sign', async route => route.fulfill({ json: { signature: await account.signMessage({ message: siwe }) } }));
  await context.route('**/api/delegate/authorize-sign', async route => {
    expect(route.request().headers().origin).toBe(LOOPBACK_ORIGIN);
    return route.fulfill({ json: {
    protocolVersion: 1, address, keyId: key.id, keyType: key.keyType, signature: await account.signMessage({ message: siwe }), signedMessage: siwe,
    selectedActionKeys: selected, permissions: [],
  } }); });
  await page.goto('/__parity_harness');
  await page.evaluate(async ({ origin, siwe, address, mode }) => {
    const sdkPath = '/__signin-sdk.mjs';
    const { OpenKey } = await import(sdkPath);
    window.addEventListener('message', event => { if (event.data?.type === 'openkey:signin:error') (window as any).identityFailure = event.data.error; });
    (window as any).ethereum = { request: async ({ method }: { method: string }) => {
      if (method === 'eth_accounts' || method === 'eth_requestAccounts') return [address];
      if (method === 'personal_sign') return (await (await fetch('/__fixture-wallet-sign')).json()).signature;
      throw new Error('Unexpected wallet method: ' + method);
    } };
    const button = document.createElement('button');
    button.textContent = 'Start TinyCloud';
    button.onclick = () => {
      const sdk = new OpenKey({ host: origin, mode: 'popup' });
      const handle = sdk.beginTinyCloudSignIn({ chainId: 1, verify: async () => mode !== 'bad-verifier' });
      (window as any).outcome = 'pending';
      handle.authorize(async () => {
        await new Promise(resolve => setTimeout(resolve, 1200));
        return { protocolVersion: mode === 'bad-handoff' ? 99 : 1, siwe, jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, host: 'https://node.test' };
      }).then(() => { (window as any).outcome = 'signed'; }, (error: unknown) => { (window as any).outcome = String(error); });
    };
    document.body.append(button);
  }, { origin: LOOPBACK_ORIGIN, siwe, address, mode });
  const pages: unknown[] = [];
  context.on('page', popup => pages.push(popup));
  const popupPromise = page.waitForEvent('popup');
  await page.getByRole('button', { name: 'Start TinyCloud' }).click();
  const popup = await popupPromise;
  await popup.waitForURL('**/widget/signin?**');
  expect(await popup.evaluate(() => typeof globalThis.PublicKeyCredential)).toBe('function');
  if (!initiallyAuthenticated) await popup.getByRole('button', { name: 'Passkey', exact: true }).click();
  await popup.getByRole('button', { name: 'Continue with passkey' }).click();
  if (mode === 'bad-handoff') {
    await expect.poll(() => page.evaluate(() => (window as any).outcome)).toContain('protocolVersion');
    expect(cancellations).toBeGreaterThan(0);
    expect(popup.isClosed()).toBe(true);
    expect(pages).toHaveLength(1);
    return;
  }
  await popup.waitForURL('**/widget/sign?**').catch(async () => { throw new Error(await page.evaluate(() => (window as any).identityFailure ?? (window as any).outcome)); });
  const approve = popup.getByRole('button', { name: 'Approve', exact: true });
  await expect(approve).toBeEnabled();
  await popup.screenshot({ path: testInfo.outputPath('approval.png'), fullPage: true });
  await approve.click();
  if (mode === 'bad-verifier') {
    await expect.poll(() => page.evaluate(() => (window as any).outcome)).toContain('verification refused');
    expect(cancellations).toBeGreaterThan(0);
  } else await expect.poll(() => page.evaluate(() => (window as any).outcome)).toBe('signed');
  expect(pages).toHaveLength(1);
});

}
