import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { makeRecapResource, siweWithResources, FIXTURE_META } from '../../../../packages/capability-review/test/fixtures/index';
import { LOOPBACK_ORIGIN } from './e2e-port';

// Real SDK transport and typed popup. API/session/WebAuthn fixtures, not live-account evidence.
test('HTTPS outside app uses one popup and one Create share click', async ({ page, context }) => {
  const appOrigin = 'https://thirdparty.example';
  const requestId = 'A'.repeat(43), shareId = 'b'.repeat(32), intentDigest = 'c'.repeat(64);
  const ownerDid = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
  const sessionDid = 'did:key:z6Mktest';
  const siwe = siweWithResources([makeRecapResource({
    [`urn:tinycloud:encryption:${ownerDid}:default/share/${shareId}`]: { 'tinycloud.encryption/decrypt': [{}] },
  })], { domain: 'thirdparty.example', uri: sessionDid });
  const preview = { purpose: 'share-create', requestId, shareId, ownerDid, sessionDid, origin: appOrigin,
    intentDigest, expiresAt: Date.now() + 60_000, prepared: { siwe }, assertion: {
      token: 'token', options: { challenge: 'AQ', rpId: 'localhost', userVerification: 'required',
        allowCredentials: [{ id: 'AQ', type: 'public-key' }] } } };
  const phases: string[] = [];
  await context.addInitScript(() => {
    Object.defineProperty(globalThis, 'PublicKeyCredential', { configurable: true, value: function PublicKeyCredential() {} });
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: async () => ({
      id: 'credential', rawId: new Uint8Array([1]).buffer, type: 'public-key',
      response: { clientDataJSON: new Uint8Array([1]).buffer, authenticatorData: new Uint8Array([1]).buffer,
        signature: new Uint8Array([1]).buffer, userHandle: null }, getClientExtensionResults: () => ({}),
    }) } });
  });
  await context.route(`${appOrigin}/`, route => route.fulfill({ contentType: 'text/html', body: '<button id="start">Share</button>' }));
  await context.route(`${appOrigin}/sdk.mjs`, route => route.fulfill({ contentType: 'text/javascript',
    body: readFileSync(new URL('../../../../packages/sdk/dist/index.mjs', import.meta.url)) }));
  await context.route('**/api/auth/get-session**', route => route.fulfill({ json: {
    session: { id: 'auth-session' }, user: { id: 'owner', email: 'owner@example.test' },
  } }));
  await context.route('**/api/keys', route => route.fulfill({ json: { keys: [{ id: 'key', address: FIXTURE_META.address,
    publicKey: '0x02', keyType: 'MANAGED', keyIndex: 0, createdAt: '2026-01-01' }] } }));
  await context.route('**/api/delegate/share/*', route => {
    const phase = route.request().url().split('/').at(-1)!;
    phases.push(phase);
    if (phase === 'capabilities') return route.fulfill({ headers: { 'access-control-allow-origin': '*' }, json: { enabled: true, protocolVersion: 1 } });
    const body = route.request().postDataJSON();
    if (phase === 'window') {
      expect(body.observedOrigin).toBe(appOrigin);
      return route.fulfill({ json: { windowContextToken: 'window-token' } });
    }
    if (phase === 'options') {
      expect(body.windowContextToken).toBe('window-token');
      expect(body.intent.origin).toBe(appOrigin);
      expect(body.intent).not.toHaveProperty('shareId');
      return route.fulfill({ json: preview });
    }
    if (phase === 'verify') return route.fulfill({ json: { verified: true } });
    if (phase === 'resume') return route.fulfill({ json: { resumed: true } });
    if (phase === 'sign') {
      expect(body.intentDigest).toBe(intentDigest);
      return route.fulfill({ json: { ...preview, signature: 'fixture-signature' } });
    }
    return route.fulfill({ status: 400, json: {} });
  });
  await page.goto(appOrigin);
  await page.evaluate(async ({ host, siwe }) => {
    const modulePath = '/sdk.mjs';
    const { OpenKey } = await import(modulePath);
    const sdk = new OpenKey({ host, mode: 'popup' });
    document.querySelector<HTMLButtonElement>('#start')!.onclick = () => {
      const handle = sdk.beginShareApproval({ approvalNonce: 'd'.repeat(64), session: { siwe, signature: 'fixture-owner-signature', publicJwk: {} },
        expiresAt: new Date(Date.now() + 3600_000).toISOString() }, {
        verify: async ({ result, identity, origin }: any) => {
          (window as any).verified = origin === window.location.origin && result.requestId === identity.requestId &&
            result.shareId === identity.shareId && result.prepared.siwe === identity.prepared.siwe;
          return (window as any).verified;
        },
      });
      handle.authorize().then((result: any) => { (window as any).outcome = result.shareId; },
        (error: Error) => { (window as any).outcome = error.message; });
    };
  }, { host: LOOPBACK_ORIGIN, siwe });
  const popupPromise = page.waitForEvent('popup');
  await page.getByRole('button', { name: 'Share', exact: true }).click();
  const popup = await popupPromise;
  await expect(popup.getByRole('heading', { name: 'Create a new share' })).toBeVisible();
  await popup.getByRole('button', { name: 'Create share', exact: true }).click();
  await expect.poll(() => page.evaluate(() => (window as any).outcome)).toBe(shareId);
  expect(await page.evaluate(() => (window as any).verified)).toBe(true);
  expect(context.pages()).toHaveLength(1);
  expect(phases.filter(phase => phase !== 'capabilities')).toEqual(['window', 'options', 'verify', 'resume', 'sign']);
});
