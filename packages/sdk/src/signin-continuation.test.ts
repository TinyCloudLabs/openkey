// @ts-expect-error bun:test is runtime-only in the SDK tsconfig
import { expect, test } from 'bun:test';
import { OpenKey } from './index';
import { privateKeyToAccount } from 'viem/accounts';
import { createSiweMessage } from 'viem/siwe';
import { sessionDidForPublicKey } from '@openkey/core';

for (const verification of ['success', 'false', 'throw', 'timeout'] as const) {
test(`one reserved window; required verifier ${verification}`, async () => {
  const previous = { window: (globalThis as any).window, document: (globalThis as any).document, fetch: globalThis.fetch, setTimeout: globalThis.setTimeout };
  const listeners = new Set<(event: any) => void>();
  if (verification === 'timeout') globalThis.setTimeout = ((fn: any, ms: number, ...args: any[]) => {
    const timer = previous.setTimeout(fn, ms, ...args);
    if (ms === 30_000) queueMicrotask(() => fn(...args));
    return timer;
  }) as typeof setTimeout;
  const host = 'https://openkey.test';
  const account = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
  const did = sessionDidForPublicKey(new Uint8Array(32));
  const siwe = createSiweMessage({ address: account.address, chainId: 1, domain: 'app.test', nonce: '12345678',
    uri: `${did}#${did.slice(8)}`, version: '1', issuedAt: new Date('2026-11-13T00:00:00Z') });
  let cancelledOnServer = false;
  let opens = 0;
  let active = true;
  const emit = (data: any, origin = host, source: any = popup) => {
    for (const listener of [...listeners]) listener({ origin, source, data });
  };
  const popup = { closed: false, location: { href: '' }, close() { this.closed = true; },
    postMessage(data: any) {
      if (data.type === 'openkey:signin:cancel') {
        cancelledOnServer = true;
        queueMicrotask(() => emit({ type: 'openkey:signin:cancelled', protocolVersion: 1, requestId: data.requestId, cancelled: true }));
      }
      if (data.type === 'openkey:signin:finalize') queueMicrotask(() => emit({
        type: 'openkey:signin:finalized', protocolVersion: 1, requestId: data.requestId, success: true,
        result: { protocolVersion: 1, address: account.address, keyId: 'selected', keyType: 'EXTERNAL',
          signedMessage: siwe, signature: data.signature, selectedActionKeys: [], permissions: [] },
      }));
      if (data.type === 'openkey:signin:resume') queueMicrotask(() => emit({
        type: 'openkey:signin:resumed', protocolVersion: 1, requestId: data.requestId,
      }));
    },
  };
  (globalThis as any).window = {
    location: { origin: 'https://app.test' }, screenX: 0, screenY: 0, outerWidth: 1000, outerHeight: 800,
    addEventListener(type: string, listener: any) { if (type === 'message') listeners.add(listener); },
    removeEventListener(type: string, listener: any) { if (type === 'message') listeners.delete(listener); },
    dispatchEvent() {}, matchMedia: () => ({ matches: false }),
    open() { opens++; if (!active) throw new Error('Popup blocked'); return popup; },
  };
  (globalThis as any).document = {};
  try {
    const sdk = new OpenKey({ host, mode: 'popup' });
    const handle = sdk.beginTinyCloudSignIn({ chainId: 1, verify: async ({ result, identity, request, origin }) => {
      expect(result.signedMessage).toBe(siwe); expect(identity.address).toBe(account.address);
      expect(request.siwe).toBe(siwe); expect(origin).toBe('https://app.test');
      if (verification === 'throw') throw new Error('verification failed');
      if (verification === 'timeout') return new Promise<boolean>(() => {});
      return verification === 'success';
    } });
    expect(opens).toBe(1);
    active = false;
    let prepared = false;
    (sdk as any).openFlow = async (_action: string, message: any, mode: string, reserved: any) => {
      expect(reserved.window).toBe(popup);
      expect(message.keyId).toBe('selected');
      expect(message.externalSign).toBe(true);
      expect(message.signInContinuation.requestId).toBeTruthy();
      return { authorizationContextToken: 'context', previewApprovalToken: 'preview',
        signedMessage: siwe, selectedActionIds: [], address: account.address };
    };
    (sdk as any).findWalletProvider = async (address: string) => {
      expect(address).toBe(account.address);
      return { request: async () => account.signMessage({ message: siwe }) };
    };
    globalThis.fetch = (async (url: unknown) => {
      expect(String(url)).toEndWith('/api/delegate/signin/capabilities');
      return Response.json({ enabled: true, protocolVersion: 1 });
    }) as typeof fetch;
    const result = handle.authorize(async () => {
      prepared = true;
      await new Promise((resolve) => setTimeout(resolve, 10));
      return { protocolVersion: 1, siwe, jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } };
    });
    for (let i = 0; i < 10; i++) await Promise.resolve();
    const requestId = new URL(popup.location.href).searchParams.get('requestId');
    const identity = { token: 'opaque', requestId, address: account.address, keyId: 'selected', keyType: 'EXTERNAL', chainId: 1 };
    const message = { type: 'openkey:signin:identity', protocolVersion: 1, requestId, identity };
    emit(message, 'https://evil.test');
    emit(message, host, {});
    expect(prepared).toBe(false);
    emit(message);
    if (verification === 'success') await result;
    else await expect(result).rejects.toThrow('verif');
    expect(cancelledOnServer).toBe(verification !== 'success');
    expect(prepared).toBe(true);
    expect(opens).toBe(1);
    expect(popup.closed).toBe(true);
    if (verification === 'success') expect((sdk as any).lastAuth).toEqual({ address: account.address, keyId: 'selected', keyType: 'EXTERNAL', chainId: 1 });
    else expect((sdk as any).lastAuth).toBeNull();
    await expect(handle.authorize(async () => ({ protocolVersion: 1, siwe: 'again' }))).rejects.toThrow('already started');
  } finally {
    globalThis.setTimeout = previous.setTimeout;
    globalThis.fetch = previous.fetch;
    (globalThis as any).window = previous.window;
    (globalThis as any).document = previous.document;
  }
});

}

test('missing or non-function verifier refuses before opening any window', () => {
  const sdk = new OpenKey({ appName: 'fixture', passkeysSupported: false });
  let opened = 0;
  (sdk as any).reservePopup = () => { opened++; return null; };
  for (const verify of [undefined, null, true, {}]) {
    expect(() => sdk.beginTinyCloudSignIn({ chainId: 1, verify } as any)).toThrow('result verifier');
  }
  expect(opened).toBe(0);
});
