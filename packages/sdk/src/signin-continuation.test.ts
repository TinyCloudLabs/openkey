// @ts-expect-error bun:test is runtime-only in the SDK tsconfig
import { expect, test } from 'bun:test';
import { OpenKey } from './index';

test('outer click reserves once; identity messages require origin/source; preparation reuses the window', async () => {
  const previous = { window: (globalThis as any).window, document: (globalThis as any).document, fetch: globalThis.fetch };
  const listeners = new Set<(event: any) => void>();
  const host = 'https://openkey.test';
  let opens = 0;
  let active = true;
  const emit = (data: any, origin = host, source: any = popup) => {
    for (const listener of [...listeners]) listener({ origin, source, data });
  };
  const popup = { closed: false, location: { href: '' }, close() { this.closed = true; },
    postMessage(data: any) {
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
    const handle = sdk.beginTinyCloudSignIn({ chainId: 1 });
    expect(opens).toBe(1);
    active = false;
    let prepared = false;
    (sdk as any).openFlow = async (_action: string, message: any, mode: string, reserved: any) => {
      expect(reserved.window).toBe(popup);
      expect(message.keyId).toBe('selected');
      expect(message.externalSign).toBe(true);
      expect(message.signInContinuation.requestId).toBeTruthy();
      return { authorizationContextToken: 'context', previewApprovalToken: 'preview',
        signedMessage: 'owner-bound SIWE', selectedActionIds: [], address: '0xowner' };
    };
    (sdk as any).findWalletProvider = async (address: string) => {
      expect(address).toBe('0xowner');
      return { request: async () => '0xsignature' };
    };
    globalThis.fetch = (async (_url: unknown, options: any) => {
      expect(JSON.parse(options.body).externalSignature).toBe('0xsignature');
      return Response.json({ protocolVersion: 1, address: '0xowner', keyId: 'selected', keyType: 'EXTERNAL',
        signedMessage: 'owner-bound SIWE', signature: '0xsignature', selectedActionKeys: [], permissions: [] });
    }) as typeof fetch;
    const result = handle.authorize(async () => {
      prepared = true;
      await new Promise((resolve) => setTimeout(resolve, 10));
      return { protocolVersion: 1, siwe: 'owner-bound SIWE' };
    });
    const requestId = new URL(popup.location.href).searchParams.get('requestId');
    const identity = { token: 'opaque', requestId, address: '0xowner', keyId: 'selected', keyType: 'EXTERNAL', chainId: 1 };
    const message = { type: 'openkey:signin:identity', protocolVersion: 1, requestId, identity };
    emit(message, 'https://evil.test');
    emit(message, host, {});
    expect(prepared).toBe(false);
    emit(message);
    await result;
    expect(prepared).toBe(true);
    expect(opens).toBe(1);
    expect(popup.closed).toBe(true);
    expect((sdk as any).lastAuth).toBeNull();
    await expect(handle.authorize(async () => ({ protocolVersion: 1, siwe: 'again' }))).rejects.toThrow('already started');
  } finally {
    globalThis.fetch = previous.fetch;
    (globalThis as any).window = previous.window;
    (globalThis as any).document = previous.document;
  }
});
