// @ts-expect-error bun:test is runtime-only in the SDK tsconfig
import { expect, test } from 'bun:test';
import { beginShareApprovalTransport } from './share-approval';

for (const mode of ['success', 'verifier-refusal', 'wrong-origin', 'wrong-source', 'cancel-retry'] as const) {
  test(`typed Share transport ${mode}`, async () => {
    const previous = (globalThis as any).window;
    const listeners = new Set<(event: any) => void>();
    const host = 'https://openkey.test';
    const origin = 'https://app.test';
    let cancelCount = 0;
    let verifierCount = 0;
    let outerRequestId = '';
    let helloCount = 0;
    const preview = { requestId: 'a'.repeat(43), shareId: 'b'.repeat(32), ownerDid: 'did:owner',
      sessionDid: 'did:session', origin, intentDigest: 'c'.repeat(64), expiresAt: Date.now() + 60_000,
      prepared: { siwe: 'exact server bytes' }, assertion: { token: 'token' } };
    const emit = (data: any, source: any = popup, eventOrigin = host) => {
      for (const listener of [...listeners]) listener({ data: { protocolVersion: 1, outerRequestId, ...data }, source, origin: eventOrigin });
    };
    const popup = { closed: false, location: { href: '' }, close() { this.closed = true; },
      postMessage(message: any) {
        if (message.type === 'openkey:share:hello') {
          helloCount++;
          expect(message.intent).not.toHaveProperty('shareId');
          queueMicrotask(() => {
            emit({ type: 'openkey:share:preview', preview });
            emit({ type: 'openkey:share:result', result: { purpose: 'share-create', ...preview, signature: 'signature' } });
          });
        }
        if (message.type === 'openkey:share:cancel') {
          cancelCount++;
          queueMicrotask(() => emit({ type: 'openkey:share:cancelled', requestId: preview.requestId,
            cancelled: mode === 'cancel-retry' && cancelCount === 1 ? false : true }));
        }
      },
    };
    (globalThis as any).window = { location: { origin },
      addEventListener: (_: string, fn: any) => listeners.add(fn),
      removeEventListener: (_: string, fn: any) => listeners.delete(fn) };
    try {
      const handle = beginShareApprovalTransport({ host, popup: popup as any,
        intent: { approvalNonce: 'd'.repeat(64), session: { siwe: 'session', signature: 'owner-signature', publicJwk: {} }, expiresAt: new Date().toISOString() },
        verify: async input => { verifierCount++; expect(input.identity.prepared.siwe).toBe('exact server bytes');
          expect(Object.isFrozen(input.identity)).toBe(true);
          return mode !== 'verifier-refusal' && mode !== 'cancel-retry'; },
        available: async () => true, signExternal: async () => { throw new Error('unexpected wallet'); }, registerCancel() {}, unregisterCancel() {},
      });
      const result = handle.authorize();
      await Promise.resolve();
      outerRequestId = new URL(popup.location.href).searchParams.get('requestId')!;
      if (mode === 'wrong-origin' || mode === 'wrong-source') {
        emit({ type: 'openkey:share:ready', purpose: 'share-create', requestId: outerRequestId },
          mode === 'wrong-source' ? {} : popup, mode === 'wrong-origin' ? 'https://evil.test' : host);
        expect(helloCount).toBe(0);
      }
      emit({ type: 'openkey:share:ready', purpose: 'share-create', requestId: outerRequestId });
      if (mode === 'verifier-refusal' || mode === 'cancel-retry') await expect(result).rejects.toThrow();
      else expect((await result).shareId).toBe(preview.shareId);
      expect(verifierCount).toBe(1);
      expect(popup.closed).toBe(true);
      expect(listeners.size).toBe(0);
      if (mode === 'cancel-retry') expect(cancelCount).toBe(2);
    } finally { (globalThis as any).window = previous; }
  });
}
