// @ts-expect-error bun:test is a runtime-only module
import { describe, expect, test } from 'bun:test';
import { OpenKey } from './index';

describe('sign-out acknowledgement boolean', () => {
  for (const mode of ['iframe', 'popup'] as const) {
    for (const revoked of [true, false, 'true', 1, null, undefined]) {
      test(`${mode}: accepts revoked only as boolean true (${String(revoked)})`, async () => {
        const previous = { window: globalThis.window, document: globalThis.document };
        const listeners = new Set<(event: any) => void>();
        let posted: any;
        const source = { closed: false, close() {}, postMessage(value: any) { posted = value; } };
        const element = (): any => ({
          style: {}, contentWindow: source, children: [],
          setAttribute() {}, addEventListener() {}, remove() {},
          appendChild(child: any) { this.children.push(child); return child; },
          attachShadow: element,
        });
        (globalThis as any).document = { createElement: element, body: element() };
        (globalThis as any).window = {
          location: { origin: 'https://home.test', hostname: 'home.test' },
          navigator: { userAgent: 'test' },
          screenX: 0, screenY: 0, outerWidth: 1024, outerHeight: 768,
          innerHeight: 800, matchMedia: () => ({ matches: false }),
          open: () => source,
          addEventListener(type: string, callback: any) { if (type === 'message') listeners.add(callback); },
          removeEventListener(type: string, callback: any) { if (type === 'message') listeners.delete(callback); },
          dispatchEvent() {},
        };
        const send = (data: any) => {
          for (const callback of [...listeners]) callback({ origin: 'https://openkey.test', source, data });
        };
        const client = new OpenKey({ host: 'https://openkey.test', mode });
        const result = client.signOut();
        try {
          send({ type: 'openkey:ready' });
          const correlation = { requestId: posted.requestId, protocolVersion: 1 };
          send({ ...correlation, type: 'openkey:sign-out:response', success: true, revoked });
          expect(await result).toEqual({ requestId: posted.requestId, revoked: revoked === true });
        } finally {
          (client as any).cancelActiveFlows();
          (globalThis as any).window = previous.window;
          (globalThis as any).document = previous.document;
        }
      });
    }
  }
});
