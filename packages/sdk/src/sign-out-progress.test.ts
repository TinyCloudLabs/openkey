// @ts-expect-error bun:test is a runtime-only module
import { describe, expect, test } from 'bun:test';
import { OpenKey } from './index';

describe('sign-out progress transport', () => {
  for (const mode of ['iframe', 'popup'] as const) {
    test(`${mode}: progress belongs to this widget and request; only the response completes sign-out`, async () => {
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
      const send = (data: any, origin = 'https://openkey.test', sender: any = source) => {
        for (const callback of [...listeners]) callback({ origin, source: sender, data });
      };
      const progress: string[] = [];
      const client = new OpenKey({ host: 'https://openkey.test', mode });
      let settled = false;
      const result = client.signOut({ onProgress: value => progress.push(value) }).then(value => { settled = true; return value; });
      try {
        send({ type: 'openkey:ready' }, 'https://other.test');
        send({ type: 'openkey:ready' }, undefined, {});
        expect(progress).toEqual([]);
        send({ type: 'openkey:ready' });
        expect(progress).toEqual(['ready']);
        const confirmed = { type: 'openkey:sign-out:confirmed', requestId: posted.requestId, protocolVersion: 1 };
        send(confirmed, 'https://other.test');
        send(confirmed, undefined, {});
        send({ ...confirmed, requestId: 'unrelated' });
        send({ ...confirmed, protocolVersion: 2 });
        expect(progress).toEqual(['ready']);
        send(confirmed);
        await Promise.resolve();
        expect(progress).toEqual(['ready', 'confirmed']);
        expect(settled).toBe(false);
        send({ ...confirmed, type: 'openkey:sign-out:response', success: true, revoked: true });
        expect(await result).toEqual({ requestId: posted.requestId, revoked: true });
      } finally {
        (client as any).cancelActiveFlows();
        (globalThis as any).window = previous.window;
        (globalThis as any).document = previous.document;
      }
    });
  }
});
