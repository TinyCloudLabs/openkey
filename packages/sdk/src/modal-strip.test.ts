// @ts-expect-error bun:test is a runtime-only module; tsc does not ship its types
import { describe, expect, test } from 'bun:test';
import { OpenKey } from './index';

type FakeElement = {
  tag: string;
  className: string;
  textContent: string;
  style: Record<string, string>;
  src: string;
  children: FakeElement[];
  listeners: Record<string, Array<(event: unknown) => void>>;
  contentWindow: { postMessage: (data: unknown, origin: string) => void };
  appendChild: (child: FakeElement) => FakeElement;
  attachShadow: () => FakeElement;
  querySelector: () => null;
  setAttribute: () => void;
  addEventListener: (type: string, listener: (event: unknown) => void) => void;
  remove: () => void;
};

// Opens the real modal over a recording DOM and returns the card, the frame and a way to click a control.
function openModal(mobile: boolean) {
  const globals = globalThis as unknown as { window: unknown; document: unknown };
  const oldWindow = globals.window;
  const oldDocument = globals.document;
  const elements: FakeElement[] = [];
  const element = (tag: string): FakeElement => {
    const el: FakeElement = {
      tag, className: '', textContent: '', style: {}, src: '', children: [], listeners: {},
      contentWindow: { postMessage() {} },
      appendChild(child) { this.children.push(child); return child; },
      attachShadow() { return element('shadow'); },
      querySelector: () => null,
      setAttribute() {},
      addEventListener(type, listener) { (this.listeners[type] ??= []).push(listener); },
      remove() {},
    };
    elements.push(el);
    return el;
  };
  globals.window = {
    location: { origin: 'https://app.test', hostname: 'app.test' }, innerHeight: 900,
    matchMedia: () => ({ matches: mobile }),
    addEventListener() {}, removeEventListener() {}, dispatchEvent: () => true,
  };
  globals.document = { createElement: element, body: element('body') };
  const client = new OpenKey({ host: 'https://openkey.test' });
  const outcome = client.signMessage({ message: 'review me', keyId: 'key-1' }).then(
    () => 'signed', (error: { code?: string }) => error.code,
  );
  const card = elements.find((el) => el.className === 'ok-card')!;
  const iframe = elements.find((el) => el.tag === 'iframe')!;
  return {
    card, iframe, outcome,
    // Ends the request, so no load timer outlives the fake window.
    async restore() {
      card.children[0]!.children.find((child) => child.className === 'ok-close')!.listeners.click![0]!({});
      await outcome;
      globals.window = oldWindow;
      globals.document = oldDocument;
    },
  };
}

describe('SDK modal chrome', () => {
  for (const mobile of [false, true]) {
    test(`the handle and the close button sit in a strip before the frame, never beside it (${mobile ? 'sheet' : 'dialog'})`, async () => {
      const modal = openModal(mobile);
      try {
        // The card holds exactly the strip and then the frame: nothing else is a sibling that could be
        // positioned over the cross-origin frame.
        expect(modal.card.children.map((child) => child.className || child.tag)).toEqual(['ok-strip', 'iframe']);
        const strip = modal.card.children[0]!;
        expect(strip.children.map((child) => child.className)).toEqual(mobile ? ['ok-handle', 'ok-close'] : ['ok-close']);
        expect(modal.card.children[1]).toBe(modal.iframe);
        expect(modal.iframe.children).toEqual([]);
      } finally { await modal.restore(); }
    });
  }

  test('the close button dismisses the request as cancelled', async () => {
    const modal = openModal(false);
    try {
      const close = modal.card.children[0]!.children.find((child) => child.className === 'ok-close')!;
      expect(close.textContent).toBe('\u00d7');
      close.listeners.click![0]!({});
      expect(await modal.outcome).toBe('USER_CANCELLED');
    } finally { await modal.restore(); }
  });
});
