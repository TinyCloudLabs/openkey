// @ts-expect-error bun:test is a runtime-only module; tsc does not ship its types
import { describe, expect, test, vi } from 'bun:test';
import { OpenKey } from './index';

// TC-4438: when an embedded flow gives up on the widget's `openkey:ready` and what it does then. A popup holds a
// different OpenKey session than the frame, so only a frame that never showed a sign of life falls back by itself.

const HOST = 'https://openkey.test';

type Frame = { src: string; posts: unknown[]; contentWindow: { postMessage(data: unknown): void } };
type Element = {
  tag: string; className?: string; textContent?: string; removed: boolean; children: Element[];
  clicks: Array<() => void>; style: Record<string, string>;
};

function harness() {
  const globals = globalThis as unknown as { window: unknown; document: unknown };
  const previous = { window: globals.window, document: globals.document };
  const listeners = new Map<string, Set<(event: unknown) => void>>();
  const frames: Frame[] = [];
  const elements: Element[] = [];
  const popups: string[] = [];
  const warnings: string[] = [];
  const element = (tag: string) => {
    const el: Element & Record<string, unknown> = {
      tag, style: {}, src: '', children: [], clicks: [], removed: false,
      contentWindow: { postMessage() {} },
      appendChild(child: Element) { el.children.push(child); return child; },
      attachShadow: () => element('shadow'),
      setAttribute() {},
      addEventListener(type: string, fn: () => void) { if (type === 'click') el.clicks.push(fn); },
      remove() { el.removed = true; },
    };
    if (tag === 'iframe') {
      const posts: unknown[] = [];
      el.posts = posts;
      el.contentWindow = { postMessage(data: unknown) { posts.push(data); } };
      frames.push(el as unknown as Frame);
    }
    elements.push(el);
    return el;
  };
  globals.window = {
    location: { origin: 'https://app.test', hostname: 'app.test' },
    innerHeight: 900, screenX: 0, screenY: 0, outerWidth: 1024, outerHeight: 768,
    navigator: { userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36' },
    matchMedia: () => ({ matches: false }),
    open(url: string) { popups.push(url); return { closed: false, close() {}, postMessage() {} }; },
    addEventListener(type: string, fn: (event: unknown) => void) {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type)!.add(fn);
    },
    removeEventListener(type: string, fn: (event: unknown) => void) { listeners.get(type)?.delete(fn); },
    dispatchEvent: () => true,
  };
  globals.document = { createElement: element, body: element('body') };
  const warn = vi.spyOn(console, 'warn').mockImplementation((text: string) => { warnings.push(text); });
  const dispatch = (type: string, event: unknown) => { for (const fn of [...(listeners.get(type) ?? [])]) fn(event); };
  return {
    client: new OpenKey({ host: HOST }),
    frames, popups, warnings,
    send(frame: Frame, data: unknown, origin = HOST) { dispatch('message', { origin, source: frame.contentWindow, data }); },
    violation(effectiveDirective: string, blockedURI: string) { dispatch('securitypolicyviolation', { effectiveDirective, blockedURI }); },
    /** The live "Open in a new window" offer, or undefined. */
    offer() {
      const offer = elements.find((el) => el.className === 'ok-new-window' && !el.removed);
      if (!offer) return undefined;
      const [link, note] = offer.children;
      return { link: link!.textContent, note: note!.textContent, click() { for (const fn of link!.clicks) fn(); } };
    },
    restore() { warn.mockRestore(); globals.window = previous.window; globals.document = previous.document; },
  };
}
type Harness = ReturnType<typeof harness>;

function connectIn(h: Harness) {
  const result = h.client.connect();
  result.catch(() => {});
  const frame = h.frames.at(-1);
  if (!frame) throw new Error('Connect iframe missing');
  const url = new URL(frame.src);
  return { result, frame, phase: { requestId: url.searchParams.get('requestId'), protocolVersion: 2 } };
}

async function withHarness(run: (h: Harness) => Promise<void>) {
  vi.useFakeTimers();
  const h = harness();
  try { await run(h); } finally { h.restore(); vi.useRealTimers(); }
}

async function outcome(promise: Promise<unknown>): Promise<string> {
  let result = 'pending';
  promise.then(() => { result = 'resolved'; }, (error: { code?: string }) => { result = `rejected:${error?.code}`; });
  for (let i = 0; i < 20; i++) await Promise.resolve();
  return result;
}

describe('embedded widget ready wait (TC-4438)', () => {
  test('a frame that says it is loading keeps the embedded flow past 3 s and completes it there', async () => {
    await withHarness(async (h) => {
      const { result, frame, phase } = connectIn(h);
      vi.advanceTimersByTime(500);
      h.send(frame, { type: 'openkey:loading' });
      vi.advanceTimersByTime(13_000);
      expect(h.popups).toHaveLength(0);
      h.send(frame, { type: 'openkey:ready', ...phase });
      expect(frame.posts.at(-1)).toMatchObject({ type: 'openkey:auth:request', ...phase });
      h.send(frame, { type: 'openkey:auth:response', success: true, address: '0xfirst', keyId: 'key-first', ...phase });
      expect((await result).keyId).toBe('key-first');
      vi.advanceTimersByTime(60_000);
      expect(h.popups).toHaveLength(0);
      expect(h.offer()).toBeUndefined();
      expect(h.warnings).toHaveLength(0);
    });
  });

  test('a loading frame never falls back by itself: after 15 s the card offers a new window, and only a click opens it', async () => {
    await withHarness(async (h) => {
      const { result, frame } = connectIn(h);
      h.send(frame, { type: 'openkey:loading' });
      vi.advanceTimersByTime(14_999);
      expect(h.offer()).toBeUndefined();
      vi.advanceTimersByTime(1);
      expect(h.offer()).toMatchObject({ link: 'Open in a new window', note: 'You may need to sign in again there.' });
      expect(h.warnings).toHaveLength(1);
      expect(h.warnings[0]).toContain('started loading but was not ready within 15000 ms');
      expect(h.warnings[0]).not.toContain('Content Security Policy');
      vi.advanceTimersByTime(60_000);
      expect(h.popups).toHaveLength(0);
      expect(await outcome(result)).toBe('pending');
      h.offer()!.click();
      expect(h.popups).toEqual([expect.stringMatching(new RegExp(`^${HOST}/widget/connect\\?`))]);
    });
  });

  test('without a click the loading frame waits for the overall timeout', async () => {
    await withHarness(async (h) => {
      const { result, frame } = connectIn(h);
      h.send(frame, { type: 'openkey:loading' });
      vi.advanceTimersByTime(5 * 60 * 1000);
      expect(await outcome(result)).toBe('rejected:TIMEOUT');
      expect(h.popups).toHaveLength(0);
    });
  });

  test('after a flow ran embedded, a silent frame on the same instance gets the offer, not an automatic popup', async () => {
    await withHarness(async (h) => {
      const first = connectIn(h);
      h.send(first.frame, { type: 'openkey:ready', ...first.phase });
      h.send(first.frame, { type: 'openkey:auth:response', success: true, address: '0xfirst', keyId: 'key-first', ...first.phase });
      await first.result;

      connectIn(h);
      vi.advanceTimersByTime(14_999);
      expect(h.popups).toHaveLength(0);
      expect(h.offer()).toBeUndefined();
      vi.advanceTimersByTime(1);
      expect(h.offer()?.link).toBe('Open in a new window');
      expect(h.warnings[0]).toContain('no message from the OpenKey frame within 15000 ms');
      expect(h.popups).toHaveLength(0);
    });
  });

  test('a ready after the offer withdraws it and continues embedded', async () => {
    await withHarness(async (h) => {
      const { result, frame, phase } = connectIn(h);
      h.send(frame, { type: 'openkey:loading' });
      vi.advanceTimersByTime(15_000);
      const offer = h.offer()!;
      h.send(frame, { type: 'openkey:ready', ...phase });
      expect(h.offer()).toBeUndefined();
      offer.click();
      expect(h.popups).toHaveLength(0);
      h.send(frame, { type: 'openkey:auth:response', success: true, address: '0xfirst', keyId: 'key-first', ...phase });
      expect((await result).keyId).toBe('key-first');
    });
  });

  test('a frame silent for 3 s on a fresh instance falls back without claiming a CSP block; foreign signals do not count', async () => {
    await withHarness(async (h) => {
      const { frame } = connectIn(h);
      h.send(frame, { type: 'openkey:loading' }, 'https://attacker.test');
      h.violation('frame-src', 'https://elsewhere.test/embed');
      h.violation('connect-src', `${HOST}/api`);
      vi.advanceTimersByTime(3_000);
      expect(h.popups).toHaveLength(1);
      expect(h.warnings).toHaveLength(1);
      expect(h.warnings[0]).toContain('falling back to popup: no message from the OpenKey frame within 3000 ms');
      expect(h.warnings[0]).not.toContain('Content Security Policy blocked');
      vi.advanceTimersByTime(20_000);
      expect(h.popups).toHaveLength(1);
      expect(h.offer()).toBeUndefined();
    });
  });

  test("a frame-src violation for the OpenKey frame is named as the page's CSP", async () => {
    await withHarness(async (h) => {
      const { frame } = connectIn(h);
      h.violation('frame-src', frame.src);
      vi.advanceTimersByTime(3_000);
      expect(h.popups).toHaveLength(1);
      expect(h.warnings[0]).toContain("the page's Content Security Policy blocked the OpenKey frame (frame-src)");
      expect(h.warnings[0]).toContain(`frame-src ${HOST}`);
    });
  });
});
