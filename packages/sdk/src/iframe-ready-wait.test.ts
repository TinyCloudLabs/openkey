// @ts-expect-error bun:test is a runtime-only module; tsc does not ship its types
import { describe, expect, test, vi } from 'bun:test';
import { OpenKey } from './index';

// TC-4438: how long an embedded flow waits for the widget's `openkey:ready` before it opens a popup, and what it says.

const HOST = 'https://openkey.test';

type Frame = { tag: string; src: string; style: Record<string, string>; posts: unknown[]; contentWindow: { postMessage(data: unknown): void } };

function harness() {
  const globals = globalThis as unknown as { window: unknown; document: unknown };
  const previous = { window: globals.window, document: globals.document };
  const listeners = new Map<string, Set<(event: unknown) => void>>();
  const frames: Frame[] = [];
  const popups: string[] = [];
  const warnings: string[] = [];
  const element = (tag: string) => {
    const el: Record<string, unknown> & { children: unknown[] } = {
      tag, style: {}, src: '', children: [],
      contentWindow: { postMessage() {} },
      appendChild(child: unknown) { el.children.push(child); return child; },
      attachShadow: () => element('shadow'),
      setAttribute() {}, addEventListener() {}, remove() {},
    };
    if (tag === 'iframe') {
      const posts: unknown[] = [];
      el.posts = posts;
      el.contentWindow = { postMessage(data: unknown) { posts.push(data); } };
      frames.push(el as unknown as Frame);
    }
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
    restore() { warn.mockRestore(); globals.window = previous.window; globals.document = previous.document; },
  };
}

function connectIn(h: ReturnType<typeof harness>) {
  const result = h.client.connect();
  result.catch(() => {});
  const frame = h.frames[0];
  if (!frame) throw new Error('Connect iframe missing');
  const url = new URL(frame.src);
  return { result, frame, phase: { requestId: url.searchParams.get('requestId'), protocolVersion: 2 } };
}

async function withHarness(run: (h: ReturnType<typeof harness>) => Promise<void>) {
  vi.useFakeTimers();
  const h = harness();
  try { await run(h); } finally { h.restore(); vi.useRealTimers(); }
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
      expect(h.warnings).toHaveLength(0);
    });
  });

  test('a loading frame not ready by 15 s falls back to the popup and says it was slow, not blocked', async () => {
    await withHarness(async (h) => {
      const { frame } = connectIn(h);
      h.send(frame, { type: 'openkey:loading' });
      vi.advanceTimersByTime(14_999);
      expect(h.popups).toHaveLength(0);
      vi.advanceTimersByTime(1);
      expect(h.popups).toHaveLength(1);
      expect(h.popups[0]).toStartWith(`${HOST}/widget/connect?`);
      expect(h.warnings).toHaveLength(1);
      expect(h.warnings[0]).toContain('started loading but was not ready within 15000 ms');
      expect(h.warnings[0]).not.toContain('Content Security Policy');
    });
  });

  test('with no word from the frame, 3 s falls back without claiming a CSP block; foreign signals do not extend it', async () => {
    await withHarness(async (h) => {
      const { frame } = connectIn(h);
      h.send(frame, { type: 'openkey:loading' }, 'https://attacker.test');
      h.violation('frame-src', 'https://elsewhere.test/embed');
      h.violation('connect-src', `${HOST}/api`);
      vi.advanceTimersByTime(3_000);
      expect(h.popups).toHaveLength(1);
      expect(h.warnings).toHaveLength(1);
      expect(h.warnings[0]).toContain('no message from the OpenKey frame within 3000 ms');
      expect(h.warnings[0]).not.toContain('Content Security Policy blocked');
      // The fallback ends the frame's wait: the later loading deadline opens no second popup.
      vi.advanceTimersByTime(20_000);
      expect(h.popups).toHaveLength(1);
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
