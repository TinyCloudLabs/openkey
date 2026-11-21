// @ts-expect-error bun:test is a runtime-only module; tsc does not ship its types
import { describe, expect, test } from 'bun:test';
import { OpenKey } from './index';

type Listener = (event: { origin: string; source: unknown; data: unknown }) => void;
type Frame = { src: string; posts: unknown[]; contentWindow: { postMessage: (data: unknown, origin: string) => void } };

function harness() {
  const globals = globalThis as unknown as { window: unknown; document: unknown };
  const oldWindow = globals.window;
  const oldDocument = globals.document;
  const listeners = new Set<Listener>();
  const frames: Frame[] = [];
  const element = (tag: string): Record<string, unknown> => {
    const el: Record<string, unknown> = {
      tag, style: {}, src: '', children: [],
      contentWindow: { postMessage() {} },
      appendChild(child: unknown) { (el.children as unknown[]).push(child); return child; },
      attachShadow: () => element('shadow'),
      setAttribute() {}, addEventListener() {}, remove() {},
    };
    if (tag === 'iframe') {
      const posts: unknown[] = [];
      el.contentWindow = { postMessage(data: unknown) { posts.push(data); } };
      el.posts = posts;
      frames.push(el as unknown as Frame);
    }
    return el;
  };
  globals.window = {
    location: { origin: 'https://app.test', hostname: 'app.test' }, innerHeight: 900,
    matchMedia: () => ({ matches: false }),
    addEventListener(type: string, listener: Listener) { if (type === 'message') listeners.add(listener); },
    removeEventListener(type: string, listener: Listener) { if (type === 'message') listeners.delete(listener); },
    dispatchEvent: () => true,
  };
  globals.document = { createElement: element, body: element('body') };
  const client = new OpenKey({ host: 'https://openkey.test' });
  const send = (frame: Frame, data: unknown) => {
    for (const listener of [...listeners]) listener({ origin: 'https://openkey.test', source: frame.contentWindow, data });
  };
  const phase = (frame: Frame) => {
    const url = new URL(frame.src);
    return { requestId: url.searchParams.get('requestId'), protocolVersion: Number(url.searchParams.get('protocolVersion')) };
  };
  async function connect() {
    const connecting = client.connect();
    const frame = frames.at(-1)!;
    send(frame, { type: 'openkey:ready', ...phase(frame) });
    send(frame, { type: 'openkey:auth:response', success: true, address: '0xfirst', keyId: 'key-first', ...phase(frame) });
    await connecting;
  }
  return { client, frames, send, phase, connect, restore() { globals.window = oldWindow; globals.document = oldDocument; } };
}

const PRESENTATION = {
  protocolVersion: 1 as const,
  displayName: 'Acme Notes',
  reason: 'Keep your notes in step.',
  onBehalfOf: 'Sync in Acme Notes',
  iconUrl: 'data:image/png;base64,iVBORw0KGgo=',
};

describe('signMessage presentation', () => {
  test('the client marks that it sends a presentation', () => {
    const h = harness();
    try {
      expect(h.client.signMessagePresentation).toBe(1);
    } finally { h.restore(); }
  });

  test('a widget whose ready says presentation: 1 gets the presentation, and only its five fields', async () => {
    const h = harness();
    try {
      await h.connect();
      const signing = h.client.signMessage({
        message: 'exact bytes',
        keyId: 'key-first',
        presentation: { ...PRESENTATION, extra: 'ignored' } as typeof PRESENTATION,
      });
      const frame = h.frames.at(-1)!;
      const phase = h.phase(frame);
      h.send(frame, { type: 'openkey:ready', presentation: 1, ...phase });
      expect(frame.posts.at(-1)).toEqual({
        type: 'openkey:sign:request', message: 'exact bytes', keyId: 'key-first', presentation: PRESENTATION, ...phase,
      });
      h.send(frame, { type: 'openkey:sign:response', success: true, signature: 'sig', address: '0xfirst', ...phase });
      h.send(frame, { type: 'openkey:resize', height: 700, layoutId: 1, ...phase });
      h.send(frame, { type: 'openkey:layout-ready', layoutId: 1, ...phase });
      h.send(frame, { type: 'openkey:sign:response', success: true, signature: 'sig', address: '0xfirst', ...phase });
      expect((await signing).signature).toBe('sig');
    } finally { h.restore(); }
  });

  test('a widget whose ready lacks the marker never receives the presentation', async () => {
    const h = harness();
    try {
      await h.connect();
      const signing = h.client.signMessage({ message: 'exact bytes', keyId: 'key-first', presentation: PRESENTATION });
      const frame = h.frames.at(-1)!;
      const phase = h.phase(frame);
      h.send(frame, { type: 'openkey:ready', ...phase });
      const posted = frame.posts.at(-1);
      expect(posted).toEqual({ type: 'openkey:sign:request', message: 'exact bytes', keyId: 'key-first', ...phase });
      expect(JSON.stringify(posted)).not.toContain('Acme');
      h.send(frame, { type: 'openkey:close', ...phase });
      await expect(signing).rejects.toBeDefined();
    } finally { h.restore(); }
  });

  test('a request with no presentation posts none, with or without the marker', async () => {
    const h = harness();
    try {
      await h.connect();
      for (const ready of [{}, { presentation: 1 }]) {
        const signing = h.client.signMessage({ message: 'exact bytes', keyId: 'key-first' });
        const frame = h.frames.at(-1)!;
        const phase = h.phase(frame);
        h.send(frame, { type: 'openkey:ready', ...ready, ...phase });
        expect(frame.posts.at(-1)).not.toHaveProperty('presentation');
        h.send(frame, { type: 'openkey:close', ...phase });
        await expect(signing).rejects.toBeDefined();
      }
    } finally { h.restore(); }
  });
});
