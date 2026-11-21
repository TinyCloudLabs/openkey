// @ts-expect-error bun:test is a runtime-only module; tsc does not ship its types
import { describe, expect, test } from 'bun:test';
import { OpenKey } from './index';

type Listener = (event: { origin: string; source: unknown; data: unknown }) => void;
type Frame = { src: string; posts: unknown[]; contentWindow: { postMessage: (data: unknown, origin: string) => void } };

function harness(config: ConstructorParameters<typeof OpenKey>[0] = {}) {
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
  const client = new OpenKey({ host: 'https://openkey.test', ...config });
  const send = (frame: Frame, data: unknown) => {
    for (const listener of [...listeners]) listener({ origin: 'https://openkey.test', source: frame.contentWindow, data });
  };
  const phase = (frame: Frame) => {
    const url = new URL(frame.src);
    return { requestId: url.searchParams.get('requestId'), protocolVersion: Number(url.searchParams.get('protocolVersion')) };
  };
  async function connect(keyType?: 'MANAGED' | 'EXTERNAL') {
    const connecting = client.connect();
    const frame = frames.at(-1)!;
    send(frame, { type: 'openkey:ready', ...phase(frame) });
    send(frame, { type: 'openkey:auth:response', success: true, address: '0xfirst', keyId: 'key-first', keyType, ...phase(frame) });
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

  test('with an external key, signMessage asks the wallet and posts nothing to OpenKey, even with a presentation', async () => {
    const address = '0xfirst';
    const calls: Array<{ method: string; params?: unknown[] }> = [];
    const provider = {
      request: async (args: { method: string; params?: unknown[] }) => {
        calls.push(args);
        if (args.method === 'eth_accounts' || args.method === 'eth_requestAccounts') return [address];
        if (args.method === 'personal_sign') return '0xsignature';
        throw new Error(`unexpected ${args.method}`);
      },
    };
    const h = harness({ externalProvider: provider });
    try {
      await h.connect('EXTERNAL');
      const frameCount = h.frames.length;
      const posted = h.frames.map((frame) => frame.posts.length);

      const result = await h.client.signMessage({ message: 'exact bytes', keyId: 'key-first', presentation: PRESENTATION });

      expect(result).toEqual({ signature: '0xsignature', address });
      const signs = calls.filter((call) => call.method === 'personal_sign');
      expect(signs).toHaveLength(1);
      expect(signs[0]!.params).toEqual([`0x${Buffer.from('exact bytes').toString('hex')}`, address]);
      expect(h.frames).toHaveLength(frameCount);
      expect(h.frames.map((frame) => frame.posts.length)).toEqual(posted);
      expect(JSON.stringify(calls)).not.toContain('Acme');
    } finally { h.restore(); }
  });

  test('signMessageShowsApproval is true for a connected managed key and false otherwise', async () => {
    const h = harness();
    try {
      expect(h.client.signMessageShowsApproval).toBe(false);
      await h.connect('MANAGED');
      expect(h.client.signMessageShowsApproval).toBe(true);
    } finally { h.restore(); }
    const unmarked = harness();
    try {
      // A connect response that names no key type is a managed key.
      await unmarked.connect();
      expect(unmarked.client.signMessageShowsApproval).toBe(true);
    } finally { unmarked.restore(); }
    const external = harness();
    try {
      expect(external.client.signMessageShowsApproval).toBe(false);
      await external.connect('EXTERNAL');
      expect(external.client.signMessageShowsApproval).toBe(false);
    } finally { external.restore(); }
  });
});
