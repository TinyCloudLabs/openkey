// Unit tests for the OpenKeyNostr postMessage client (packages/sdk/src/nostr.ts).
//
// OpenKeyNostr mounts an ephemeral NostrFrame per request, which touches
// `document` and `window`. Bun's test runner has no DOM and the SDK package
// deliberately carries no DOM shim dependency, so this suite installs a
// minimal hand-rolled fake: just enough Element/Document/Window surface for
// NostrFrame's constructor, message listener, postMessage, and destroy().
// The fakes mirror the FakeWindow convention used by
// apps/web/src/lib/widget-transport.test.ts.

// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { describe, expect, test, beforeEach, afterEach } from 'bun:test';
import { OpenKeyNostr } from './nostr';
import type { NostrError, SignedNostrEvent, UnsignedNostrEvent } from './nostr';

const HOST = 'https://openkey.example';
const APP_ORIGIN = 'https://app.example';
const PEER = 'cd'.repeat(32);

// ---------------------------------------------------------------------------
// Minimal DOM fakes
// ---------------------------------------------------------------------------

class FakeStyle {
  props: Record<string, string> = {};
  height = '';
  setProperty(name: string, value: string) {
    this.props[name] = value;
  }
}

class FakeClassList {
  classes = new Set<string>();
  add(name: string) {
    this.classes.add(name);
  }
  remove(name: string) {
    this.classes.delete(name);
  }
}

class FakeContentWindow {
  sent: Array<{ data: any; target: string }> = [];
  postMessage(data: any, targetOrigin: string) {
    this.sent.push({ data, target: targetOrigin });
  }
}

class FakeElement {
  tag: string;
  children: FakeElement[] = [];
  attrs: Record<string, string> = {};
  className = '';
  textContent = '';
  src = '';
  title = '';
  removed = false;
  style = new FakeStyle();
  classList = new FakeClassList();
  contentWindow: FakeContentWindow | null = null;
  constructor(tag: string) {
    this.tag = tag;
  }
  attachShadow(_opts: { mode: string }) {
    return new FakeElement('#shadow-root');
  }
  appendChild(child: FakeElement) {
    this.children.push(child);
    return child;
  }
  setAttribute(name: string, value: string) {
    this.attrs[name] = value;
  }
  remove() {
    this.removed = true;
  }
}

class FakeTopWindow {
  listeners: Array<(event: any) => void> = [];
  location = { origin: APP_ORIGIN };
  innerWidth = 1024;
  innerHeight = 768;
  visualViewport = undefined;
  addEventListener(type: string, cb: (event: any) => void) {
    if (type === 'message') this.listeners.push(cb);
  }
  removeEventListener(type: string, cb: (event: any) => void) {
    if (type !== 'message') return;
    this.listeners = this.listeners.filter((l) => l !== cb);
  }
  dispatch(event: { origin: string; source: unknown; data: any }) {
    for (const l of [...this.listeners]) l(event);
  }
}

function makeDom() {
  const win = new FakeTopWindow();
  const iframes: FakeElement[] = [];
  const doc = {
    body: new FakeElement('body'),
    createElement(tag: string) {
      const el = new FakeElement(tag);
      if (tag === 'iframe') {
        el.contentWindow = new FakeContentWindow();
        iframes.push(el);
      }
      return el;
    },
  };
  (globalThis as any).window = win;
  (globalThis as any).document = doc;
  return { win, iframes };
}

// ---------------------------------------------------------------------------
// Harness helpers
// ---------------------------------------------------------------------------

interface Tracked<T> {
  state: 'pending' | 'resolved' | 'rejected';
  value: T | undefined;
  error: unknown;
  promise: Promise<void>;
}

function trackPromise<T>(p: Promise<T>): Tracked<T> {
  const t: Tracked<T> = {
    state: 'pending',
    value: undefined,
    error: undefined,
    promise: undefined as unknown as Promise<void>,
  };
  t.promise = p.then(
    (v) => {
      t.state = 'resolved';
      t.value = v;
    },
    (e) => {
      t.state = 'rejected';
      t.error = e;
    },
  );
  return t;
}

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

function emitReady(win: FakeTopWindow, iframe: FakeElement, protocolVersion = 1) {
  win.dispatch({
    origin: HOST,
    source: iframe.contentWindow,
    data: { type: 'openkey:ready', protocolVersion },
  });
}

/** Start an encrypt request and complete the ready handshake. */
function startEncrypt(win: FakeTopWindow, iframes: FakeElement[], plaintext = 'hello') {
  const nostr = new OpenKeyNostr(HOST);
  const tracked = trackPromise(nostr.nip44Encrypt('key-1', { peerPubkey: PEER, plaintext }));
  const iframe = iframes[iframes.length - 1]!;
  emitReady(win, iframe);
  const posted = iframe.contentWindow!.sent[0]!;
  return { tracked, iframe, requestId: posted.data.requestId as string, posted };
}

const SIGNED_EVENT: SignedNostrEvent = {
  id: '1'.repeat(64),
  pubkey: 'a'.repeat(64),
  created_at: 1754000000,
  kind: 22242,
  tags: [['relay', 'wss://relay.example']],
  content: '',
  sig: 'b'.repeat(128),
};

describe('OpenKeyNostr', () => {
  let originalWindow: any;
  let originalDocument: any;

  beforeEach(() => {
    originalWindow = (globalThis as any).window;
    originalDocument = (globalThis as any).document;
  });
  afterEach(() => {
    (globalThis as any).window = originalWindow;
    (globalThis as any).document = originalDocument;
  });

  test('connect() posts the request with kinds/operations/relayUrl after openkey:ready and resolves the identity', async () => {
    const { win, iframes } = makeDom();
    const nostr = new OpenKeyNostr(HOST);
    const tracked = trackPromise(
      nostr.connect({
        relayUrl: 'wss://relay.example',
        kinds: [1, 14, 22242],
        operations: ['nip44_encrypt', 'nip59_wrap'],
      }),
    );
    const iframe = iframes[0]!;
    // The widget URL carries the caller origin, never a wildcard.
    expect(iframe.src).toBe(`${HOST}/widget/embed/nostr/approve?origin=${encodeURIComponent(APP_ORIGIN)}`);
    // Nothing is posted before the ready handshake.
    expect(iframe.contentWindow!.sent).toHaveLength(0);

    emitReady(win, iframe);
    expect(iframe.contentWindow!.sent).toHaveLength(1);
    const { data, target } = iframe.contentWindow!.sent[0]!;
    expect(target).toBe(HOST);
    expect(data.type).toBe('openkey:nostr:connect:request');
    expect(data.protocolVersion).toBe(1);
    expect(typeof data.requestId).toBe('string');
    expect(data.requestId.length).toBeGreaterThan(0);
    expect(data.relayUrl).toBe('wss://relay.example');
    expect(data.kinds).toEqual([1, 14, 22242]);
    expect(data.operations).toEqual(['nip44_encrypt', 'nip59_wrap']);

    win.dispatch({
      origin: HOST,
      source: iframe.contentWindow,
      data: {
        type: 'openkey:nostr:connect:response',
        requestId: data.requestId,
        protocolVersion: 1,
        success: true,
        keyId: 'key-1',
        pubkey: 'a'.repeat(64),
        npub: 'npub1example',
      },
    });
    await tracked.promise;
    expect(tracked.state).toBe('resolved');
    expect(tracked.value).toEqual({ keyId: 'key-1', pubkey: 'a'.repeat(64), npub: 'npub1example' });
  });

  test('signEvent() forwards the exact event object and the relayUrl hint, and resolves the signed event', async () => {
    const { win, iframes } = makeDom();
    const nostr = new OpenKeyNostr(HOST);
    const event: UnsignedNostrEvent = {
      pubkey: 'a'.repeat(64),
      created_at: 1754000000,
      kind: 22242,
      tags: [['relay', 'wss://relay.example']],
      content: '',
    };
    const tracked = trackPromise(nostr.signEvent('key-1', event, { relayUrl: 'wss://relay.example' }));
    const iframe = iframes[0]!;
    emitReady(win, iframe);
    const { data } = iframe.contentWindow!.sent[0]!;
    expect(data.type).toBe('openkey:nostr:sign:request');
    expect(data.keyId).toBe('key-1');
    // The exact object, not a lossy copy.
    expect(data.event).toBe(event);
    expect(data.relayUrl).toBe('wss://relay.example');
    expect(data.protocolVersion).toBe(1);

    win.dispatch({
      origin: HOST,
      source: iframe.contentWindow,
      data: {
        type: 'openkey:nostr:sign:response',
        requestId: data.requestId,
        protocolVersion: 1,
        success: true,
        event: SIGNED_EVENT,
      },
    });
    await tracked.promise;
    expect(tracked.state).toBe('resolved');
    expect(tracked.value).toEqual(SIGNED_EVENT);
  });

  test('nip44Encrypt posts an encrypt request and resolves the ciphertext', async () => {
    const { win, iframes } = makeDom();
    const { tracked, iframe, requestId, posted } = startEncrypt(win, iframes, 'remember the milk');
    expect(posted.data.type).toBe('openkey:nostr:encrypt:request');
    expect(posted.data.keyId).toBe('key-1');
    expect(posted.data.peerPubkey).toBe(PEER);
    expect(posted.data.plaintext).toBe('remember the milk');
    expect(posted.data.protocolVersion).toBe(1);
    expect(posted.target).toBe(HOST);

    win.dispatch({
      origin: HOST,
      source: iframe.contentWindow,
      data: {
        type: 'openkey:nostr:encrypt:response',
        requestId,
        protocolVersion: 1,
        success: true,
        ciphertext: 'AqCiphertext==',
      },
    });
    await tracked.promise;
    expect(tracked.state).toBe('resolved');
    expect(tracked.value).toBe('AqCiphertext==');
  });

  test('nip44Decrypt posts a decrypt request and resolves the plaintext', async () => {
    const { win, iframes } = makeDom();
    const nostr = new OpenKeyNostr(HOST);
    const tracked = trackPromise(nostr.nip44Decrypt('key-1', { peerPubkey: PEER, payload: 'AqZz==' }));
    const iframe = iframes[0]!;
    emitReady(win, iframe);
    const { data } = iframe.contentWindow!.sent[0]!;
    expect(data.type).toBe('openkey:nostr:decrypt:request');
    expect(data.keyId).toBe('key-1');
    expect(data.peerPubkey).toBe(PEER);
    expect(data.payload).toBe('AqZz==');

    win.dispatch({
      origin: HOST,
      source: iframe.contentWindow,
      data: {
        type: 'openkey:nostr:decrypt:response',
        requestId: data.requestId,
        protocolVersion: 1,
        success: true,
        plaintext: 'remember the milk',
      },
    });
    await tracked.promise;
    expect(tracked.state).toBe('resolved');
    expect(tracked.value).toBe('remember the milk');
  });

  test('nip59Wrap posts content/recipients/createdAt and resolves the wraps', async () => {
    const { win, iframes } = makeDom();
    const nostr = new OpenKeyNostr(HOST);
    const recipients = ['ef'.repeat(32)];
    const tracked = trackPromise(
      nostr.nip59Wrap('key-1', { content: 'hi there', recipients, createdAt: 1754000000 }),
    );
    const iframe = iframes[0]!;
    emitReady(win, iframe);
    const { data } = iframe.contentWindow!.sent[0]!;
    expect(data.type).toBe('openkey:nostr:wrap:request');
    expect(data.keyId).toBe('key-1');
    expect(data.content).toBe('hi there');
    expect(data.recipients).toBe(recipients);
    expect(data.createdAt).toBe(1754000000);

    const wraps = [SIGNED_EVENT, { ...SIGNED_EVENT, id: '2'.repeat(64) }];
    win.dispatch({
      origin: HOST,
      source: iframe.contentWindow,
      data: {
        type: 'openkey:nostr:wrap:response',
        requestId: data.requestId,
        protocolVersion: 1,
        success: true,
        wraps,
      },
    });
    await tracked.promise;
    expect(tracked.state).toBe('resolved');
    expect(tracked.value).toEqual(wraps);
  });

  test('nip59Unwrap posts the wrap and resolves the rumor', async () => {
    const { win, iframes } = makeDom();
    const nostr = new OpenKeyNostr(HOST);
    const wrap: SignedNostrEvent = { ...SIGNED_EVENT, kind: 1059 };
    const tracked = trackPromise(nostr.nip59Unwrap('key-1', wrap));
    const iframe = iframes[0]!;
    emitReady(win, iframe);
    const { data } = iframe.contentWindow!.sent[0]!;
    expect(data.type).toBe('openkey:nostr:unwrap:request');
    expect(data.keyId).toBe('key-1');
    expect(data.wrap).toBe(wrap);

    const rumor = {
      id: '3'.repeat(64),
      pubkey: 'f'.repeat(64),
      created_at: 1754000002,
      kind: 14,
      tags: [],
      content: 'the rumor',
    };
    win.dispatch({
      origin: HOST,
      source: iframe.contentWindow,
      data: {
        type: 'openkey:nostr:unwrap:response',
        requestId: data.requestId,
        protocolVersion: 1,
        success: true,
        rumor,
      },
    });
    await tracked.promise;
    expect(tracked.state).toBe('resolved');
    expect(tracked.value).toEqual(rumor);
  });

  test('each request gets a fresh requestId', async () => {
    const { win, iframes } = makeDom();
    const first = startEncrypt(win, iframes);
    // Settle the first request so its frame tears down cleanly.
    win.dispatch({
      origin: HOST,
      source: first.iframe.contentWindow,
      data: {
        type: 'openkey:nostr:encrypt:response',
        requestId: first.requestId,
        protocolVersion: 1,
        success: true,
        ciphertext: 'ct-1',
      },
    });
    await first.tracked.promise;
    const second = startEncrypt(win, iframes);
    expect(second.requestId).not.toBe(first.requestId);
    win.dispatch({
      origin: HOST,
      source: second.iframe.contentWindow,
      data: {
        type: 'openkey:nostr:encrypt:response',
        requestId: second.requestId,
        protocolVersion: 1,
        success: true,
        ciphertext: 'ct-2',
      },
    });
    await second.tracked.promise;
  });

  test('ignores an openkey:ready with the wrong protocolVersion (no request is posted)', async () => {
    const { win, iframes } = makeDom();
    const nostr = new OpenKeyNostr(HOST);
    const tracked = trackPromise(nostr.nip44Encrypt('key-1', { peerPubkey: PEER, plaintext: 'x' }));
    const iframe = iframes[0]!;
    emitReady(win, iframe, 99);
    expect(iframe.contentWindow!.sent).toHaveLength(0);
    // A correct ready afterwards still completes the handshake.
    emitReady(win, iframe);
    expect(iframe.contentWindow!.sent).toHaveLength(1);
    const requestId = iframe.contentWindow!.sent[0]!.data.requestId;
    win.dispatch({
      origin: HOST,
      source: iframe.contentWindow,
      data: { type: 'openkey:nostr:encrypt:response', requestId, protocolVersion: 1, success: true, ciphertext: 'ct' },
    });
    await tracked.promise;
    expect(tracked.state).toBe('resolved');
  });

  test('ignores a response from the wrong origin (request stays pending)', async () => {
    const { win, iframes } = makeDom();
    const { tracked, iframe, requestId } = startEncrypt(win, iframes);
    win.dispatch({
      origin: 'https://evil.example',
      source: iframe.contentWindow,
      data: {
        type: 'openkey:nostr:encrypt:response',
        requestId,
        protocolVersion: 1,
        success: true,
        ciphertext: 'forged',
      },
    });
    await flush();
    expect(tracked.state).toBe('pending');
    // The genuine response still lands.
    win.dispatch({
      origin: HOST,
      source: iframe.contentWindow,
      data: { type: 'openkey:nostr:encrypt:response', requestId, protocolVersion: 1, success: true, ciphertext: 'real' },
    });
    await tracked.promise;
    expect(tracked.state).toBe('resolved');
    expect(tracked.value).toBe('real');
  });

  test('ignores a response from the right origin but wrong event.source', async () => {
    const { win, iframes } = makeDom();
    const { tracked, iframe, requestId } = startEncrypt(win, iframes);
    const impostorWindow = new FakeContentWindow();
    win.dispatch({
      origin: HOST,
      source: impostorWindow,
      data: {
        type: 'openkey:nostr:encrypt:response',
        requestId,
        protocolVersion: 1,
        success: true,
        ciphertext: 'forged',
      },
    });
    await flush();
    expect(tracked.state).toBe('pending');
    win.dispatch({
      origin: HOST,
      source: iframe.contentWindow,
      data: { type: 'openkey:nostr:encrypt:response', requestId, protocolVersion: 1, success: true, ciphertext: 'real' },
    });
    await tracked.promise;
    expect(tracked.state).toBe('resolved');
    expect(tracked.value).toBe('real');
  });

  test('ignores a response with a mismatched requestId', async () => {
    const { win, iframes } = makeDom();
    const { tracked, iframe, requestId } = startEncrypt(win, iframes);
    win.dispatch({
      origin: HOST,
      source: iframe.contentWindow,
      data: {
        type: 'openkey:nostr:encrypt:response',
        requestId: 'someone-elses-request',
        protocolVersion: 1,
        success: true,
        ciphertext: 'forged',
      },
    });
    await flush();
    expect(tracked.state).toBe('pending');
    win.dispatch({
      origin: HOST,
      source: iframe.contentWindow,
      data: { type: 'openkey:nostr:encrypt:response', requestId, protocolVersion: 1, success: true, ciphertext: 'real' },
    });
    await tracked.promise;
    expect(tracked.value).toBe('real');
  });

  test('ignores a response with the wrong protocolVersion', async () => {
    const { win, iframes } = makeDom();
    const { tracked, iframe, requestId } = startEncrypt(win, iframes);
    win.dispatch({
      origin: HOST,
      source: iframe.contentWindow,
      data: {
        type: 'openkey:nostr:encrypt:response',
        requestId,
        protocolVersion: 2,
        success: true,
        ciphertext: 'forged',
      },
    });
    await flush();
    expect(tracked.state).toBe('pending');
    win.dispatch({
      origin: HOST,
      source: iframe.contentWindow,
      data: { type: 'openkey:nostr:encrypt:response', requestId, protocolVersion: 1, success: true, ciphertext: 'real' },
    });
    await tracked.promise;
    expect(tracked.value).toBe('real');
  });

  test('a success:false response rejects with the widget-provided {code, message}', async () => {
    const { win, iframes } = makeDom();
    const { tracked, iframe, requestId } = startEncrypt(win, iframes);
    win.dispatch({
      origin: HOST,
      source: iframe.contentWindow,
      data: {
        type: 'openkey:nostr:encrypt:response',
        requestId,
        protocolVersion: 1,
        success: false,
        error: { code: 'UNAUTHORIZED', message: 'No grant covers nip44_encrypt' },
      },
    });
    await tracked.promise;
    expect(tracked.state).toBe('rejected');
    expect(tracked.error as NostrError).toEqual({
      code: 'UNAUTHORIZED',
      message: 'No grant covers nip44_encrypt',
    });
  });

  test('openkey:close rejects with USER_CANCELLED', async () => {
    const { win, iframes } = makeDom();
    const nostr = new OpenKeyNostr(HOST);
    const tracked = trackPromise(nostr.nip59Wrap('key-1', { content: 'hi', recipients: [PEER] }));
    const iframe = iframes[0]!;
    emitReady(win, iframe);
    const requestId = iframe.contentWindow!.sent[0]!.data.requestId;
    win.dispatch({
      origin: HOST,
      source: iframe.contentWindow,
      data: { type: 'openkey:close', requestId, protocolVersion: 1 },
    });
    await tracked.promise;
    expect(tracked.state).toBe('rejected');
    expect((tracked.error as NostrError).code).toBe('USER_CANCELLED');
  });

  test('the frame is torn down after settlement (listener removed, root removed)', async () => {
    const { win, iframes } = makeDom();
    const { tracked, iframe, requestId } = startEncrypt(win, iframes);
    win.dispatch({
      origin: HOST,
      source: iframe.contentWindow,
      data: { type: 'openkey:nostr:encrypt:response', requestId, protocolVersion: 1, success: true, ciphertext: 'ct' },
    });
    await tracked.promise;
    expect(win.listeners).toHaveLength(0);
    // NostrFrame's root container was removed from the document.
    const root = (globalThis as any).document.body.children[0] as FakeElement;
    expect(root.removed).toBe(true);
  });
});
