// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, it, beforeEach, afterEach } from 'bun:test';
import { createVersionedIframeTransport, createWidgetTransport } from './widget-transport';

// Minimal DOM-ish shim for the transport in a Node test environment.
// We simulate window, window.opener, window.postMessage, and MessageEvent.

class FakeWindow {
  listeners: Array<(event: MessageEvent) => void> = [];
  sent: Array<{ target: string; data: any }> = [];
  opener: FakeWindow | null = null;
  parent: FakeWindow = this;
  constructor() {}
  addEventListener(type: string, cb: (event: MessageEvent) => void) {
    if (type === 'message') this.listeners.push(cb);
  }
  removeEventListener(type: string, cb: (event: MessageEvent) => void) {
    if (type !== 'message') return;
    this.listeners = this.listeners.filter((l) => l !== cb);
  }
  postMessage(data: any, targetOrigin: string) {
    this.sent.push({ target: targetOrigin, data });
  }
  dispatch(event: Partial<MessageEvent> & { origin: string; source?: unknown }) {
    for (const l of this.listeners) l(event as MessageEvent);
  }
}

let originalWindow: any;

function makeWindows() {
  const parent = new FakeWindow();
  const child = new FakeWindow();
  child.opener = parent;
  child.parent = parent;
  (globalThis as any).window = child;
  return { parent, child };
}

describe('widget-transport', () => {
  beforeEach(() => {
    originalWindow = (globalThis as any).window;
  });
  afterEach(() => {
    (globalThis as any).window = originalWindow;
  });

  it('rejects origin "*"', () => {
    makeWindows();
    expect(() =>
      createWidgetTransport({
        origin: '*',
        container: 'popup',
        onRequest: () => {},
        onClose: () => {},
      }),
    ).toThrow();
  });

  it('drops messages from wrong origin', () => {
    const { parent, child } = makeWindows();
    let received = 0;
    let invalidReasons: string[] = [];
    createWidgetTransport({
      origin: 'https://caller.example',
      container: 'popup',
      onRequest: () => (received += 1),
      onClose: () => {},
      onInvalid: (reason) => invalidReasons.push(reason),
    });
    child.dispatch({
      origin: 'https://evil.example',
      source: parent as unknown as MessageEventSource,
      data: {
        type: 'openkey:sign:request',
        requestId: 'r1',
        protocolVersion: 1,
        payload: {},
      },
    });
    expect(received).toBe(0);
    expect(invalidReasons).toContain('wrong-origin');
  });

  it('drops messages from wrong source', () => {
    const { child } = makeWindows();
    const impostor = new FakeWindow();
    let received = 0;
    const invalids: string[] = [];
    createWidgetTransport({
      origin: 'https://caller.example',
      container: 'popup',
      onRequest: () => (received += 1),
      onClose: () => {},
      onInvalid: (reason) => invalids.push(reason),
    });
    child.dispatch({
      origin: 'https://caller.example',
      source: impostor as unknown as MessageEventSource,
      data: {
        type: 'openkey:sign:request',
        requestId: 'r1',
        protocolVersion: 1,
        payload: {},
      },
    });
    expect(received).toBe(0);
    expect(invalids).toContain('wrong-source');
  });

  it('drops messages missing requestId', () => {
    const { parent, child } = makeWindows();
    const invalids: string[] = [];
    createWidgetTransport({
      origin: 'https://caller.example',
      container: 'popup',
      onRequest: () => {},
      onClose: () => {},
      onInvalid: (reason) => invalids.push(reason),
    });
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: { type: 'openkey:sign:request', protocolVersion: 1, payload: {} },
    });
    expect(invalids).toContain('missing-request-id');
  });

  it('drops messages with wrong protocol version', () => {
    const { parent, child } = makeWindows();
    const invalids: string[] = [];
    createWidgetTransport({
      origin: 'https://caller.example',
      container: 'popup',
      onRequest: () => {},
      onClose: () => {},
      onInvalid: (reason) => invalids.push(reason),
    });
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: {
        type: 'openkey:sign:request',
        requestId: 'r1',
        protocolVersion: 99,
        payload: {},
      },
    });
    expect(invalids).toContain('wrong-protocol-version');
  });

  it('accepts a well-formed message and echoes correlation', () => {
    const { parent, child } = makeWindows();
    const seen: unknown[] = [];
    const transport = createWidgetTransport({
      origin: 'https://caller.example',
      container: 'popup',
      onRequest: (req) => seen.push(req),
      onClose: () => {},
    });
    transport.emitReady();
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: {
        type: 'openkey:sign:request',
        requestId: 'r1',
        protocolVersion: 1,
        // Sol MAJOR-8: the payload validator requires `message` to be
        // a non-empty string. Older tests used `payload: { foo: 'bar' }`
        // (no `message`) — that shape now correctly fails validation.
        message: 'some SIWE bytes',
      },
    });
    expect(seen).toHaveLength(1);
    expect((seen[0] as any).requestId).toBe('r1');
    // Ready message and any response go to the parent, never '*'.
    expect(parent.sent.every((s) => s.target === 'https://caller.example')).toBe(true);
  });

  // Sol MAJOR-8: payload validation tests. Each dropped field surfaces
  // via onInvalid('invalid-payload') and the handler is never called.
  it('drops messages missing a `message` field', () => {
    const { parent, child } = makeWindows();
    const seen: unknown[] = [];
    const invalid: string[] = [];
    createWidgetTransport({
      origin: 'https://caller.example',
      container: 'popup',
      onRequest: (req) => seen.push(req),
      onClose: () => {},
      onInvalid: (r) => invalid.push(r),
    });
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: {
        type: 'openkey:sign:request',
        requestId: 'r-missing-message',
        protocolVersion: 1,
      },
    });
    expect(seen).toHaveLength(0);
    expect(invalid).toContain('invalid-payload');
  });

  it('drops messages with malformed jwk (non-object)', () => {
    const { parent, child } = makeWindows();
    const seen: unknown[] = [];
    const invalid: string[] = [];
    createWidgetTransport({
      origin: 'https://caller.example',
      container: 'popup',
      onRequest: (req) => seen.push(req),
      onClose: () => {},
      onInvalid: (r) => invalid.push(r),
    });
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: {
        type: 'openkey:sign:request',
        requestId: 'r-bad-jwk',
        protocolVersion: 1,
        message: 'a message',
        jwk: 'not-an-object',
      },
    });
    expect(seen).toHaveLength(0);
    expect(invalid).toContain('invalid-payload');
  });

  it('drops messages with an empty keyId', () => {
    const { parent, child } = makeWindows();
    const seen: unknown[] = [];
    const invalid: string[] = [];
    createWidgetTransport({
      origin: 'https://caller.example',
      container: 'popup',
      onRequest: (req) => seen.push(req),
      onClose: () => {},
      onInvalid: (r) => invalid.push(r),
    });
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: {
        type: 'openkey:sign:request',
        requestId: 'r-empty-keyid',
        protocolVersion: 1,
        message: 'a message',
        keyId: '',
      },
    });
    expect(seen).toHaveLength(0);
    expect(invalid).toContain('invalid-payload');
  });

  it('drops close messages that carry a wrong protocolVersion', () => {
    const { parent, child } = makeWindows();
    let closed = 0;
    const invalid: string[] = [];
    createWidgetTransport({
      origin: 'https://caller.example',
      container: 'popup',
      onRequest: () => {},
      onClose: () => (closed += 1),
      onInvalid: (r) => invalid.push(r),
    });
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: { type: 'openkey:close', protocolVersion: 99 },
    });
    expect(closed).toBe(0);
    expect(invalid).toContain('invalid-close');
  });

  it('surfaces the full incoming envelope as request.data (Sol continuation contract)', () => {
    // Sol continuation contract: the transport captures the whole message
    // envelope so the widget can read application-specific fields (message,
    // keyId, jwk, sessionToken) directly. This is the wire format the
    // SDK sends today; changing it silently would break sign requests.
    const { parent, child } = makeWindows();
    const seen: any[] = [];
    createWidgetTransport({
      origin: 'https://caller.example',
      container: 'popup',
      onRequest: (req) => seen.push(req),
      onClose: () => {},
    });
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: {
        type: 'openkey:sign:request',
        requestId: 'r1',
        protocolVersion: 1,
        message: 'some SIWE',
        keyId: 'k1',
        jwk: { kty: 'OKP' },
      },
    });
    expect(seen).toHaveLength(1);
    expect(seen[0].data.message).toBe('some SIWE');
    expect(seen[0].data.keyId).toBe('k1');
    expect(seen[0].data.jwk).toEqual({ kty: 'OKP' });
  });

  it('respond flattens data fields into the message envelope', () => {
    const { parent } = makeWindows();
    const transport = createWidgetTransport({
      origin: 'https://caller.example',
      container: 'popup',
      onRequest: () => {},
      onClose: () => {},
    });
    transport.respond({
      type: 'openkey:sign:response',
      requestId: 'r1',
      protocolVersion: 1,
      success: true,
      data: {
        signature: '0xdeadbeef',
        address: '0x1111111111111111111111111111111111111111',
      },
    });
    const last = parent.sent[parent.sent.length - 1];
    expect(last?.target).toBe('https://caller.example');
    expect(last?.data.type).toBe('openkey:sign:response');
    expect(last?.data.requestId).toBe('r1');
    expect(last?.data.success).toBe(true);
    // Application fields at the top level so existing SDK listeners work.
    expect(last?.data.signature).toBe('0xdeadbeef');
    expect(last?.data.address).toBe('0x1111111111111111111111111111111111111111');
  });

  it('respond emits a well-formed failure envelope', () => {
    const { parent } = makeWindows();
    const transport = createWidgetTransport({
      origin: 'https://caller.example',
      container: 'popup',
      onRequest: () => {},
      onClose: () => {},
    });
    transport.respond({
      type: 'openkey:sign:response',
      requestId: 'r1',
      protocolVersion: 1,
      success: false,
      error: { code: 'USER_CANCELLED', message: 'Cancelled' },
    });
    const last = parent.sent[parent.sent.length - 1];
    expect(last?.data.success).toBe(false);
    expect(last?.data.error).toEqual({ code: 'USER_CANCELLED', message: 'Cancelled' });
  });

  it('resize goes to origin, never * (and carries requestId + protocolVersion per Sol continuation req 5)', () => {
    const { parent, child } = makeWindows();
    const transport = createWidgetTransport({
      origin: 'https://caller.example',
      container: 'popup',
      onRequest: () => {},
      onClose: () => {},
    });
    // Sol final continuation contract requirement 5: `emitResize` drops
    // when no active sign request exists. Dispatch a sign request first
    // so the transport has an authoritative (requestId, protocolVersion)
    // pair to bind the resize to.
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: {
        type: 'openkey:sign:request',
        requestId: 'r-resize',
        protocolVersion: 1,
        message: 'msg',
      },
    });
    parent.sent = [];
    transport.emitResize(200);
    expect(parent.sent).toContainEqual({
      target: 'https://caller.example',
      data: {
        type: 'openkey:resize',
        height: 200,
        protocolVersion: 1,
        requestId: 'r-resize',
      },
    });
  });

  // Sol MAJOR-4 (continuation): close messages MUST correlate to the
  // active request. A same-origin stale close carrying no requestId must
  // NOT tear down a live signing flow.
  it('rejects close messages with a mismatched requestId while a request is active', () => {
    const { parent, child } = makeWindows();
    let closed = 0;
    let requested = 0;
    const invalids: string[] = [];
    createWidgetTransport({
      origin: 'https://caller.example',
      container: 'popup',
      onRequest: () => (requested += 1),
      onClose: () => (closed += 1),
      onInvalid: (reason) => invalids.push(reason),
    });
    // Deliver a valid request.
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: {
        type: 'openkey:sign:request',
        requestId: 'active-1',
        protocolVersion: 1,
        message: 'hi',
      },
    });
    expect(requested).toBe(1);
    // A close carrying a DIFFERENT requestId is dropped.
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: { type: 'openkey:close', requestId: 'stale-999', protocolVersion: 1 },
    });
    expect(closed).toBe(0);
    expect(invalids).toContain('invalid-close');
  });

  it('accepts a correlated close for the active request', () => {
    const { parent, child } = makeWindows();
    let closed = 0;
    createWidgetTransport({
      origin: 'https://caller.example',
      container: 'popup',
      onRequest: () => {},
      onClose: () => (closed += 1),
    });
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: {
        type: 'openkey:sign:request',
        requestId: 'active-2',
        protocolVersion: 1,
        message: 'hi',
      },
    });
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: { type: 'openkey:close', requestId: 'active-2', protocolVersion: 1 },
    });
    expect(closed).toBe(1);
  });

  it('rejects close messages that omit protocolVersion while a versioned request is active', () => {
    const { parent, child } = makeWindows();
    let closed = 0;
    const invalids: string[] = [];
    createWidgetTransport({
      origin: 'https://caller.example',
      container: 'popup',
      onRequest: () => {},
      onClose: () => (closed += 1),
      onInvalid: (reason) => invalids.push(reason),
    });
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: {
        type: 'openkey:sign:request',
        requestId: 'active-3',
        protocolVersion: 1,
        message: 'hi',
      },
    });
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: { type: 'openkey:close' },
    });
    expect(closed).toBe(0);
    expect(invalids).toContain('invalid-close');
  });

  // Sol final continuation contract requirement 5: iframe resize traffic
  // MUST include and exactly match the active requestId + protocolVersion.
  // The transport's `emitResize` is the widget-side emitter; the parent
  // SDK's IframeModal is the consumer. These tests exercise the emitter.
  describe('emitResize correlation (Sol continuation req 5)', () => {
    it('drops emitResize when NO sign request is in flight', () => {
      const { parent } = makeWindows();
      const transport = createWidgetTransport({
        origin: 'https://caller.example',
        container: 'popup',
        onRequest: () => {},
        onClose: () => {},
      });
      // Sanity: ready is emitted with parent already receiving.
      transport.emitReady();
      parent.sent = [];
      // No sign request has landed yet — active-request tracking is null.
      transport.emitResize(500);
      const resizes = parent.sent.filter((m) => m.data?.type === 'openkey:resize');
      expect(resizes.length).toBe(0);
    });

    it('emits a resize carrying the active requestId AND protocolVersion after a sign request', () => {
      const { parent, child } = makeWindows();
      const transport = createWidgetTransport({
        origin: 'https://caller.example',
        container: 'popup',
        onRequest: () => {},
        onClose: () => {},
      });
      child.dispatch({
        origin: 'https://caller.example',
        source: parent as unknown as MessageEventSource,
        data: {
          type: 'openkey:sign:request',
          requestId: 'req-alpha',
          protocolVersion: 1,
          message: 'hi',
        },
      });
      parent.sent = [];
      transport.emitResize(720);
      const resizes = parent.sent.filter((m) => m.data?.type === 'openkey:resize');
      expect(resizes.length).toBe(1);
      const msg = resizes[0]!.data;
      expect(msg.height).toBe(720);
      expect(msg.protocolVersion).toBe(1);
      expect(msg.requestId).toBe('req-alpha');
      // Sanity: NEVER "*".
      expect(resizes[0]!.target).toBe('https://caller.example');
    });

    it('resize is bound to a SPECIFIC requestId — a stale/wrong requestId cannot be forged from the widget side', () => {
      // The widget-side emitter can only emit the active requestId. This
      // proves that the emitted `requestId` on the resize message ALWAYS
      // matches the last-received sign-request's requestId — the widget
      // cannot emit a resize claiming a different one.
      const { parent, child } = makeWindows();
      const transport = createWidgetTransport({
        origin: 'https://caller.example',
        container: 'popup',
        onRequest: () => {},
        onClose: () => {},
      });
      // First sign request — emit resize; MUST carry req-one.
      child.dispatch({
        origin: 'https://caller.example',
        source: parent as unknown as MessageEventSource,
        data: {
          type: 'openkey:sign:request',
          requestId: 'req-one',
          protocolVersion: 1,
          message: 'msg-one',
        },
      });
      parent.sent = [];
      transport.emitResize(400);
      let resizes = parent.sent.filter((m) => m.data?.type === 'openkey:resize');
      expect(resizes[0]!.data.requestId).toBe('req-one');
      // Respond to close the first request, then a NEW request lands —
      // subsequent resize MUST carry the NEW requestId.
      transport.respond({
        type: 'openkey:sign:response',
        requestId: 'req-one',
        protocolVersion: 1,
        success: true,
        data: {},
      });
      child.dispatch({
        origin: 'https://caller.example',
        source: parent as unknown as MessageEventSource,
        data: {
          type: 'openkey:sign:request',
          requestId: 'req-two',
          protocolVersion: 1,
          message: 'msg-two',
        },
      });
      parent.sent = [];
      transport.emitResize(500);
      resizes = parent.sent.filter((m) => m.data?.type === 'openkey:resize');
      expect(resizes[0]!.data.requestId).toBe('req-two');
    });

    it('after respond() clears the active request, resize is dropped again until a new request lands', () => {
      const { parent, child } = makeWindows();
      const transport = createWidgetTransport({
        origin: 'https://caller.example',
        container: 'popup',
        onRequest: () => {},
        onClose: () => {},
      });
      child.dispatch({
        origin: 'https://caller.example',
        source: parent as unknown as MessageEventSource,
        data: {
          type: 'openkey:sign:request',
          requestId: 'req-final',
          protocolVersion: 1,
          message: 'msg',
        },
      });
      transport.respond({
        type: 'openkey:sign:response',
        requestId: 'req-final',
        protocolVersion: 1,
        success: true,
        data: {},
      });
      parent.sent = [];
      transport.emitResize(999);
      const resizes = parent.sent.filter((m) => m.data?.type === 'openkey:resize');
      expect(resizes.length).toBe(0);
    });
  });

  it('refuses a second overlapping sign request while one is in flight', () => {
    const { parent, child } = makeWindows();
    let requested = 0;
    const invalids: string[] = [];
    createWidgetTransport({
      origin: 'https://caller.example',
      container: 'popup',
      onRequest: () => (requested += 1),
      onClose: () => {},
      onInvalid: (reason) => invalids.push(reason),
    });
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: {
        type: 'openkey:sign:request',
        requestId: 'r-a',
        protocolVersion: 1,
        message: 'hi',
      },
    });
    // Second (overlapping) request with a different requestId — refused.
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: {
        type: 'openkey:sign:request',
        requestId: 'r-b',
        protocolVersion: 1,
        message: 'hi again',
      },
    });
    expect(requested).toBe(1);
    expect(invalids).toContain('invalid-payload');
  });
});

describe('versioned iframe transport', () => {
  beforeEach(() => {
    originalWindow = (globalThis as any).window;
  });
  afterEach(() => {
    (globalThis as any).window = originalWindow;
  });

  it('binds Nostr request, response, and resize messages to one requestId', () => {
    const { parent, child } = makeWindows();
    const seen: unknown[] = [];
    const transport = createVersionedIframeTransport({
      origin: 'https://caller.example',
      requestTypes: ['openkey:nostr:sign:request'],
      onRequest: request => seen.push(request),
      onClose: () => {},
      validateRequest: request => typeof request.data.keyId === 'string',
    });
    transport.emitReady();
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: {
        type: 'openkey:nostr:sign:request',
        requestId: 'nostr-1',
        protocolVersion: 1,
        keyId: 'key-1',
      },
    });
    transport.emit('openkey:nostr:show');
    transport.emitResize(240);
    transport.respond('openkey:nostr:sign:response', 'nostr-1', true, { event: {} });

    expect(seen).toHaveLength(1);
    expect(parent.sent.map(entry => entry.data.requestId).filter(Boolean)).toEqual([
      'nostr-1',
      'nostr-1',
      'nostr-1',
    ]);
    expect(parent.sent.every(entry => entry.target === 'https://caller.example')).toBe(true);
  });

  it('drops a stale close and a concurrent request', () => {
    const { parent, child } = makeWindows();
    const invalid: string[] = [];
    let closed = 0;
    createVersionedIframeTransport({
      origin: 'https://caller.example',
      requestTypes: ['openkey:nostr:connect:request'],
      onRequest: () => {},
      onClose: () => (closed += 1),
      onInvalid: reason => invalid.push(reason),
    });
    for (const data of [
      { type: 'openkey:nostr:connect:request', requestId: 'active', protocolVersion: 1 },
      { type: 'openkey:nostr:connect:request', requestId: 'other', protocolVersion: 1 },
      { type: 'openkey:close', requestId: 'stale', protocolVersion: 1 },
    ]) {
      child.dispatch({
        origin: 'https://caller.example',
        source: parent as unknown as MessageEventSource,
        data,
      });
    }
    expect(closed).toBe(0);
    expect(invalid).toEqual(['invalid-payload', 'invalid-close']);
  });

  // Full Nostr custody request surface (TC-421 growth): six request types,
  // all on protocolVersion 1. The transport itself stays payload-dumb; these
  // tests pin the envelope rules for every new type.
  const NOSTR_REQUEST_TYPES = [
    'openkey:nostr:connect:request',
    'openkey:nostr:sign:request',
    'openkey:nostr:encrypt:request',
    'openkey:nostr:decrypt:request',
    'openkey:nostr:wrap:request',
    'openkey:nostr:unwrap:request',
  ] as const;

  const PEER = 'cd'.repeat(32);
  const SAMPLE_FIELDS: Record<string, Record<string, unknown>> = {
    'openkey:nostr:connect:request': {
      kinds: [1, 14, 22242],
      operations: ['nip44_encrypt', 'nip59_wrap'],
      relayUrl: 'wss://relay.example',
    },
    'openkey:nostr:sign:request': {
      keyId: 'key-1',
      event: { pubkey: 'ab'.repeat(32), created_at: 1754000000, kind: 22242, tags: [], content: '' },
      relayUrl: 'wss://relay.example',
    },
    'openkey:nostr:encrypt:request': { keyId: 'key-1', peerPubkey: PEER, plaintext: 'remember the milk' },
    'openkey:nostr:decrypt:request': { keyId: 'key-1', peerPubkey: PEER, payload: 'AqZzb2R1bQ==' },
    'openkey:nostr:wrap:request': {
      keyId: 'key-1',
      content: 'hi there',
      recipients: ['ef'.repeat(32)],
      createdAt: 1754000000,
    },
    'openkey:nostr:unwrap:request': {
      keyId: 'key-1',
      wrap: {
        id: '1'.repeat(64),
        pubkey: 'a'.repeat(64),
        created_at: 1754000000,
        kind: 1059,
        tags: [['p', 'b'.repeat(64)]],
        content: 'sealed',
        sig: 'c'.repeat(128),
      },
    },
  };

  const RESPONSE_CASES: Array<{
    requestType: string;
    responseType: string;
    payload: Record<string, unknown>;
  }> = [
    {
      requestType: 'openkey:nostr:encrypt:request',
      responseType: 'openkey:nostr:encrypt:response',
      payload: { ciphertext: 'AqCiphertext==' },
    },
    {
      requestType: 'openkey:nostr:decrypt:request',
      responseType: 'openkey:nostr:decrypt:response',
      payload: { plaintext: 'remember the milk' },
    },
    {
      requestType: 'openkey:nostr:wrap:request',
      responseType: 'openkey:nostr:wrap:response',
      payload: {
        wraps: [
          {
            id: '2'.repeat(64),
            pubkey: 'd'.repeat(64),
            created_at: 1754000001,
            kind: 1059,
            tags: [],
            content: 'wrapped',
            sig: 'e'.repeat(128),
          },
        ],
      },
    },
    {
      requestType: 'openkey:nostr:unwrap:request',
      responseType: 'openkey:nostr:unwrap:response',
      payload: {
        rumor: {
          id: '3'.repeat(64),
          pubkey: 'f'.repeat(64),
          created_at: 1754000002,
          kind: 14,
          tags: [],
          content: 'the rumor',
        },
      },
    },
  ];

  function makeNostrTransport(overrides: {
    onRequest?: (request: unknown) => void;
    onClose?: () => void;
    onInvalid?: (reason: string) => void;
  } = {}) {
    return createVersionedIframeTransport({
      origin: 'https://caller.example',
      requestTypes: NOSTR_REQUEST_TYPES,
      onRequest: overrides.onRequest ?? (() => {}),
      onClose: overrides.onClose ?? (() => {}),
      onInvalid: overrides.onInvalid ? reason => overrides.onInvalid!(reason) : undefined,
    });
  }

  it('delivers each of the six Nostr request types to onRequest with correct requestId/protocolVersion', () => {
    for (const type of NOSTR_REQUEST_TYPES) {
      const { parent, child } = makeWindows();
      const seen: any[] = [];
      makeNostrTransport({ onRequest: request => seen.push(request) });
      const requestId = `rid-${type}`;
      child.dispatch({
        origin: 'https://caller.example',
        source: parent as unknown as MessageEventSource,
        data: { type, requestId, protocolVersion: 1, ...SAMPLE_FIELDS[type] },
      });
      expect(seen).toHaveLength(1);
      expect(seen[0].type).toBe(type);
      expect(seen[0].requestId).toBe(requestId);
      expect(seen[0].protocolVersion).toBe(1);
      // The full envelope is surfaced so the approve page can validate
      // application fields (keyId, peerPubkey, kinds, wrap, ...).
      for (const [field, value] of Object.entries(SAMPLE_FIELDS[type]!)) {
        expect(seen[0].data[field]).toEqual(value);
      }
    }
  });

  it('still rejects an unknown message type when all six request types are registered', () => {
    const { parent, child } = makeWindows();
    const seen: unknown[] = [];
    const invalid: string[] = [];
    makeNostrTransport({ onRequest: request => seen.push(request), onInvalid: r => invalid.push(r) });
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: { type: 'openkey:nostr:export-secret:request', requestId: 'r1', protocolVersion: 1 },
    });
    expect(seen).toHaveLength(0);
    expect(invalid).toEqual(['unknown-message-type']);
  });

  it('rejects wrong-origin / wrong-source / missing requestId / wrong protocolVersion for every new type', () => {
    const newTypes = [
      'openkey:nostr:encrypt:request',
      'openkey:nostr:decrypt:request',
      'openkey:nostr:wrap:request',
      'openkey:nostr:unwrap:request',
    ] as const;
    for (const type of newTypes) {
      const { parent, child } = makeWindows();
      const impostor = new FakeWindow();
      const seen: unknown[] = [];
      const invalid: string[] = [];
      makeNostrTransport({ onRequest: request => seen.push(request), onInvalid: r => invalid.push(r) });
      const fields = SAMPLE_FIELDS[type]!;
      // Wrong origin.
      child.dispatch({
        origin: 'https://evil.example',
        source: parent as unknown as MessageEventSource,
        data: { type, requestId: 'r1', protocolVersion: 1, ...fields },
      });
      // Wrong source (same origin, sibling window).
      child.dispatch({
        origin: 'https://caller.example',
        source: impostor as unknown as MessageEventSource,
        data: { type, requestId: 'r1', protocolVersion: 1, ...fields },
      });
      // Missing requestId.
      child.dispatch({
        origin: 'https://caller.example',
        source: parent as unknown as MessageEventSource,
        data: { type, protocolVersion: 1, ...fields },
      });
      // Wrong protocol version.
      child.dispatch({
        origin: 'https://caller.example',
        source: parent as unknown as MessageEventSource,
        data: { type, requestId: 'r1', protocolVersion: 2, ...fields },
      });
      expect(seen).toHaveLength(0);
      expect(invalid).toEqual([
        'wrong-origin',
        'wrong-source',
        'missing-request-id',
        'wrong-protocol-version',
      ]);
    }
  });

  it('respond() for each new response type echoes requestId + protocolVersion 1, flattens the payload, and clears the active request', () => {
    for (const { requestType, responseType, payload } of RESPONSE_CASES) {
      const { parent, child } = makeWindows();
      const seen: any[] = [];
      const transport = makeNostrTransport({ onRequest: request => seen.push(request) });
      child.dispatch({
        origin: 'https://caller.example',
        source: parent as unknown as MessageEventSource,
        data: { type: requestType, requestId: 'live-1', protocolVersion: 1, ...SAMPLE_FIELDS[requestType] },
      });
      expect(seen).toHaveLength(1);

      parent.sent = [];
      transport.respond(responseType, 'live-1', true, payload);
      expect(parent.sent).toHaveLength(1);
      const message = parent.sent[0]!;
      expect(message.target).toBe('https://caller.example');
      expect(message.data.type).toBe(responseType);
      expect(message.data.requestId).toBe('live-1');
      expect(message.data.protocolVersion).toBe(1);
      expect(message.data.success).toBe(true);
      // Application payload flattened to the top level (ciphertext /
      // plaintext / wraps / rumor), exactly what the SDK reads.
      for (const [field, value] of Object.entries(payload)) {
        expect(message.data[field]).toEqual(value);
      }

      // Active request cleared: a follow-up request with a NEW id lands.
      child.dispatch({
        origin: 'https://caller.example',
        source: parent as unknown as MessageEventSource,
        data: { type: requestType, requestId: 'live-2', protocolVersion: 1, ...SAMPLE_FIELDS[requestType] },
      });
      expect(seen).toHaveLength(2);
      expect(seen[1].requestId).toBe('live-2');
    }
  });

  it('respond() flattens a failure envelope for the new types', () => {
    const { parent, child } = makeWindows();
    const transport = makeNostrTransport();
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: {
        type: 'openkey:nostr:encrypt:request',
        requestId: 'fail-1',
        protocolVersion: 1,
        ...SAMPLE_FIELDS['openkey:nostr:encrypt:request'],
      },
    });
    parent.sent = [];
    transport.respond('openkey:nostr:encrypt:response', 'fail-1', false, {
      error: { code: 'UNAUTHORIZED', message: 'No grant covers nip44_encrypt' },
    });
    expect(parent.sent).toHaveLength(1);
    expect(parent.sent[0]!.data.success).toBe(false);
    expect(parent.sent[0]!.data.requestId).toBe('fail-1');
    expect(parent.sent[0]!.data.protocolVersion).toBe(1);
    expect(parent.sent[0]!.data.error).toEqual({
      code: 'UNAUTHORIZED',
      message: 'No grant covers nip44_encrypt',
    });
  });

  it('respond() with a stale/mismatched requestId is a no-op and keeps the live request active', () => {
    const { parent, child } = makeWindows();
    const transport = makeNostrTransport();
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: {
        type: 'openkey:nostr:decrypt:request',
        requestId: 'live-1',
        protocolVersion: 1,
        ...SAMPLE_FIELDS['openkey:nostr:decrypt:request'],
      },
    });
    parent.sent = [];
    // Stale id: nothing posted, active request NOT cleared.
    transport.respond('openkey:nostr:decrypt:response', 'stale-9', true, { plaintext: 'nope' });
    expect(parent.sent).toHaveLength(0);
    // The live request is still active: correlated emits still flow...
    transport.emit('openkey:nostr:show');
    expect(parent.sent).toHaveLength(1);
    expect(parent.sent[0]!.data.requestId).toBe('live-1');
    // ...and the correlated respond still succeeds afterwards.
    parent.sent = [];
    transport.respond('openkey:nostr:decrypt:response', 'live-1', true, { plaintext: 'the real one' });
    expect(parent.sent).toHaveLength(1);
    expect(parent.sent[0]!.data.requestId).toBe('live-1');
    expect(parent.sent[0]!.data.plaintext).toBe('the real one');
  });

  it('rejects a second in-flight request across different Nostr types (invalid-payload)', () => {
    const { parent, child } = makeWindows();
    const seen: unknown[] = [];
    const invalid: string[] = [];
    makeNostrTransport({ onRequest: request => seen.push(request), onInvalid: r => invalid.push(r) });
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: {
        type: 'openkey:nostr:encrypt:request',
        requestId: 'first',
        protocolVersion: 1,
        ...SAMPLE_FIELDS['openkey:nostr:encrypt:request'],
      },
    });
    child.dispatch({
      origin: 'https://caller.example',
      source: parent as unknown as MessageEventSource,
      data: {
        type: 'openkey:nostr:wrap:request',
        requestId: 'second',
        protocolVersion: 1,
        ...SAMPLE_FIELDS['openkey:nostr:wrap:request'],
      },
    });
    expect(seen).toHaveLength(1);
    expect(invalid).toEqual(['invalid-payload']);
  });
});
