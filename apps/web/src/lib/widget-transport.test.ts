// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, it, beforeEach, afterEach } from 'bun:test';
import { createWidgetTransport } from './widget-transport';

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
        payload: { foo: 'bar' },
      },
    });
    expect(seen).toHaveLength(1);
    expect((seen[0] as any).requestId).toBe('r1');
    // Ready message and any response go to the parent, never '*'.
    expect(parent.sent.every((s) => s.target === 'https://caller.example')).toBe(true);
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

  it('resize goes to origin, never *', () => {
    const { parent } = makeWindows();
    const transport = createWidgetTransport({
      origin: 'https://caller.example',
      container: 'popup',
      onRequest: () => {},
      onClose: () => {},
    });
    transport.emitResize(200);
    expect(parent.sent).toContainEqual({
      target: 'https://caller.example',
      data: { type: 'openkey:resize', height: 200, protocolVersion: 1 },
    });
  });
});
