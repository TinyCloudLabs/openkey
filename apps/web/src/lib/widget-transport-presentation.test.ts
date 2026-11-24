// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import { createWidgetTransport, type WidgetRequest } from './widget-transport';

// Minimal window shim: the transport listens on `window`, answers its opener or parent, and checks the sender.
class FakeWindow {
  listeners: Array<(event: MessageEvent) => void> = [];
  sent: Array<{ target: string; data: unknown }> = [];
  opener: FakeWindow | null = null;
  parent: FakeWindow = this;
  addEventListener(type: string, cb: (event: MessageEvent) => void) {
    if (type === 'message') this.listeners.push(cb);
  }
  removeEventListener(type: string, cb: (event: MessageEvent) => void) {
    if (type === 'message') this.listeners = this.listeners.filter((l) => l !== cb);
  }
  postMessage(data: unknown, targetOrigin: string) {
    this.sent.push({ target: targetOrigin, data });
  }
  dispatch(event: { origin: string; source: unknown; data: unknown }) {
    for (const l of this.listeners) l(event as MessageEvent);
  }
}

let originalWindow: unknown;

function makeWindows() {
  const parent = new FakeWindow();
  const child = new FakeWindow();
  child.opener = parent;
  child.parent = parent;
  (globalThis as unknown as { window: unknown }).window = child;
  return { parent, child };
}

const ORIGIN = 'https://caller.example';
const PRESENTATION = { protocolVersion: 1, displayName: 'Acme Notes', reason: 'To sync.' };
const ICON = `data:image/png;base64,iVBORw0KGgo${'A'.repeat(30000)}`;

describe('widget-transport and the signMessage presentation', () => {
  beforeEach(() => {
    originalWindow = (globalThis as unknown as { window: unknown }).window;
  });
  afterEach(() => {
    (globalThis as unknown as { window: unknown }).window = originalWindow;
  });

  it('ready carries presentation: 1 only for a page that shows it', () => {
    for (const showsPresentation of [true, false, undefined]) {
      const { parent } = makeWindows();
      createWidgetTransport({
        origin: ORIGIN,
        container: 'popup',
        showsPresentation,
        onRequest: () => {},
        onClose: () => {},
        onInvalid: () => {},
      }).emitReady();
      expect(parent.sent[0]?.data).toEqual(
        showsPresentation ? { type: 'openkey:ready', protocolVersion: 1, presentation: 1 } : { type: 'openkey:ready', protocolVersion: 1 },
      );
    }
  });

  it('a v2 iframe phase says presentation: 1 beside its phase identity', () => {
    const { parent } = makeWindows();
    createWidgetTransport({
      origin: ORIGIN,
      container: 'iframe',
      protocolVersion: 2,
      requestId: 'phase-2',
      showsPresentation: true,
      onRequest: () => {},
      onClose: () => {},
      onInvalid: () => {},
    }).emitReady();
    expect(parent.sent[0]?.data).toEqual({ type: 'openkey:ready', protocolVersion: 2, requestId: 'phase-2', presentation: 1 });
  });

  function request(authorization: boolean, presentation: unknown) {
    const { parent, child } = makeWindows();
    const requests: WidgetRequest[] = [];
    createWidgetTransport({
      origin: ORIGIN,
      container: 'iframe',
      protocolVersion: 2,
      requestId: 'phase-2',
      showsPresentation: true,
      onRequest: (r) => requests.push(r),
      onClose: () => {},
      onInvalid: () => {},
    });
    child.dispatch({
      origin: ORIGIN,
      source: parent,
      data: {
        type: 'openkey:sign:request',
        requestId: 'phase-2',
        protocolVersion: 2,
        message: 'SIWE',
        ...(authorization ? { authorizationProtocolVersion: 1 } : {}),
        presentation,
      },
    });
    return requests;
  }

  it('a plain signMessage request keeps a presentation with an icon of 32768 characters', () => {
    const presentation = { ...PRESENTATION, iconUrl: `data:image/png;base64,iVBORw0KGgo${'A'.repeat(32744 - 11)}` };
    const [received] = request(false, presentation);
    expect(received.data.presentation).toEqual(presentation);
  });

  it('a TinyCloud authorization request keeps the 16 KB limit on its presentation', () => {
    const [received] = request(true, { ...PRESENTATION, iconUrl: ICON });
    expect(received.data.presentation).toBeUndefined();
    const [small] = request(true, PRESENTATION);
    expect(small.data.presentation).toEqual(PRESENTATION);
  });

  it('a plain presentation larger than the icon allowance is dropped and the request goes on', () => {
    const [received] = request(false, { ...PRESENTATION, reason: 'x'.repeat(41 * 1024) });
    expect(received.data.message).toBe('SIWE');
    expect(received.data.presentation).toBeUndefined();
  });
});
