// The renewal ask on a widget sign request (TC-2933): the transport keeps a well-formed ask as is and drops
// anything else, so the page never forwards a malformed ask to /authorize-sign-prepare.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import { createWidgetTransport, type WidgetRequest } from './widget-transport';

class FakeWindow {
  listeners: Array<(event: MessageEvent) => void> = [];
  opener: FakeWindow | null = null;
  parent: FakeWindow = this;
  addEventListener(type: string, cb: (event: MessageEvent) => void) {
    if (type === 'message') this.listeners.push(cb);
  }
  removeEventListener() {}
  postMessage() {}
  dispatch(event: { origin: string; source: unknown; data: unknown }) {
    for (const l of this.listeners) l(event as MessageEvent);
  }
}

const ORIGIN = 'https://caller.example';
// The transport reads `window` from the global scope; the test swaps in a fake per request.
const globals = globalThis as unknown as { window: unknown };
let originalWindow: unknown;
beforeEach(() => { originalWindow = globals.window; });
afterEach(() => { globals.window = originalWindow; });

/** Sends one sign request carrying `fields` and returns what the page receives, or null when it is refused. */
function deliver(fields: Record<string, unknown>): Record<string, unknown> | null {
  const parent = new FakeWindow();
  const child = new FakeWindow();
  child.opener = parent;
  globals.window = child;
  const warn = console.warn;
  console.warn = () => {};
  let received: WidgetRequest | null = null;
  try {
    createWidgetTransport({ origin: ORIGIN, container: 'popup', onRequest: (request) => { received = request; }, onClose: () => {} });
    child.dispatch({
      origin: ORIGIN,
      source: parent,
      data: { type: 'openkey:sign:request', requestId: 'r1', protocolVersion: 1, message: 'siwe', ...fields },
    });
  } finally {
    console.warn = warn;
  }
  return received === null ? null : (received as WidgetRequest).data;
}

describe('the renewal ask on a sign request', () => {
  it('keeps a well-formed ask, with or without a purpose', () => {
    for (const renewal of [
      { version: 1, leaseLifetimeSeconds: 7_776_000, purpose: 'standing' },
      { version: 1, leaseLifetimeSeconds: 1, purpose: 'task' },
      { version: 1, leaseLifetimeSeconds: 31_536_000 },
    ]) {
      const data = deliver({ expiryChangeable: true, renewal });
      expect(data?.renewal).toEqual(renewal);
    }
  });

  it('drops a malformed ask but still delivers the request', () => {
    for (const renewal of [
      null,
      'yes',
      [],
      { version: 2, leaseLifetimeSeconds: 600 },
      { leaseLifetimeSeconds: 600 },
      { version: 1 },
      { version: 1, leaseLifetimeSeconds: '600' },
      { version: 1, leaseLifetimeSeconds: 0 },
      { version: 1, leaseLifetimeSeconds: 31_536_001 },
      { version: 1, leaseLifetimeSeconds: 1.5 },
      { version: 1, leaseLifetimeSeconds: Number.NaN },
      { version: 1, leaseLifetimeSeconds: 600, purpose: 'forever' },
      { version: 1, leaseLifetimeSeconds: 600, purpose: null },
      { version: 1, leaseLifetimeSeconds: 600, extra: true },
    ]) {
      const data = deliver({ expiryChangeable: true, renewal });
      expect(data).not.toBeNull();
      expect(data!.message).toBe('siwe');
      expect(data!.renewal).toBeUndefined();
    }
  });

  it('drops an ask that comes without expiryChangeable: true', () => {
    const data = deliver({ renewal: { version: 1, leaseLifetimeSeconds: 600, purpose: 'standing' } });
    expect(data).not.toBeNull();
    expect(data!.renewal).toBeUndefined();
  });

  it('leaves a request without an ask unchanged', () => {
    const data = deliver({ expiryChangeable: true });
    expect(data).not.toBeNull();
    expect('renewal' in data!).toBe(false);
  });
});
