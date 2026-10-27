// The popup of authorizeTinyCloud opens in the caller's own tick, before the
// first await, and is navigated to the widget once the route is known. A browser
// lets a window open only while the click that asked for it still counts; the key
// list that routing waits for can outlast that.

// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { OpenKey } from './index';

const HOST = 'https://openkey.test';
const REQUEST = { protocolVersion: 1 as const, siwe: 'app.test wants you to sign in', jwk: { kty: 'OKP' }, host: 'https://node.test', keyId: 'key-other' };

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

// Timers the test runs by hand: the popup poll is a setInterval.
const intervals: Array<() => void> = [];
let saved: Pick<typeof globalThis, 'setInterval' | 'clearInterval' | 'setTimeout' | 'clearTimeout'>;
function holdTimers() {
  saved = { setInterval: globalThis.setInterval, clearInterval: globalThis.clearInterval, setTimeout: globalThis.setTimeout, clearTimeout: globalThis.clearTimeout };
  intervals.length = 0;
  (globalThis as any).setInterval = (fn: () => void) => { intervals.push(fn); return intervals.length; };
  (globalThis as any).clearInterval = () => {};
  (globalThis as any).setTimeout = () => 0;
  (globalThis as any).clearTimeout = () => {};
}
const releaseTimers = () => Object.assign(globalThis, saved);
const tick = () => intervals.forEach((fn) => fn());

type PopupWindow = { closed: boolean; location: { href: string }; close: () => void; postMessage: () => void };

/** A window that, like a browser, only opens a popup while the click still counts. */
function setup(mode: 'popup' | 'iframe') {
  const previous = { window: (globalThis as any).window, document: (globalThis as any).document };
  const activation = { active: true };
  const opened: Array<{ url: string; popup: PopupWindow | null }> = [];
  const order: string[] = [];
  const win: any = {
    location: { origin: 'https://app.test', hostname: 'app.test', href: '' },
    screenX: 0, screenY: 0, outerWidth: 1024, outerHeight: 768, innerHeight: 800,
    matchMedia: () => ({ matches: false }),
    addEventListener: () => {},
    dispatchEvent: () => true,
    removeEventListener: () => {},
    open: (url: string) => {
      order.push(`open ${url}`);
      if (!activation.active) {
        opened.push({ url, popup: null });
        return null;
      }
      const popup: PopupWindow = { closed: false, location: { href: url }, close() { this.closed = true; }, postMessage() {} };
      opened.push({ url, popup });
      return popup;
    },
  };
  (globalThis as any).window = win;
  (globalThis as any).document = { createElement: () => ({ style: {}, setAttribute() {}, addEventListener() {}, appendChild() {}, attachShadow: () => ({ appendChild() {} }), remove() {} }), body: { appendChild() {} } };
  const openkey = new OpenKey({ host: HOST, mode });
  (openkey as any).lastAuth = { address: '0xfirst', keyId: 'key-first', keyType: 'MANAGED' };
  return {
    openkey,
    activation,
    opened,
    order,
    restore() {
      (globalThis as any).window = previous.window;
      (globalThis as any).document = previous.document;
    },
  };
}

describe('authorizeTinyCloud in popup mode', () => {
  beforeEach(holdTimers);
  afterEach(releaseTimers);

  test('opens the popup in the call itself, before the key list answers, then navigates it', async () => {
    const { openkey, activation, opened, order, restore } = setup('popup');
    try {
      const keys = deferred<Array<{ id: string; keyType: 'MANAGED' | 'EXTERNAL' }>>();
      (openkey as any).fetchKnownKeysIfNeeded = () => { order.push('key list requested'); return keys.promise; };
      const result = openkey.authorizeTinyCloud(REQUEST, { mode: 'popup' });
      result.catch(() => {});

      // Same tick as the call: one blank window, and the key list is still waited for.
      expect(opened).toHaveLength(1);
      expect(opened[0]!.url).toBe('about:blank');
      expect(order).toEqual(['open about:blank', 'key list requested']);

      // By the time the key list answers, the click has expired.
      activation.active = false;
      keys.resolve([{ id: 'key-other', keyType: 'MANAGED' }]);
      for (let i = 0; i < 20; i++) await Promise.resolve();

      expect(opened).toHaveLength(1);
      const popup = opened[0]!.popup!;
      expect(popup.location.href).toStartWith(`${HOST}/widget/sign?origin=${encodeURIComponent('https://app.test')}`);

      popup.closed = true;
      tick();
      await expect(result).rejects.toMatchObject({ code: 'USER_CANCELLED' });
    } finally {
      restore();
    }
  });

  test('the order that waits first is refused by the same check', async () => {
    const { openkey, activation, opened, restore } = setup('popup');
    try {
      const keys = deferred<unknown[]>();
      // What the flow did before: ask for the key list, then open.
      const flow = (async () => {
        await keys.promise;
        return (openkey as any).openFlow('sign', { type: 'openkey:sign:request' }, 'popup');
      })();
      flow.catch(() => {});
      activation.active = false;
      keys.resolve([]);
      await expect(flow).rejects.toMatchObject({ code: 'POPUP_BLOCKED' });
      expect(opened.map((entry) => entry.popup)).toEqual([null]);
    } finally {
      restore();
    }
  });

  test('closes the blank popup when the flow fails before the widget is shown', async () => {
    const { openkey, opened, restore } = setup('popup');
    try {
      (openkey as any).fetchKnownKeysIfNeeded = () => Promise.reject(new Error('key list unavailable'));
      await expect(openkey.authorizeTinyCloud(REQUEST, { mode: 'popup' })).rejects.toThrow('key list unavailable');
      expect(opened).toHaveLength(1);
      expect(opened[0]!.popup!.closed).toBe(true);
    } finally {
      restore();
    }
  });

  test('closes the blank popup when sending it to the widget fails, and the call rejects', async () => {
    const { openkey, opened, restore } = setup('popup');
    try {
      (openkey as any).fetchKnownKeysIfNeeded = () => Promise.resolve([{ id: 'key-other', keyType: 'MANAGED' }]);
      const originalOpen = (globalThis as any).window.open;
      (globalThis as any).window.open = (url: string) => {
        const popup = originalOpen(url) as PopupWindow;
        // The blank window refuses to be navigated.
        Object.defineProperty(popup, 'location', {
          get: () => ({ set href(_value: string) { throw new Error('navigation refused'); } }),
        });
        return popup;
      };
      await expect(openkey.authorizeTinyCloud(REQUEST, { mode: 'popup' })).rejects.toMatchObject({ code: 'POPUP_BLOCKED' });
      expect(opened).toHaveLength(1);
      expect(opened[0]!.popup!.closed).toBe(true);
    } finally {
      restore();
    }
  });

  test('closes the blank popup when the key is an external wallet, which opens its own flow', async () => {
    const { openkey, opened, restore } = setup('popup');
    try {
      (openkey as any).lastAuth = { address: '0xext', keyId: 'key-ext', keyType: 'EXTERNAL' };
      (openkey as any).fetchKnownKeysIfNeeded = () => Promise.resolve([]);
      (openkey as any).authorizeTinyCloudExternal = async () => { throw new Error('external flow reached'); };
      await expect(openkey.authorizeTinyCloud({ ...REQUEST, keyId: undefined }, { mode: 'popup' })).rejects.toThrow('external flow reached');
      expect(opened[0]!.popup!.closed).toBe(true);
    } finally {
      restore();
    }
  });

  test('opens nothing for a request that is refused before any window is needed', async () => {
    const { openkey, opened, restore } = setup('popup');
    try {
      await expect(openkey.authorizeTinyCloud({ ...REQUEST, protocolVersion: 2 as never }, { mode: 'popup' })).rejects.toThrow('protocolVersion 1');
      await expect(openkey.authorizeTinyCloud({ ...REQUEST, siwe: '' }, { mode: 'popup' })).rejects.toThrow('non-empty SIWE');
      expect(opened).toHaveLength(0);
    } finally {
      restore();
    }
  });

  test('a browser that gives no window for the blank popup leaves the flow as it was', async () => {
    const { openkey, activation, opened, restore } = setup('popup');
    try {
      activation.active = false;
      (openkey as any).fetchKnownKeysIfNeeded = () => Promise.resolve([]);
      await expect(openkey.authorizeTinyCloud(REQUEST, { mode: 'popup' })).rejects.toMatchObject({ code: 'POPUP_BLOCKED' });
      // One attempt at the call, one by the flow itself.
      expect(opened.map((entry) => entry.url)).toHaveLength(2);
    } finally {
      restore();
    }
  });
});

describe('other modes', () => {
  beforeEach(holdTimers);
  afterEach(releaseTimers);

  test('iframe mode opens no popup in the call', async () => {
    const { openkey, opened, restore } = setup('iframe');
    try {
      const keys = deferred<unknown[]>();
      (openkey as any).fetchKnownKeysIfNeeded = () => keys.promise;
      (openkey as any).openFlow = async () => { throw new Error('iframe flow reached'); };
      const result = openkey.authorizeTinyCloud(REQUEST, { mode: 'iframe' });
      result.catch(() => {});
      expect(opened).toHaveLength(0);
      keys.resolve([{ id: 'key-other', keyType: 'MANAGED' }]);
      await expect(result).rejects.toThrow('iframe flow reached');
      expect(opened).toHaveLength(0);
    } finally {
      restore();
    }
  });

  test('signMessage and connect open their popup as before: one window, with the widget URL', async () => {
    const { openkey, opened, restore } = setup('popup');
    try {
      const result = openkey.connect({ mode: 'popup' });
      result.catch(() => {});
      expect(opened.map((entry) => entry.url)).toHaveLength(1);
      expect(opened[0]!.url).toStartWith(`${HOST}/widget/connect?origin=`);
      opened[0]!.popup!.closed = true;
      tick();
      await expect(result).rejects.toMatchObject({ code: 'USER_CANCELLED' });
    } finally {
      restore();
    }
  });
});
