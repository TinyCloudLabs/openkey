// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterEach, describe, expect, test } from 'bun:test';
import { embedSignInPasskey } from './embed-passkey';
import {
  carryPopupSignFlow,
  isWebSignFlowId,
  newWebSignFlowId,
  peekPopupSignFlow,
  popupSignFlowForLogin,
  releaseWebSignFlow,
  takePopupSignFlow,
  WEB_SIGN_FLOW_HEADER,
  webSignFlowHeaders,
} from './web-sign-flow';

const SHAPE = /^w\.[A-Za-z0-9_-]{32}$/;
const ORIGIN = 'https://openkey.test';

function memoryStorage(initial: Record<string, string> = {}) {
  const values = new Map(Object.entries(initial));
  return {
    values,
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value); },
    removeItem: (key: string) => { values.delete(key); },
  };
}

describe('the flow id', () => {
  test('has the web shape and is different every time', () => {
    const ids = Array.from({ length: 200 }, () => newWebSignFlowId());
    for (const id of ids) {
      expect(id).toMatch(SHAPE);
      expect(isWebSignFlowId(id)).toBe(true);
    }
    expect(new Set(ids).size).toBe(ids.length);
  });

  test('the header carries it under the one name the API reads', () => {
    expect(WEB_SIGN_FLOW_HEADER).toBe('x-openkey-passkey-flow');
    const id = newWebSignFlowId();
    expect(webSignFlowHeaders(id)).toEqual({ 'x-openkey-passkey-flow': id });
  });

  test('only the web shape is a web flow id', () => {
    const native = 'A'.repeat(32);
    for (const value of [undefined, null, 42, '', native, `w.${'A'.repeat(31)}`, `w.${'A'.repeat(33)}`, `W.${'A'.repeat(32)}`, `w.${'A'.repeat(31)}+`, `w.${'A'.repeat(32)}\n`, ` w.${'A'.repeat(32)}`]) {
      expect(isWebSignFlowId(value)).toBe(false);
    }
  });
});

describe('the flow id carried across the login redirect', () => {
  test('is kept, read without being forgotten, then taken once', () => {
    const storage = memoryStorage();
    const id = newWebSignFlowId();
    expect(peekPopupSignFlow(storage)).toBeNull();
    carryPopupSignFlow(id, storage);
    expect(peekPopupSignFlow(storage)).toBe(id);
    expect(peekPopupSignFlow(storage)).toBe(id);
    expect(takePopupSignFlow(storage)).toBe(id);
    expect(takePopupSignFlow(storage)).toBeNull();
    expect(storage.values.size).toBe(0);
  });

  test('a stored value without the web shape is never returned, and taking it clears it', () => {
    for (const stored of ['junk', 'A'.repeat(32), `w.${'A'.repeat(31)}`, `w.${'A'.repeat(33)}`]) {
      const storage = memoryStorage({ openkey_sign_flow: stored });
      expect(peekPopupSignFlow(storage)).toBeNull();
      expect(takePopupSignFlow(storage)).toBeNull();
      expect(storage.values.size).toBe(0);
    }
  });

  test('storage that refuses reads and writes is the same as no flow', () => {
    const broken = {
      getItem: () => { throw new Error('blocked'); },
      setItem: () => { throw new Error('blocked'); },
      removeItem: () => { throw new Error('blocked'); },
    };
    expect(() => carryPopupSignFlow(newWebSignFlowId(), broken)).not.toThrow();
    expect(peekPopupSignFlow(broken)).toBeNull();
    expect(takePopupSignFlow(broken)).toBeNull();
    expect(peekPopupSignFlow(null)).toBeNull();
  });

  test('the login page names it only when it returns to the sign pop-up', () => {
    const id = newWebSignFlowId();
    const storage = memoryStorage({ openkey_sign_flow: id });
    const redirect = `/widget/sign?origin=${encodeURIComponent('https://cli.tinycloud.xyz')}`;
    expect(popupSignFlowForLogin(redirect, ORIGIN, storage)).toBe(id);
    expect(popupSignFlowForLogin(`${ORIGIN}/widget/sign?origin=x`, ORIGIN, storage)).toBe(id);
    for (const other of [null, '', '/dashboard', '/widget/sign/other', '/widget/embed/sign', '/auth/native', 'https://evil.test/widget/sign', '//evil.test/widget/sign', 'http://[']) {
      expect(popupSignFlowForLogin(other, ORIGIN, storage), String(other)).toBeNull();
    }
    expect(popupSignFlowForLogin(redirect, ORIGIN, memoryStorage({ openkey_sign_flow: 'junk' }))).toBeNull();
    expect(popupSignFlowForLogin(redirect, ORIGIN, memoryStorage())).toBeNull();
  });
});

const realGlobals = {
  window: Object.getOwnPropertyDescriptor(globalThis, 'window'),
  sessionStorage: Object.getOwnPropertyDescriptor(globalThis, 'sessionStorage'),
  navigator: Object.getOwnPropertyDescriptor(globalThis, 'navigator'),
  PublicKeyCredential: Object.getOwnPropertyDescriptor(globalThis, 'PublicKeyCredential'),
  fetch: globalThis.fetch,
};

function installBrowser(options: { framed: boolean; token?: string }) {
  const top = {};
  Object.defineProperty(globalThis, 'window', { configurable: true, writable: true, value: { top, self: options.framed ? {} : top } });
  Object.defineProperty(globalThis, 'sessionStorage', {
    configurable: true,
    writable: true,
    value: { getItem: () => options.token ?? null, setItem: () => {}, removeItem: () => {} },
  });
}

afterEach(() => {
  for (const name of ['window', 'sessionStorage', 'navigator', 'PublicKeyCredential'] as const) {
    const real = realGlobals[name];
    if (real) Object.defineProperty(globalThis, name, real);
    else delete (globalThis as Record<string, unknown>)[name];
  }
  globalThis.fetch = realGlobals.fetch;
});

describe('releasing a flow', () => {
  async function release(id: string) {
    const requests: Array<{ url: string; init: RequestInit }> = [];
    await releaseWebSignFlow(id, (async (url: string, init: RequestInit) => {
      requests.push({ url, init });
      return new Response('{}');
    }) as unknown as typeof fetch);
    return requests;
  }

  test('posts the flow id with the cookie session outside an embedded frame', async () => {
    installBrowser({ framed: false, token: 'stale-token' });
    const id = newWebSignFlowId();
    const requests = await release(id);
    expect(requests).toHaveLength(1);
    expect(requests[0]!.url).toEndWith('/api/delegate/authorize-sign-release');
    expect(requests[0]!.init.method).toBe('POST');
    expect(requests[0]!.init.credentials).toBe('include');
    const headers = requests[0]!.init.headers as Record<string, string>;
    expect(headers[WEB_SIGN_FLOW_HEADER]).toBe(id);
    expect(headers.Authorization).toBeUndefined();
  });

  test('posts the flow id with the frame\'s session token inside an embedded frame', async () => {
    installBrowser({ framed: true, token: 'frame-token' });
    const id = newWebSignFlowId();
    const requests = await release(id);
    expect(requests).toHaveLength(1);
    expect(requests[0]!.init.credentials).toBe('omit');
    const headers = requests[0]!.init.headers as Record<string, string>;
    expect(headers[WEB_SIGN_FLOW_HEADER]).toBe(id);
    expect(headers.Authorization).toBe('Bearer frame-token');
  });

  test('a failed request is not an error', async () => {
    installBrowser({ framed: false });
    await expect(releaseWebSignFlow(newWebSignFlowId(), (async () => { throw new Error('offline'); }) as unknown as typeof fetch)).resolves.toBeUndefined();
  });
});

describe('the iframe passkey sign-in', () => {
  function installPasskey() {
    installBrowser({ framed: true });
    const bytes = (value: string) => new TextEncoder().encode(value).buffer;
    Object.defineProperty(globalThis, 'PublicKeyCredential', { configurable: true, writable: true, value: class {} });
    Object.defineProperty(globalThis, 'navigator', {
      configurable: true,
      value: {
        credentials: {
          get: async () => ({
            id: 'credential',
            rawId: bytes('credential'),
            type: 'public-key',
            authenticatorAttachment: 'platform',
            response: { authenticatorData: bytes('data'), clientDataJSON: bytes('{}'), signature: bytes('signature'), userHandle: null },
            getClientExtensionResults: () => ({}),
          }),
        },
      },
    });
  }

  async function signIn(flowHeaders?: Record<string, string>) {
    installPasskey();
    const requests: Array<{ url: string; headers: Record<string, string> }> = [];
    globalThis.fetch = (async (url: string, init: RequestInit) => {
      requests.push({ url: String(url), headers: { ...(init.headers as Record<string, string>) } });
      if (String(url).endsWith('/generate-authenticate-options')) {
        return Response.json({ challenge: 'Y2hhbGxlbmdl', rpId: 'openkey.test', challengeToken: 'challenge-token' });
      }
      return Response.json({ session: {}, user: { id: 'user_1' }, sessionToken: 'token' });
    }) as unknown as typeof fetch;
    await embedSignInPasskey(flowHeaders);
    return requests;
  }

  test('names the flow on the verification and on nothing else', async () => {
    const id = newWebSignFlowId();
    const requests = await signIn(webSignFlowHeaders(id));
    expect(requests).toHaveLength(2);
    expect(requests[0]!.url).toEndWith('/api/passkey/generate-authenticate-options');
    expect(requests[0]!.headers[WEB_SIGN_FLOW_HEADER]).toBeUndefined();
    expect(requests[1]!.url).toEndWith('/api/passkey/verify-authentication');
    expect(requests[1]!.headers[WEB_SIGN_FLOW_HEADER]).toBe(id);
  });

  test('names no flow when none is given', async () => {
    const requests = await signIn();
    expect(requests[1]!.url).toEndWith('/api/passkey/verify-authentication');
    expect(requests[1]!.headers[WEB_SIGN_FLOW_HEADER]).toBeUndefined();
  });
});
