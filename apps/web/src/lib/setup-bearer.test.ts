// The embed's session token on its way to the account setup window: handed over in the request message after the
// window's hello, read only from the window's opener at OpenKey's own origin, held in memory, sent as a bearer
// (no cookie) to the five setup calls and the key list, dropped when the API rejects it. It never reaches storage, a
// cookie or the URL.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import {
  ACCOUNT_SETUP_REQUEST,
  openAccountSetupWindow,
  readAccountSetupBearer,
  readAccountSetupRequest,
} from './account-setup';
import { api } from './api';
import { dropSetupBearer, heldSetupBearer, holdSetupBearer, onSetupBearerDropped } from './setup-bearer';

const OPENKEY = 'https://openkey.test';
const APP = 'https://app.example';
const TOKEN = 'embed.token%3D';
const opener = {} as MessageEventSource;
const message = (extra: Record<string, unknown> = {}) => ({
  type: ACCOUNT_SETUP_REQUEST, requestId: 'req_1', protocolVersion: 1, keyId: 'key_1', requestOrigin: APP, sessionToken: TOKEN, ...extra,
});
const event = (data: unknown, over: { origin?: string; source?: MessageEventSource } = {}) =>
  ({ origin: over.origin ?? OPENKEY, source: over.source ?? opener, data });

type Touch = string;
const realWindow = (globalThis as { window?: unknown }).window;
const realSession = (globalThis as { sessionStorage?: unknown }).sessionStorage;
const realLocal = (globalThis as { localStorage?: unknown }).localStorage;
const realDocument = (globalThis as { document?: unknown }).document;
const realFetch = globalThis.fetch;
let touched: Touch[] = [];

/** Storage and cookie fakes that record every call; the embed's stored token is readable, nothing may be written. */
function installStorage(stored: string | null) {
  const record = (name: string) => (...args: unknown[]) => { touched.push(`${name}(${args.join(',')})`); return null; };
  (globalThis as { sessionStorage?: unknown }).sessionStorage = {
    getItem: (key: string) => key === 'openkey_session_token' ? stored : null,
    setItem: record('session.setItem'),
    removeItem: record('session.removeItem'),
    clear: record('session.clear'),
  };
  (globalThis as { localStorage?: unknown }).localStorage = {
    getItem: record('local.getItem'), setItem: record('local.setItem'), removeItem: record('local.removeItem'), clear: record('local.clear'),
  };
  (globalThis as { document?: unknown }).document = {
    get cookie() { touched.push('cookie.get'); return ''; },
    set cookie(value: string) { touched.push(`cookie.set(${value})`); },
  };
}

beforeEach(() => {
  touched = [];
  holdSetupBearer(null);
});
afterEach(() => {
  holdSetupBearer(null);
  (globalThis as { window?: unknown }).window = realWindow;
  (globalThis as { sessionStorage?: unknown }).sessionStorage = realSession;
  (globalThis as { localStorage?: unknown }).localStorage = realLocal;
  (globalThis as { document?: unknown }).document = realDocument;
  globalThis.fetch = realFetch;
});

describe('reading the token from the request message', () => {
  test('takes it only from a valid request of the counterparty window at its exact origin, from an OpenKey hand-off', () => {
    installStorage(null);
    expect(readAccountSetupBearer(event(message()), OPENKEY, opener, true)).toBe(TOKEN);
    // An app's own window never hands a token over.
    expect(readAccountSetupBearer(event(message(), { origin: APP }), APP, opener, false)).toBeNull();
    expect(readAccountSetupBearer(event(message(), { origin: 'https://evil.example' }), OPENKEY, opener, true)).toBeNull();
    expect(readAccountSetupBearer(event(message(), { source: {} as MessageEventSource }), OPENKEY, opener, true)).toBeNull();
    expect(readAccountSetupBearer(event(message()), null, opener, true)).toBeNull();
    expect(readAccountSetupBearer(event(message()), OPENKEY, null, true)).toBeNull();
    // A message that is not a valid request carries no token.
    expect(readAccountSetupBearer(event(message({ protocolVersion: 2 })), OPENKEY, opener, true)).toBeNull();
    expect(readAccountSetupBearer(event(message({ type: 'other' })), OPENKEY, opener, true)).toBeNull();
    expect(readAccountSetupBearer(event(message({ requestOrigin: undefined })), OPENKEY, opener, true)).toBeNull();
    expect(touched).toEqual([]);
  });

  test('refuses a token that is not one header-safe string', () => {
    for (const bad of [undefined, null, 5, {}, ['x'], '', 'has space', 'new\nline', 'tab\t', 'é', 'x'.repeat(4097)]) {
      expect(readAccountSetupBearer(event(message({ sessionToken: bad })), OPENKEY, opener, true), String(bad)).toBeNull();
    }
    expect(readAccountSetupBearer(event(message({ sessionToken: undefined })), OPENKEY, opener, true)).toBeNull();
  });

  test('the request read for the page carries no token', () => {
    const read = readAccountSetupRequest(event(message()), OPENKEY, opener, true);
    expect(read).toEqual({ requestId: 'req_1', protocolVersion: 1, keyId: 'key_1', requester: APP });
    expect(JSON.stringify(read)).not.toContain(TOKEN);
  });
});

describe('the held token', () => {
  test('lives in memory, is dropped on a rejection and tells the page', () => {
    installStorage(null);
    const dropped: number[] = [];
    const stop = onSetupBearerDropped(() => dropped.push(1));
    dropSetupBearer();
    expect(dropped).toEqual([]);
    holdSetupBearer(TOKEN);
    expect(heldSetupBearer()).toBe(TOKEN);
    dropSetupBearer();
    expect(heldSetupBearer()).toBeNull();
    expect(dropped).toEqual([1]);
    stop();
    holdSetupBearer(TOKEN);
    dropSetupBearer();
    expect(dropped).toEqual([1]);
    expect(touched).toEqual([]);
  });
});

describe('the hand-off sending the token', () => {
  function fakeWindow(options: { embedded: boolean; stored: string | null }) {
    installStorage(options.stored);
    const listeners = new Set<(event: unknown) => void>();
    const opened: string[] = [];
    const posted: { data: Record<string, unknown>; origin: string }[] = [];
    const popup = { closed: false, postMessage: (data: unknown, origin: string) => { posted.push({ data: data as Record<string, unknown>, origin }); } };
    const self = {};
    (globalThis as { window?: unknown }).window = {
      self, top: options.embedded ? {} : self,
      location: { origin: OPENKEY },
      open: (url: string) => { opened.push(url); return popup; },
      addEventListener: (type: string, listener: (event: unknown) => void) => { if (type === 'message') listeners.add(listener); },
      removeEventListener: (type: string, listener: (event: unknown) => void) => { listeners.delete(listener); },
    };
    const send = (data: unknown, over: { origin?: string; source?: unknown } = {}) => {
      for (const listener of [...listeners]) listener({ origin: over.origin ?? OPENKEY, source: over.source ?? popup, data });
    };
    return { popup, posted, opened, send };
  }

  test('an embedded frame sends its token in the request, after the hello, to the window it opened at OpenKey\'s origin', () => {
    const { popup, posted, opened, send } = fakeWindow({ embedded: true, stored: TOKEN });
    void openAccountSetupWindow({ keyId: 'key_1', requestOrigin: APP });
    expect(posted).toEqual([]);
    send({ type: 'openkey:ready' }, { source: {} });
    send({ type: 'openkey:ready' }, { origin: APP });
    expect(posted).toEqual([]);
    send({ type: 'openkey:ready' }, { source: popup });
    expect(posted).toHaveLength(1);
    expect(posted[0]!.origin).toBe(OPENKEY);
    expect(posted[0]!.data).toMatchObject({ type: ACCOUNT_SETUP_REQUEST, keyId: 'key_1', requestOrigin: APP, sessionToken: TOKEN });
    // The window's URL, the page's storage and its cookies take nothing in.
    expect(opened.join(' ')).not.toContain(TOKEN);
    expect(touched).toEqual([]);
  });

  test('a frame without a token, or a top-level page with a leftover one, sends none', () => {
    const none = fakeWindow({ embedded: true, stored: null });
    void openAccountSetupWindow({ keyId: null, requestOrigin: APP });
    none.send({ type: 'openkey:ready' });
    expect(none.posted).toHaveLength(1);
    expect('sessionToken' in none.posted[0]!.data).toBe(false);

    const top = fakeWindow({ embedded: false, stored: TOKEN });
    void openAccountSetupWindow({ keyId: null, requestOrigin: APP });
    top.send({ type: 'openkey:ready' });
    expect(top.posted).toHaveLength(1);
    expect('sessionToken' in top.posted[0]!.data).toBe(false);
  });
});

describe('the setup calls with a held token', () => {
  type Call = { url: string; authorization: string | undefined; credentials: RequestCredentials | undefined };
  let calls: Call[];
  let status = 200;

  beforeEach(() => {
    calls = [];
    status = 200;
    const self = {};
    // A top-level setup window: it has the cookie, and may hold a leftover widget token of another account.
    (globalThis as { window?: unknown }).window = { self, top: self };
    installStorage('leftover-widget-token');
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), authorization: new Headers(init?.headers).get('authorization') ?? undefined, credentials: init?.credentials });
      return new Response(JSON.stringify(status === 200 ? { keys: [] } : { error: 'Unauthorized' }), {
        status, headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;
  });

  const setupCalls: Array<[string, () => Promise<unknown>]> = [
    ['prepare', () => api.accountSetup.prepare('key_1', APP)],
    ['passkey', () => api.accountSetup.stepUp('row_1')],
    ['email-code', () => api.accountSetup.sendEmailCode('row_1')],
    ['approve', () => api.accountSetup.approve('row_1', { emailCode: '123456' })],
    ['finish', () => api.accountSetup.finish('row_1')],
    ['the key list', () => api.accountSetup.keys()],
  ];

  test.each(setupCalls)('%s sends the held token as a bearer and no cookie', async (_name: string, call: () => Promise<unknown>) => {
    holdSetupBearer(TOKEN);
    await call();
    expect(calls).toHaveLength(1);
    expect(calls[0]!.authorization).toBe(`Bearer ${TOKEN}`);
    expect(calls[0]!.credentials).toBe('omit');
    expect(heldSetupBearer()).toBe(TOKEN);
  });

  test.each(setupCalls)('%s without a held token sends the cookie and no Authorization, whatever the tab stores', async (_name: string, call: () => Promise<unknown>) => {
    await call();
    expect(calls).toHaveLength(1);
    expect(calls[0]!.authorization).toBeUndefined();
    expect(calls[0]!.credentials).toBe('include');
  });

  test('a rejected token is dropped and tells the page; another refusal keeps it', async () => {
    const dropped: number[] = [];
    onSetupBearerDropped(() => dropped.push(1));
    holdSetupBearer(TOKEN);
    status = 403;
    await api.accountSetup.prepare('key_1', APP).catch(() => {});
    expect(heldSetupBearer()).toBe(TOKEN);
    status = 401;
    await expect(api.accountSetup.prepare('key_1', APP)).rejects.toBeDefined();
    expect(heldSetupBearer()).toBeNull();
    expect(dropped).toEqual([1]);
    expect(touched.filter((entry) => !entry.endsWith('getItem(openkey_session_token)'))).toEqual([]);
  });
});
