// TC-2355: the API refuses any request with an Authorization header when it changes a TinyCloud signing control
// (auto-sign, the manage-key mode, per-app grants, disconnects, the primary key): those are cookie-session-only.
// A tab can hold a leftover embedded-widget session token, and `fetchAPI` prefers a stored token over the cookie, so
// the owner's own change went out as a bearer request and got a 403. Every control change must use the cookie, with no
// Authorization header, whatever the tab holds; everything else keeps using the stored token as before.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { api } from './api';

type Call = { url: string; method: string; authorization: string | undefined; credentials: RequestCredentials | undefined };

const realFetch = globalThis.fetch;
const realSession = (globalThis as { sessionStorage?: unknown }).sessionStorage;
let calls: Call[] = [];
let stored: string | null = null;
const realWindow = (globalThis as { window?: unknown }).window;
const topLevel = { self: {}, top: {} };
topLevel.self = topLevel.top; // a tab's own window: window.self === window.top
const inIframe = { self: {}, top: {} }; // an embedded frame: window.self !== window.top

beforeEach(() => {
  calls = [];
  stored = 'tok-from-the-widget';
  (globalThis as { window?: unknown }).window = inIframe;
  (globalThis as { sessionStorage?: unknown }).sessionStorage = {
    getItem: (key: string) => (key === 'openkey_session_token' ? stored : null),
    setItem: () => {},
    removeItem: () => {},
  };
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    calls.push({
      url: String(input),
      method: init?.method ?? 'GET',
      authorization: headers.get('authorization') ?? undefined,
      credentials: init?.credentials,
    });
    return new Response(JSON.stringify({}), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
  (globalThis as { sessionStorage?: unknown }).sessionStorage = realSession;
  (globalThis as { window?: unknown }).window = realWindow;
});

const controls: Array<[string, () => Promise<unknown>, string, string]> = [
  ['turning Auto-Sign off', () => api.updateAutoSignPreference(false), 'PATCH', '/api/account/auto-sign'],
  ['changing the TinyCloud manage-key mode', () => api.updateTinyCloudManageKeyPreference('OWNER_APPROVED' as never, 1, 'CONFIRM'), 'PATCH', '/api/account/tinycloud-manage-key'],
  ['changing one app\'s grant', () => api.updateTinyCloudManageKeyApp('client-1', false, 1, 'CONFIRM'), 'PATCH', '/api/account/tinycloud-apps/client-1'],
  ['disconnecting an app', () => api.disconnectTinyCloudApp('client-1'), 'DELETE', '/api/account/tinycloud-apps/client-1'],
  ['disconnecting an MCP app', () => api.disconnectMcpApp('consent-1'), 'DELETE', '/api/account/tinycloud-apps/mcp/consent-1'],
  ['making a key the primary key', () => api.setPrimaryKey('key-1'), 'POST', '/api/keys/key-1/primary'],
];

describe('signing-control changes use the cookie session', () => {
  test.each(controls)('%s sends no Authorization header and includes the cookie, even with a stored token', async (_name: string, call: () => Promise<unknown>, method: string, path: string) => {
    await call();
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url.endsWith(path)).toBe(true);
    expect(calls[0]!.method).toBe(method);
    expect(calls[0]!.authorization).toBeUndefined();
    expect(calls[0]!.credentials).toBe('include');
  });
});

// A tab's cookie session and a leftover widget token can belong to DIFFERENT accounts (A signed in on this page, the
// widget left B's token in the tab): the page then showed B's data and wrote to A. Outside an embedded frame the
// cookie is the one identity for every call; the stored token is for embedded frames, where cookies are blocked.
describe('a top-level tab uses one identity: the cookie', () => {
  test('reads, writes and controls all go out with the cookie and no Authorization, whatever the tab stores', async () => {
    (globalThis as { window?: unknown }).window = topLevel;
    await api.getAutoSignPreference();
    await api.listKeys();
    await api.updateAutoSignPreference(false);
    expect(calls.map((call) => call.authorization)).toEqual([undefined, undefined, undefined]);
    expect(calls.map((call) => call.credentials)).toEqual(['include', 'include', 'include']);
  });
});

describe('an embedded frame keeps using the stored token', () => {
  test('reads and ordinary calls still send the bearer and omit cookies', async () => {
    await api.getAutoSignPreference();
    await api.listKeys();
    expect(calls.map((call) => call.authorization)).toEqual(['Bearer tok-from-the-widget', 'Bearer tok-from-the-widget']);
    expect(calls.map((call) => call.credentials)).toEqual(['omit', 'omit']);
  });

  test('a control change from an embedded frame still never carries the bearer', async () => {
    await api.updateAutoSignPreference(false);
    expect(calls[0]!.authorization).toBeUndefined();
    expect(calls[0]!.credentials).toBe('include');
  });

  test('with no stored token a control change is the same cookie request', async () => {
    stored = null;
    await api.updateAutoSignPreference(false);
    expect(calls[0]!.authorization).toBeUndefined();
    expect(calls[0]!.credentials).toBe('include');
  });
});
