// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterEach, describe, expect, it } from 'bun:test';
import {
  ACCOUNT_SETUP_REQUEST,
  ACCOUNT_SETUP_RESPONSE,
  accountSetupAnswer,
  accountSetupFailure,
  accountSetupSuccess,
  hostSigningRefusal,
  openAccountSetupWindow,
  readAccountSetupRequest,
  TINYCLOUD_ONE_SETUP_URL,
} from './account-setup';

const APP = 'https://app.example';
const OPENKEY = 'https://openkey.test';
const opener = {} as MessageEventSource;
const request = (extra: Record<string, unknown> = {}) => ({
  type: ACCOUNT_SETUP_REQUEST, requestId: 'req_1', protocolVersion: 1, keyId: 'key_1', ...extra,
});

describe('the account setup request', () => {
  it('is taken only from the counterparty window at its exact origin', () => {
    expect(readAccountSetupRequest({ origin: APP, source: opener, data: request() }, APP, opener, false))
      .toEqual({ requestId: 'req_1', protocolVersion: 1, keyId: 'key_1', requester: APP });
    expect(readAccountSetupRequest({ origin: 'https://evil.example', source: opener, data: request() }, APP, opener, false)).toBeNull();
    expect(readAccountSetupRequest({ origin: APP, source: {} as MessageEventSource, data: request() }, APP, opener, false)).toBeNull();
    expect(readAccountSetupRequest({ origin: APP, source: opener, data: request() }, null, opener, false)).toBeNull();
    expect(readAccountSetupRequest({ origin: APP, source: opener, data: request({ protocolVersion: 2 }) }, APP, opener, false)).toBeNull();
  });

  it("names the app's own origin, never one the app's message claims", () => {
    const read = readAccountSetupRequest({ origin: APP, source: opener, data: request({ requestOrigin: 'https://other.example' }) }, APP, opener, false);
    expect(read?.requester).toBe(APP);
  });

  it('from an OpenKey hand-off, names the app the hand-off verified, which must be an exact origin', () => {
    const relayed = (requestOrigin: unknown) =>
      readAccountSetupRequest({ origin: OPENKEY, source: opener, data: request({ requestOrigin }) }, OPENKEY, opener, true);
    expect(relayed(APP)?.requester).toBe(APP);
    for (const bad of [undefined, '*', 'null', `${APP}/path`, 'not a url']) expect(relayed(bad)).toBeNull();
  });
});

describe('the answer to the app', () => {
  const read = { requestId: 'req_1', protocolVersion: 1 as const, keyId: 'key_1', requester: APP };

  it('carries the outcome and the request correlation only', () => {
    expect(accountSetupSuccess(read, 'published')).toEqual({
      type: ACCOUNT_SETUP_RESPONSE, requestId: 'req_1', protocolVersion: 1, success: true, outcome: 'published',
    });
  });

  it('points an unavailable setup at TinyCloud One', () => {
    expect(accountSetupFailure(read, 'ACCOUNT_SETUP_UNAVAILABLE', 'x').error).toEqual({
      code: 'ACCOUNT_SETUP_UNAVAILABLE', message: 'x', setupUrl: TINYCLOUD_ONE_SETUP_URL,
    });
    expect(accountSetupFailure(read, 'USER_CANCELLED', 'x').error).toEqual({ code: 'USER_CANCELLED', message: 'x' });
  });

  it("relays the setup window's answer, a blocked window as a setup that did not finish", () => {
    expect(accountSetupAnswer(read, { success: true, outcome: 'present' })).toMatchObject({ success: true, outcome: 'present' });
    expect(accountSetupAnswer(read, { success: false, error: { code: 'POPUP_BLOCKED', message: 'blocked' } }))
      .toMatchObject({ success: false, error: { code: 'ACCOUNT_SETUP_FAILED' } });
  });
});

describe('a host-signing refusal from prepare', () => {
  it('says whether the account needs setup, offering setup only for an app with an exact origin', () => {
    const refusal = (extra: Record<string, unknown>) => Object.assign(new Error('refused'), { status: 403, ...extra });
    const required = refusal({ code: 'host_signing_first_party_only', accountSetup: 'required' });
    expect(hostSigningRefusal(required, APP)).toBe('setup');
    for (const origin of ['*', null, `${APP}/path`]) expect(hostSigningRefusal(required, origin)).toBe('refused');
    expect(hostSigningRefusal(refusal({ code: 'host_signing_first_party_only' }), APP)).toBe('refused');
    expect(hostSigningRefusal(refusal({ code: 'other', accountSetup: 'required' }), APP)).toBeNull();
    expect(hostSigningRefusal({ code: 'host_signing_first_party_only', accountSetup: 'required' }, APP)).toBeNull();
  });
});

describe('the OpenKey hand-off to the setup window', () => {
  const previous = globalThis.window;
  afterEach(() => { (globalThis as { window?: unknown }).window = previous; });

  function fakeWindow(popup: { closed: boolean; postMessage: (data: unknown, origin: string) => void } | null) {
    const listeners = new Set<(event: unknown) => void>();
    (globalThis as { window?: unknown }).window = {
      location: { origin: OPENKEY },
      open: () => popup,
      addEventListener: (type: string, listener: (event: unknown) => void) => { if (type === 'message') listeners.add(listener); },
      removeEventListener: (type: string, listener: (event: unknown) => void) => { listeners.delete(listener); },
    };
    return (event: { origin: string; source: unknown; data: unknown }) => { for (const listener of [...listeners]) listener(event); };
  }

  it("sends the verified app on each ready and takes only its own request's answer from the window", async () => {
    const posted: { data: Record<string, unknown>; origin: string }[] = [];
    const popup = { closed: false, postMessage: (data: unknown, origin: string) => { posted.push({ data: data as Record<string, unknown>, origin }); } };
    const send = fakeWindow(popup);
    const result = openAccountSetupWindow({ keyId: 'key_1', requestOrigin: APP });
    send({ origin: OPENKEY, source: popup, data: { type: 'openkey:ready' } });
    // A sign-in in the window reloads it: the same request a second time.
    send({ origin: OPENKEY, source: popup, data: { type: 'openkey:ready' } });
    expect(posted).toHaveLength(2);
    expect(posted[0]!.origin).toBe(OPENKEY);
    expect(posted[0]!.data).toMatchObject({ type: ACCOUNT_SETUP_REQUEST, protocolVersion: 1, keyId: 'key_1', requestOrigin: APP });
    expect(posted[1]!.data.requestId).toBe(posted[0]!.data.requestId);
    const requestId = posted[0]!.data.requestId;

    const answer = { type: ACCOUNT_SETUP_RESPONSE, requestId, protocolVersion: 1, success: true, outcome: 'published' };
    send({ origin: APP, source: popup, data: { ...answer, outcome: 'present' } });
    send({ origin: OPENKEY, source: {}, data: { ...answer, outcome: 'present' } });
    send({ origin: OPENKEY, source: popup, data: { ...answer, requestId: 'other', outcome: 'present' } });
    send({ origin: OPENKEY, source: popup, data: answer });
    expect(await result).toEqual({ success: true, outcome: 'published' });
  });

  it('reports a blocked window without waiting', async () => {
    fakeWindow(null);
    expect(await openAccountSetupWindow({ keyId: null, requestOrigin: APP })).toMatchObject({
      success: false, error: { code: 'POPUP_BLOCKED' },
    });
  });

  it('closes the setup window once it answers, not before', async () => {
    let requestId: unknown;
    let closes = 0;
    const popup = {
      closed: false,
      postMessage: (data: unknown) => { if (data && typeof data === 'object' && 'requestId' in data) requestId = data.requestId; },
      close: () => { closes++; },
    };
    const send = fakeWindow(popup);
    const result = openAccountSetupWindow({ keyId: 'key_1', requestOrigin: APP });
    send({ origin: OPENKEY, source: popup, data: { type: 'openkey:ready' } });
    send({ origin: OPENKEY, source: popup, data: { type: ACCOUNT_SETUP_RESPONSE, requestId: 'other', protocolVersion: 1, success: true, outcome: 'published' } });
    expect(closes).toBe(0);
    send({ origin: OPENKEY, source: popup, data: { type: ACCOUNT_SETUP_RESPONSE, requestId, protocolVersion: 1, success: true, outcome: 'published' } });
    expect(await result).toEqual({ success: true, outcome: 'published' });
    expect(closes).toBe(1);
  });
});
