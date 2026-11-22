// A framed page holds a session token and no cookie, and the Terms screen needs the cookie session. Refused for
// the Terms, a frame stays where it is and raises `framedTermsRequired`; a tab still goes to the Terms screen.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { get } from 'svelte/store';
import { api } from './api';
import { framedTermsRequired } from './terms';

const realFetch = globalThis.fetch;
const realSession = (globalThis as { sessionStorage?: unknown }).sessionStorage;
const realWindow = (globalThis as { window?: unknown }).window;
let assigned: string[] = [];

function windowAt(framed: boolean) {
  const win: { self: unknown; top: unknown; location: Record<string, unknown> } = {
    self: {},
    top: {},
    location: { pathname: '/widget/embed/connect', search: '?origin=https%3A%2F%2Fapp.example', hash: '', assign: (url: string) => assigned.push(url) },
  };
  if (!framed) win.top = win.self;
  return win;
}

beforeEach(() => {
  assigned = [];
  framedTermsRequired.set(false);
  (globalThis as { sessionStorage?: unknown }).sessionStorage = { getItem: () => 'tok', setItem: () => {}, removeItem: () => {} };
  globalThis.fetch = (async () =>
    new Response(JSON.stringify({ error: 'terms_required' }), { status: 403, headers: { 'content-type': 'application/json' } })) as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
  (globalThis as { sessionStorage?: unknown }).sessionStorage = realSession;
  (globalThis as { window?: unknown }).window = realWindow;
});

describe('a call refused for the Terms', () => {
  test('in a frame raises the notice and leaves the frame where it is', async () => {
    (globalThis as { window?: unknown }).window = windowAt(true);
    await expect(api.listKeys()).rejects.toThrow();
    expect(get(framedTermsRequired)).toBe(true);
    expect(assigned).toEqual([]);
  });

  test('in a tab goes to the Terms screen and returns to the page', async () => {
    (globalThis as { window?: unknown }).window = windowAt(false);
    await expect(api.listKeys()).rejects.toThrow();
    expect(get(framedTermsRequired)).toBe(false);
    expect(assigned).toEqual(['/auth/terms?returnTo=%2Fwidget%2Fembed%2Fconnect%3Forigin%3Dhttps%253A%252F%252Fapp.example']);
  });
});
