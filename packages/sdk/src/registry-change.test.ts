// TC-3893: SDK unit tests for OpenKey.requestRegistryChange and OpenKey.requestRegistryUndo
// (N1 popup-only: always opens /widget/registry-change, ignoring mode:'iframe').
// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { OpenKey } from './index';

type Listener = (event: MessageEvent) => void;

const HOST = 'https://openkey.example';
const APP_ORIGIN = 'https://app.example';

let listeners: Listener[] = [];
const originalWindow = (globalThis as { window?: unknown }).window;
const originalDocument = (globalThis as { document?: unknown }).document;

function dispatchWindowMessage(event: { origin: string; source: unknown; data: unknown }) {
  for (const listener of [...listeners]) {
    listener(event as MessageEvent);
  }
}

beforeEach(() => {
  listeners = [];
});

afterEach(() => {
  if (originalWindow === undefined) delete (globalThis as { window?: unknown }).window;
  else (globalThis as { window?: unknown }).window = originalWindow;
  if (originalDocument === undefined) delete (globalThis as { document?: unknown }).document;
  else (globalThis as { document?: unknown }).document = originalDocument;
});

describe('OpenKey.requestRegistryChange', () => {
  test('popup mode opens /widget/registry-change, correlates requestId, and resolves published', async () => {
    const posted: Array<{ msg: any; targetOrigin: string }> = [];
    const openedUrls: string[] = [];
    const popupWindow = {
      closed: false,
      location: { href: '' },
      close() { this.closed = true; },
      postMessage(msg: any, targetOrigin: string) {
        posted.push({ msg, targetOrigin });
      },
    };
    Object.defineProperty(popupWindow.location, 'href', {
      set(val: string) { openedUrls.push(val); },
      get() { return openedUrls.at(-1) ?? ''; },
    });

    (globalThis as { window?: unknown }).window = {
      location: { origin: APP_ORIGIN },
      screenX: 0,
      screenY: 0,
      outerWidth: 1200,
      outerHeight: 800,
      innerHeight: 800,
      navigator: { userAgent: 'Mozilla/5.0 Chrome/130.0.0.0' },
      open: () => popupWindow,
      dispatchEvent: () => true,
      addEventListener: (type: string, fn: Listener) => { if (type === 'message') listeners.push(fn); },
      removeEventListener: (type: string, fn: Listener) => { if (type === 'message') listeners = listeners.filter((l) => l !== fn); },
    };

    const ok = new OpenKey({ host: HOST, mode: 'popup' });
    const promise = ok.requestRegistryChange({
      nodes: [{ url: 'https://node-b.example:8443' }],
      encryptionNode: 'https://node-b.example:8443',
    });

    expect(openedUrls[0]).toBe(`${HOST}/widget/registry-change?origin=${encodeURIComponent(APP_ORIGIN)}`);

    dispatchWindowMessage({ origin: HOST, source: popupWindow, data: { type: 'openkey:ready', protocolVersion: 1 } });
    expect(posted).toHaveLength(1);
    expect(posted[0]?.targetOrigin).toBe(HOST);
    expect(posted[0]?.msg.type).toBe('openkey:registry-change:request');
    expect(posted[0]?.msg.protocolVersion).toBe(1);
    const requestId = posted[0]?.msg.requestId as string;

    // Wrong requestId is dropped.
    dispatchWindowMessage({
      origin: HOST,
      source: popupWindow,
      data: {
        type: 'openkey:registry-change:response',
        requestId: 'other-id',
        protocolVersion: 1,
        success: true,
        status: 'published',
        sequence: 99,
        recordHash: 'f'.repeat(64),
      },
    });

    // Matching requestId resolves.
    dispatchWindowMessage({
      origin: HOST,
      source: popupWindow,
      data: {
        type: 'openkey:registry-change:response',
        requestId,
        protocolVersion: 1,
        success: true,
        status: 'published',
        sequence: 5,
        recordHash: 'a'.repeat(64),
      },
    });

    expect(await promise).toEqual({
      status: 'published',
      sequence: 5,
      recordHash: 'a'.repeat(64),
    });
    expect(popupWindow.closed).toBe(true);
  });

  test('popup close resolves { status: "cancelled" }', async () => {
    const posted: Array<{ msg: any; targetOrigin: string }> = [];
    const popupWindow = {
      closed: false,
      location: { href: '' },
      close() { this.closed = true; },
      postMessage(msg: any, targetOrigin: string) { posted.push({ msg, targetOrigin }); },
    };

    (globalThis as { window?: unknown }).window = {
      location: { origin: APP_ORIGIN },
      screenX: 0,
      screenY: 0,
      outerWidth: 1200,
      outerHeight: 800,
      innerHeight: 800,
      navigator: { userAgent: 'Mozilla/5.0 Chrome/130.0.0.0' },
      open: () => popupWindow,
      dispatchEvent: () => true,
      addEventListener: (type: string, fn: Listener) => { if (type === 'message') listeners.push(fn); },
      removeEventListener: (type: string, fn: Listener) => { if (type === 'message') listeners = listeners.filter((l) => l !== fn); },
    };

    const ok = new OpenKey({ host: HOST, mode: 'popup' });
    const promise = ok.requestRegistryChange({ nodes: [{ url: 'https://node-b.example' }] });
    dispatchWindowMessage({ origin: HOST, source: popupWindow, data: { type: 'openkey:ready', protocolVersion: 1 } });
    const requestId = posted[0]?.msg.requestId as string;

    dispatchWindowMessage({
      origin: HOST,
      source: popupWindow,
      data: {
        type: 'openkey:registry-change:response',
        requestId,
        protocolVersion: 1,
        success: true,
        status: 'cancelled',
      },
    });

    expect(await promise).toEqual({ status: 'cancelled' });
  });

  test('N1: mode:"iframe" (instance and per-call) is ignored and always opens the /widget/registry-change popup', async () => {
    const posted: Array<{ msg: any; targetOrigin: string }> = [];
    const openedUrls: string[] = [];
    let iframeCreated = false;
    const makePopupWindow = () => {
      const win = {
        closed: false,
        location: { href: '' },
        close() { this.closed = true; },
        postMessage(msg: any, targetOrigin: string) { posted.push({ msg, targetOrigin }); },
      };
      Object.defineProperty(win.location, 'href', {
        set(val: string) { openedUrls.push(val); },
        get() { return openedUrls.at(-1) ?? ''; },
      });
      return win;
    };
    const popups: ReturnType<typeof makePopupWindow>[] = [];

    (globalThis as { document?: unknown }).document = {
      createElement: (tag: string) => {
        if (tag === 'iframe') iframeCreated = true;
        throw new Error(`Unexpected DOM element created in popup-only flow: ${tag}`);
      },
      body: { appendChild() {} },
    };
    (globalThis as { window?: unknown }).window = {
      location: { origin: APP_ORIGIN },
      screenX: 0,
      screenY: 0,
      outerWidth: 1200,
      outerHeight: 800,
      innerHeight: 800,
      navigator: { userAgent: 'Mozilla/5.0 Chrome/130.0.0.0' },
      open: () => {
        const win = makePopupWindow();
        popups.push(win);
        return win;
      },
      dispatchEvent: () => true,
      addEventListener: (type: string, fn: Listener) => { if (type === 'message') listeners.push(fn); },
      removeEventListener: (type: string, fn: Listener) => { if (type === 'message') listeners = listeners.filter((l) => l !== fn); },
    };

    const ok = new OpenKey({ host: HOST, mode: 'iframe' });
    const promise = ok.requestRegistryChange(
      { nodes: [{ url: 'https://node-b.example' }] },
      { mode: 'iframe' },
    );
    const popup1 = popups[0]!;

    expect(iframeCreated).toBe(false);
    expect(openedUrls[0]).toBe(`${HOST}/widget/registry-change?origin=${encodeURIComponent(APP_ORIGIN)}`);

    dispatchWindowMessage({ origin: HOST, source: popup1, data: { type: 'openkey:ready', protocolVersion: 1 } });
    expect(posted).toHaveLength(1);
    const requestId = posted[0]?.msg.requestId as string;

    dispatchWindowMessage({
      origin: HOST,
      source: popup1,
      data: {
        type: 'openkey:registry-change:response',
        requestId,
        protocolVersion: 1,
        success: true,
        status: 'published',
        sequence: 7,
        recordHash: 'c'.repeat(64),
      },
    });

    expect(await promise).toEqual({
      status: 'published',
      sequence: 7,
      recordHash: 'c'.repeat(64),
    });

    // Undo also ignores mode:'iframe' and uses the popup.
    const undoPromise = ok.requestRegistryUndo({ historyId: 'hist-iframe-ignored' }, { mode: 'iframe' });
    const popup2 = popups[1]!;
    expect(iframeCreated).toBe(false);
    expect(openedUrls.at(-1)).toBe(`${HOST}/widget/registry-change?origin=${encodeURIComponent(APP_ORIGIN)}`);
    dispatchWindowMessage({ origin: HOST, source: popup2, data: { type: 'openkey:ready', protocolVersion: 1 } });
    const undoRequestId = posted.at(-1)?.msg.requestId as string;
    dispatchWindowMessage({
      origin: HOST,
      source: popup2,
      data: {
        type: 'openkey:registry-change:response',
        requestId: undoRequestId,
        protocolVersion: 1,
        success: true,
        status: 'cancelled',
      },
    });
    expect(await undoPromise).toEqual({ status: 'cancelled' });
  });

  test('requestRegistryUndo sends openkey:registry-undo:request with historyId and resolves published', async () => {
    const posted: Array<{ msg: any; targetOrigin: string }> = [];
    const popupWindow = {
      closed: false,
      location: { href: '' },
      close() { this.closed = true; },
      postMessage(msg: any, targetOrigin: string) { posted.push({ msg, targetOrigin }); },
    };

    (globalThis as { window?: unknown }).window = {
      location: { origin: 'https://tinycloud.one' },
      screenX: 0,
      screenY: 0,
      outerWidth: 1200,
      outerHeight: 800,
      innerHeight: 800,
      navigator: { userAgent: 'Mozilla/5.0 Chrome/130.0.0.0' },
      open: () => popupWindow,
      dispatchEvent: () => true,
      addEventListener: (type: string, fn: Listener) => { if (type === 'message') listeners.push(fn); },
      removeEventListener: (type: string, fn: Listener) => { if (type === 'message') listeners = listeners.filter((l) => l !== fn); },
    };

    const ok = new OpenKey({ host: HOST, mode: 'popup' });
    const promise = ok.requestRegistryUndo({ historyId: 'hist-42' });
    dispatchWindowMessage({ origin: HOST, source: popupWindow, data: { type: 'openkey:ready', protocolVersion: 1 } });

    expect(posted).toHaveLength(1);
    expect(posted[0]?.msg.type).toBe('openkey:registry-undo:request');
    expect(posted[0]?.msg.historyId).toBe('hist-42');
    const requestId = posted[0]?.msg.requestId as string;

    dispatchWindowMessage({
      origin: HOST,
      source: popupWindow,
      data: {
        type: 'openkey:registry-change:response',
        requestId,
        protocolVersion: 1,
        success: true,
        status: 'published',
        sequence: 8,
        recordHash: 'd'.repeat(64),
      },
    });

    expect(await promise).toEqual({
      status: 'published',
      sequence: 8,
      recordHash: 'd'.repeat(64),
    });
  });
});
