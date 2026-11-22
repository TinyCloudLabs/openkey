// TC-3893: SDK unit tests for OpenKey.requestRegistryChange and OpenKey.requestRegistryUndo
// in both popup and iframe modes.
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

  test('iframe mode opens /widget/embed/registry-change and resolves published', async () => {
    const posted: Array<{ msg: any; targetOrigin: string }> = [];
    let iframeSrc = '';
    const iframeContentWindow = {
      postMessage(msg: any, targetOrigin: string) { posted.push({ msg, targetOrigin }); },
    };

    const makeEl = (tag: string) => {
      const el: any = {
        tagName: tag.toUpperCase(),
        style: {},
        className: '',
        textContent: '',
        children: [] as any[],
        attributes: {} as Record<string, string>,
        classList: { add() {}, remove() {} },
        setAttribute(k: string, v: string) { el.attributes[k] = v; },
        addEventListener() {},
        appendChild(child: any) { el.children.push(child); return child; },
        remove() {},
        attachShadow() { return { appendChild() {}, querySelector: () => null }; },
      };
      if (tag === 'iframe') {
        Object.defineProperty(el, 'src', {
          get: () => iframeSrc,
          set: (v: string) => { iframeSrc = v; },
        });
        el.contentWindow = iframeContentWindow;
      }
      return el;
    };

    (globalThis as { document?: unknown }).document = {
      createElement: makeEl,
      body: { appendChild() {} },
    };
    (globalThis as { window?: unknown }).window = {
      location: { origin: APP_ORIGIN },
      innerHeight: 900,
      matchMedia: () => ({ matches: false }),
      navigator: { userAgent: 'Mozilla/5.0 Chrome/130.0.0.0' },
      dispatchEvent: () => true,
      addEventListener: (type: string, fn: Listener) => { if (type === 'message') listeners.push(fn); },
      removeEventListener: (type: string, fn: Listener) => { if (type === 'message') listeners = listeners.filter((l) => l !== fn); },
    };

    const ok = new OpenKey({ host: HOST, mode: 'iframe' });
    const promise = ok.requestRegistryChange({ nodes: [{ url: 'https://node-b.example' }] });

    expect(iframeSrc).toBe(`${HOST}/widget/embed/registry-change?origin=${encodeURIComponent(APP_ORIGIN)}`);

    dispatchWindowMessage({ origin: HOST, source: iframeContentWindow, data: { type: 'openkey:ready', protocolVersion: 1 } });
    expect(posted).toHaveLength(1);
    const requestId = posted[0]?.msg.requestId as string;

    dispatchWindowMessage({
      origin: HOST,
      source: iframeContentWindow,
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
