// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { test, expect } from 'bun:test';
import { legacySignOrigin, legacySignReadyOrigin } from './legacy-sign-origin';

test('legacy sign accepts only HTTP(S) destinations', () => {
  for (const value of ['null', '', '*', 'file:///caller', 'data:text/html,caller', 'invalid']) {
    expect(legacySignOrigin(value)).toBeNull();
  }
  expect(legacySignOrigin('https://app.example/path')).toBe('https://app.example');
  expect(legacySignOrigin('http://localhost:8080')).toBe('http://localhost:8080');
});

test('legacy ready prefers the nearest ancestor and falls back to browser referrer', () => {
  const previousWindow = globalThis.window;
  const previousDocument = globalThis.document;
  try {
    const browser: any = { parent: {}, location: { ancestorOrigins: ['https://parent.example', 'https://top.example'] } };
    (globalThis as any).window = browser;
    (globalThis as any).document = { referrer: 'https://referrer.example/path' };
    expect(legacySignReadyOrigin()).toBe('https://parent.example');
    browser.location.ancestorOrigins = [];
    expect(legacySignReadyOrigin()).toBe('https://referrer.example');
    browser.parent = browser; // popup: do not use ancestor metadata
    browser.location.ancestorOrigins = ['https://irrelevant.example'];
    expect(legacySignReadyOrigin()).toBe('https://referrer.example');
    (globalThis as any).document.referrer = '';
    expect(legacySignReadyOrigin()).toBeNull();
  } finally {
    (globalThis as any).window = previousWindow;
    (globalThis as any).document = previousDocument;
  }
});
