// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import { connectAuthResponse } from './connect-widget';
import { parseCanonicalOrigin } from './nostr-origin';
import { resolveWidgetOrigin } from './widget-transport';

const routes = new URL('../routes/widget/', import.meta.url);
const source = (path: string) => readFileSync(new URL(path, routes), 'utf8');

describe('connect widget response (TC-688)', () => {
  it('carries the selected key and no session token', () => {
    const response = connectAuthResponse({ address: '0xabc', id: 'key_1', keyType: 'MANAGED' });
    expect(response).toEqual({
      type: 'openkey:auth:response',
      success: true,
      address: '0xabc',
      keyId: 'key_1',
      keyType: 'MANAGED',
    });
    expect(response).not.toHaveProperty('sessionToken');
  });

  for (const path of ['embed/connect/+page.svelte', 'connect/+page.svelte']) {
    it(`is what ${path} posts to the requesting page`, () => {
      const page = source(path);
      expect(page).toContain('sendResponse(connectAuthResponse(key))');
      expect(page).not.toMatch(/response\.sessionToken|sessionToken:\s*token/);
    });
  }
});

describe('widget targets (TC-688, TC-690)', () => {
  for (const path of [
    'embed/connect/+page.svelte',
    'connect/+page.svelte',
    'embed/sign-typed-data/+page.svelte',
    'sign-typed-data/+page.svelte',
  ]) {
    it(`${path} never posts to '*' and checks message origin and source`, () => {
      const page = source(path);
      expect(page).not.toMatch(/postMessage\([^)]*'\*'\)/);
      expect(page).not.toContain("|| '*'");
      expect(page).toContain('resolveWidgetOrigin(');
      expect(page).toContain('if (!isFromWidgetCounterparty(event, origin,');
    });
  }

  for (const path of ['embed/sign-typed-data/+page.svelte', 'embed/sign/+page.svelte']) {
    it(`${path} does not adopt a session token from a message`, () => {
      expect(source(path)).not.toContain('setSessionToken');
    });
  }

  for (const path of ['embed/sign-out/+page.svelte', 'sign-out/+page.svelte']) {
    it(`${path} revokes OpenKey's own session, not one from the request`, () => {
      const page = source(path);
      expect(page).toContain('revokeEmbeddedSession()');
      expect(page).not.toContain('request.sessionToken');
    });
  }
});

// Desktop apps (Tauri / WKWebView) embed OpenKey from an app-scheme origin
// such as `tauri://localhost`. Connect accepted it, but sign-out parsed the
// origin with the http(s)-only Nostr parser, never sent `openkey:ready`, and
// the SDK fell back to a popup the webview cannot open.
describe('sign-out widget origin matches connect', () => {
  for (const path of ['embed/sign-out/+page.svelte', 'sign-out/+page.svelte']) {
    it(`${path} resolves ?origin= the same way the connect widget does`, () => {
      const page = source(path);
      expect(page).toContain("const origin = resolveWidgetOrigin($page.url.searchParams.get('origin'));");
      expect(page).not.toContain('parseCanonicalOrigin');
    });
  }

  it('the http(s)-only parser rejects an app-scheme origin', () => {
    expect(parseCanonicalOrigin('tauri://localhost')).toBeNull();
  });

  it('accepts an app-scheme origin when the engine gives it a tuple origin (WKWebView registered scheme)', () => {
    const NativeURL = globalThis.URL;
    class WebKitRegisteredSchemeURL extends NativeURL {
      get origin() {
        return this.protocol === 'tauri:' ? `${this.protocol}//${this.host}` : super.origin;
      }
    }
    globalThis.URL = WebKitRegisteredSchemeURL as typeof URL;
    try {
      expect(resolveWidgetOrigin('tauri://localhost')).toBe('tauri://localhost');
      expect(resolveWidgetOrigin('tauri://localhost/')).toBeNull();
    } finally {
      globalThis.URL = NativeURL;
    }
  });
});
