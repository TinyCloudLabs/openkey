// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import { connectAuthResponse } from './connect-widget';

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

  it('is what the embedded connect widget posts to the embedding page', () => {
    const page = source('embed/connect/+page.svelte');
    expect(page).toContain('sendResponse(connectAuthResponse(key))');
    expect(page).not.toMatch(/response\.sessionToken|sessionToken:\s*token/);
  });
});

describe('widget targets (TC-688, TC-690)', () => {
  for (const path of [
    'embed/connect/+page.svelte',
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

  it('the embedded sign-typed-data widget does not adopt a message session token', () => {
    expect(source('embed/sign-typed-data/+page.svelte')).not.toContain('setSessionToken');
  });
});
