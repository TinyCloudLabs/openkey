// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  loadOAuthClientBrand,
  normalizeOAuthClientBrand,
  OAuthClientBrandLoadError,
} from './oauth-client-brand';

describe('normalizeOAuthClientBrand', () => {
  test('normalizes Better Auth and OpenKey public client field names', () => {
    expect(normalizeOAuthClientBrand({
      client_name: 'Shape Rotator',
      client_uri: 'https://shape.example',
      logo_uri: 'https://shape.example/logo.png',
    })).toEqual({
      name: 'Shape Rotator',
      uri: 'https://shape.example',
      icon: 'https://shape.example/logo.png',
    });
    expect(normalizeOAuthClientBrand({
      name: 'Shape Rotator', uri: 'https://shape.example', icon: 'https://shape.example/logo.png',
    })).toEqual({
      name: 'Shape Rotator', uri: 'https://shape.example', icon: 'https://shape.example/logo.png',
    });
  });

  test('does not create a brand from unusable public-client responses', () => {
    expect(normalizeOAuthClientBrand(null)).toBeNull();
    expect(normalizeOAuthClientBrand({ client_name: '  ' })).toBeNull();
    expect(normalizeOAuthClientBrand({ client_name: 'Shape Rotator', disabled: true })).toBeNull();
  });

  test('preserves the server error detail when the consent page cannot load a client', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response(
      JSON.stringify({ message: 'This application is disabled' }),
      { status: 403, headers: { 'Content-Type': 'application/json' } },
    )) as typeof fetch;
    try {
      await expect(loadOAuthClientBrand('shape-rotator')).rejects.toEqual(
        expect.objectContaining({
          name: OAuthClientBrandLoadError.name,
          message: 'This application is disabled',
        }),
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
