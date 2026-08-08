// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { normalizeOAuthClientBrand } from './oauth-client-brand';

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
});
