import { describe, expect, test } from 'bun:test';
import {
  validateOAuthClientMetadataUrl,
  validateCoordinationosWebRedirectUris,
  validateOAuthRedirectUri,
  validateOAuthRedirectUris,
} from '../services/oauth-redirect-uris';

describe('OAuth redirect URI policy', () => {
  test('accepts HTTPS and loopback HTTP callbacks for browser applications', () => {
    expect(validateOAuthRedirectUri('https://app.example/callback?flow=oauth', 'spa').valid).toBe(true);
    expect(validateOAuthRedirectUri('http://localhost:5173/callback', 'spa').valid).toBe(true);
    expect(validateOAuthRedirectUri('http://127.0.0.1:43123/callback', 'spa').valid).toBe(true);
    expect(validateOAuthRedirectUri('http://[::1]:43123/callback', 'spa').valid).toBe(true);
  });

  test('rejects executable, local-file, credentialed, fragmented, and remote HTTP callbacks', () => {
    for (const value of [
      'javascript:alert(1)',
      'data:text/html,owned',
      'file:///tmp/callback',
      'https://user:password@app.example/callback',
      'https://app.example/callback#token',
      'http://app.example/callback',
    ]) {
      expect(validateOAuthRedirectUri(value, 'spa').valid).toBe(false);
    }
  });

  test('allows narrowly scoped reverse-domain native schemes', () => {
    expect(validateOAuthRedirectUri('com.example.product:/oauth/callback', 'native').valid).toBe(true);
    expect(validateOAuthRedirectUri('com.example.product://oauth/callback', 'native').valid).toBe(true);
    expect(validateOAuthRedirectUri('https://app.example/native-callback', 'native').valid).toBe(true);
    expect(validateOAuthRedirectUri('myapp://auth/callback', 'native').valid).toBe(true);
    expect(validateOAuthRedirectUri('mailto:user@example.com', 'native').valid).toBe(false);
    expect(validateOAuthRedirectUri('com.example.product:callback', 'native').valid).toBe(false);
  });

  test('validates every entry in a redirect URI collection', () => {
    expect(validateOAuthRedirectUris([
      'https://app.example/callback',
      'http://localhost:5173/callback',
    ], 'spa').valid).toBe(true);
    expect(validateOAuthRedirectUris([
      'https://app.example/callback',
      'data:text/html,owned',
    ], 'spa').valid).toBe(false);
  });

  test('restricts application and icon URLs to non-credentialed HTTP(S)', () => {
    expect(validateOAuthClientMetadataUrl('https://app.example').valid).toBe(true);
    expect(validateOAuthClientMetadataUrl('http://localhost:5173/icon.png').valid).toBe(true);
    expect(validateOAuthClientMetadataUrl('javascript:alert(1)').valid).toBe(false);
    expect(validateOAuthClientMetadataUrl('data:image/svg+xml,owned').valid).toBe(false);
  });

  test('accepts only the exact configured CoordinationOS callback', () => {
    const callback = 'https://coordination.example/auth/v1/callback';
    expect(validateCoordinationosWebRedirectUris([callback], callback).valid).toBe(true);
    for (const value of [
      `${callback}?`,
      `${callback}?next=/`,
      `${callback}#`,
      `${callback}#fragment`,
      'https://@coordination.example/auth/v1/callback',
      'https://coordination.example.evil.test/auth/v1/callback',
      'https://user:pass@coordination.example/auth/v1/callback',
      'http://coordination.example/auth/v1/callback',
      'com.example.app:/auth/v1/callback',
    ]) {
      expect(validateCoordinationosWebRedirectUris([value], callback).valid).toBe(false);
    }
    expect(validateCoordinationosWebRedirectUris([], callback).valid).toBe(false);
    expect(validateCoordinationosWebRedirectUris([callback, callback], callback).valid).toBe(false);
  });

  test('permits only the three exact loopback host spellings for development', () => {
    for (const callback of [
      'http://localhost:54321/auth/v1/callback',
      'http://127.0.0.1/auth/v1/callback',
      'http://[::1]:54321/auth/v1/callback',
    ]) {
      expect(validateCoordinationosWebRedirectUris([callback], callback).valid).toBe(true);
    }
    for (const callback of [
      'http://dev.localhost/auth/v1/callback',
      'http://127.0.0.2/auth/v1/callback',
      'http://127.1/auth/v1/callback',
    ]) {
      expect(validateCoordinationosWebRedirectUris([callback], callback).valid).toBe(false);
    }
  });
});
