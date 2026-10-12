// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import {
  loadNativeBranding, nativeLoginHint, nativeOtpSentKey, nativeSignIn, nativeSocialReturnUrls, parseNativeBranding,
} from './native-mode';

const signed = (extra: Record<string, string> = {}) => new URLSearchParams({
  response_type: 'code', client_id: 'exo-native', redirect_uri: 'xyz.tinycloud.exo://cb', scope: 'openid',
  tinycloud_request: 'req-1', ...extra, exp: '9999999999', ba_iat: '1', sig: 'signed',
});

describe('nativeSignIn', () => {
  test('is off without tinycloud_request', () => {
    const params = signed();
    params.delete('tinycloud_request');
    expect(nativeSignIn(params)).toBeNull();
  });

  test('is off without a client_id', () => {
    expect(nativeSignIn(new URLSearchParams({ tinycloud_request: 'req-1', sig: 'signed' }))).toBeNull();
  });

  test('reads the request, client and the signed query', () => {
    const native = nativeSignIn(signed());
    expect(native).toMatchObject({ requestId: 'req-1', clientId: 'exo-native', method: null, hint: null, socialError: false });
    expect(new URLSearchParams(native!.signedQuery).get('sig')).toBe('signed');
  });

  test('an email hint without a method selects the OTP step for that email', () => {
    expect(nativeSignIn(signed({ login_hint: 'Sam@Example.test' }))).toMatchObject({ method: 'email', hint: 'sam@example.test' });
  });

  test('passkey and google ignore the hint', () => {
    expect(nativeSignIn(signed({ login_method: 'passkey', login_hint: 'sam@example.test' }))).toMatchObject({ method: 'passkey', hint: null });
    expect(nativeSignIn(signed({ login_method: 'google', login_hint: 'sam@example.test' }))).toMatchObject({ method: 'google', hint: null });
  });

  test('an unknown method is dropped', () => {
    expect(nativeSignIn(signed({ login_method: 'carrier-pigeon' }))?.method).toBeNull();
  });

  test('a malformed hint is dropped', () => {
    expect(nativeSignIn(signed({ login_method: 'email', login_hint: 'not-an-email' }))).toMatchObject({ method: 'email', hint: null });
  });

  test('"Not you?" drops the signed hints but keeps the request', () => {
    const params = signed({ login_method: 'email', login_hint: 'sam@example.test' });
    params.set('native_switch', '1');
    expect(nativeSignIn(params)).toMatchObject({ requestId: 'req-1', method: null, hint: null });
  });

  test('flags the Google error return', () => {
    const params = signed({ login_method: 'google' });
    params.set('native_social_error', '1');
    expect(nativeSignIn(params)?.socialError).toBe(true);
  });
});

describe('nativeLoginHint', () => {
  test('applies the API shape rules', () => {
    expect(nativeLoginHint(' a@b.co ')).toBe('a@b.co');
    expect(nativeLoginHint('a b@c.co')).toBeNull();
    expect(nativeLoginHint('a@@c.co')).toBeNull();
    expect(nativeLoginHint('@c.co')).toBeNull();
    expect(nativeLoginHint(`${'a'.repeat(250)}@b.co`)).toBeNull();
    expect(nativeLoginHint(null)).toBeNull();
  });
});

describe('nativeSocialReturnUrls', () => {
  test('both return to the login page with the signed query; only the error one carries the marker', () => {
    const { callbackURL, errorCallbackURL } = nativeSocialReturnUrls('https://openkey.so', 'client_id=a&sig=b');
    expect(callbackURL).toBe('https://openkey.so/auth/login?client_id=a&sig=b');
    expect(errorCallbackURL).toBe('https://openkey.so/auth/login?client_id=a&sig=b&native_social_error=1');
  });
});

test('the OTP-sent marker is per request', () => {
  expect(nativeOtpSentKey('a')).not.toBe(nativeOtpSentKey('b'));
});

describe('branding', () => {
  const body = {
    clientId: 'exo-native', name: 'Exo', icon: 'https://tinycloud.chat/icons/pwa-512.png', organization: 'TinyCloud Labs',
    theme: { backgroundColor: '#09090B', accentColor: '#FAFAFA' },
  };

  test('parses the C2 shape and validates colours and icon', () => {
    expect(parseNativeBranding(body, 'exo-native')).toEqual({
      clientId: 'exo-native', name: 'Exo', icon: 'https://tinycloud.chat/icons/pwa-512.png', organization: 'TinyCloud Labs',
      theme: { backgroundColor: '#09090b', accentColor: '#fafafa' },
    });
  });

  test('drops an unsafe icon and invalid colours, keeps the name', () => {
    const parsed = parseNativeBranding({ ...body, icon: 'javascript:alert(1)', theme: { backgroundColor: 'red', accentColor: null } }, 'exo-native');
    expect(parsed.icon).toBeNull();
    expect(parsed.theme).toEqual({ backgroundColor: null, accentColor: null });
    expect(parsed.name).toBe('Exo');
  });

  test('a null theme is fine', () => {
    expect(parseNativeBranding({ ...body, theme: null }, 'exo-native').theme).toEqual({ backgroundColor: null, accentColor: null });
  });

  test('rejects a response without a name', () => {
    expect(() => parseNativeBranding({ ...body, name: '' }, 'exo-native')).toThrow('no name');
  });

  test('loads from the branding route without credentials and surfaces HTTP errors', async () => {
    let requested: { url: string; init?: RequestInit } | null = null;
    const ok = (async (url: string, init?: RequestInit) => {
      requested = { url, init };
      return new Response(JSON.stringify(body), { status: 200 });
    }) as unknown as typeof fetch;
    expect((await loadNativeBranding('exo native', ok)).name).toBe('Exo');
    expect(requested!.url).toEndWith('/api/oauth/tinycloud/clients/exo%20native/branding');
    expect(requested!.init?.credentials).toBe('omit');

    const missing = (async () => new Response('{}', { status: 404 })) as unknown as typeof fetch;
    await expect(loadNativeBranding('x', missing)).rejects.toThrow('404');
  });
});
