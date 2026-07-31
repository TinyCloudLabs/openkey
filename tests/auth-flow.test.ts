import { describe, expect, test } from 'bun:test';

import { normalizeAuthReturnTo, safeOAuthAuthorizeQuery } from '../apps/web/src/lib/auth-flow';

describe('auth return context', () => {
  test('allows only same-origin product destinations', () => {
    const origin = 'https://openkey.test';
    expect(normalizeAuthReturnTo('/widget/embed/sign?origin=https%3A%2F%2Fapp.test', origin))
      .toBe('/widget/embed/sign?origin=https%3A%2F%2Fapp.test');
    expect(normalizeAuthReturnTo('https://openkey.test/dashboard/settings#keys', origin))
      .toBe('/dashboard/settings#keys');
    expect(normalizeAuthReturnTo('/console/org-1/apps', origin))
      .toBe('/console/org-1/apps');
    expect(normalizeAuthReturnTo('https://evil.test/dashboard', origin)).toBeNull();
    expect(normalizeAuthReturnTo('//evil.test/widget/embed/sign', origin)).toBeNull();
    expect(normalizeAuthReturnTo('/api/admin', origin)).toBeNull();
  });

  test('preserves OIDC context through an explicit parameter allowlist', () => {
    const query = new URLSearchParams({
      client_id: 'client-1',
      redirect_uri: 'https://app.test/callback',
      response_type: 'code',
      scope: 'openid email',
      state: 'state-1',
      code_challenge: 'challenge',
      code_challenge_method: 'S256',
      exp: '1785458628',
      ba_iat: '1785458028625',
      prompt: 'login',
      sig: 'server-only-signature',
      redirect: 'https://evil.test',
    });

    const safe = new URLSearchParams(safeOAuthAuthorizeQuery(query));
    expect(Object.fromEntries(safe)).toEqual({
      client_id: 'client-1',
      redirect_uri: 'https://app.test/callback',
      response_type: 'code',
      scope: 'openid email',
      state: 'state-1',
      code_challenge: 'challenge',
      code_challenge_method: 'S256',
      exp: '1785458628',
      ba_iat: '1785458028625',
      prompt: 'login',
      sig: 'server-only-signature',
    });
  });

  test('filters nested oauth_query context with the same allowlist', () => {
    const nested = new URLSearchParams({
      client_id: 'client-2',
      state: 'state-2',
      exp: '1785458628',
      ba_iat: '1785458028625',
      ba_pl: 'session-1',
      sig: 'signed-query',
      injected: 'nope',
    });
    const safe = new URLSearchParams(safeOAuthAuthorizeQuery(new URLSearchParams({
      oauth_query: nested.toString(),
    })));
    expect(Object.fromEntries(safe)).toEqual({
      client_id: 'client-2',
      state: 'state-2',
      exp: '1785458628',
      ba_iat: '1785458028625',
      ba_pl: 'session-1',
      sig: 'signed-query',
    });
  });
});
