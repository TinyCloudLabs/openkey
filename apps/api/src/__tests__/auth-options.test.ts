import { describe, expect, test } from 'bun:test';
import { crossSubDomainCookieOptions } from '../auth-options';
import { socialProviderTrustedOrigins } from '../social-providers';

describe('production console session options', () => {
  test('shares API-issued sessions with both production browser surfaces', () => {
    expect(crossSubDomainCookieOptions(false)).toEqual({
      enabled: true,
      domain: '.openkey.so',
    });
    expect(socialProviderTrustedOrigins('https://openkey.so', {
      CONSOLE_ORIGIN: 'https://console.openkey.so',
    })).toContain('https://console.openkey.so');
  });

  test('does not apply the production domain attribute to local development', () => {
    expect(crossSubDomainCookieOptions(true)).toEqual({ enabled: false });
  });
});
