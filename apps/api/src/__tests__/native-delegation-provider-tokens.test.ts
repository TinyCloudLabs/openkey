import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import {
  providerTokenOptions,
  storedOpaqueAccessToken,
  storedRefreshToken,
} from '../services/native-delegation/provider-tokens';

const sha256 = (value: string) => createHash('sha256').update(value).digest('base64url');

describe('provider token normalization', () => {
  test('the interceptors are written against the pinned provider version', () => {
    // provider-tokens.ts mirrors this version's internals; an upgrade must
    // re-check them before changing the pin.
    // The package's exports map omits package.json; resolve it beside dist/.
    const entry = Bun.resolveSync('@better-auth/oauth-provider', import.meta.dir);
    const manifest = JSON.parse(readFileSync(join(dirname(entry), '..', 'package.json'), 'utf8')) as { version: string };
    expect(manifest.version).toBe('1.6.10');
  });

  test('defaults to the provider\'s hashed storage: unpadded base64url SHA-256', async () => {
    expect(await storedRefreshToken({}, 'refresh')).toBe(sha256('refresh'));
    expect(await storedRefreshToken({ storeTokens: 'hashed' }, 'refresh')).toBe(sha256('refresh'));
    expect(await storedOpaqueAccessToken({}, 'access')).toBe(sha256('access'));
    expect(sha256('refresh')).not.toContain('=');
  });

  test('applies the configured prefixes, refresh-token decryption and custom hash', async () => {
    const options = {
      prefix: { refreshToken: 'rt_', opaqueAccessToken: 'at_' },
      formatRefreshToken: { decrypt: async (token: string) => ({ token: token.split('.')[0]! }) },
      storeTokens: { hash: async (token: string, type: string) => `${type}:${token}` },
    };
    expect(await storedRefreshToken(options, 'rt_inner.session')).toBe('refresh_token:inner');
    expect(await storedOpaqueAccessToken(options, 'at_access')).toBe('access_token:access');
    // A missing prefix is rejected by the provider before any lookup.
    expect(await storedRefreshToken(options, 'inner.session')).toBeNull();
    expect(await storedOpaqueAccessToken(options, 'access')).toBeNull();
  });

  test('fails closed on a storage method the provider cannot look up', async () => {
    await expect(storedRefreshToken({ storeTokens: 'plain' }, 'refresh')).rejects.toThrow('unsupported');
  });

  test('reads the options of the configured oauth-provider plugin instance', () => {
    const options = { storeTokens: 'hashed' };
    expect(providerTokenOptions({ options: { plugins: [{ id: 'jwt' }, { id: 'oauth-provider', options }] } })).toBe(options);
    expect(() => providerTokenOptions({ options: { plugins: [{ id: 'jwt' }] } })).toThrow('not configured');
  });
});
