import { describe, expect, test } from 'bun:test';

import {
  ADMIN_MANAGED_SCOPES,
  DEFAULT_OAUTH_SCOPES,
  DYNAMIC_CLIENT_REGISTRATION_ALLOWED_SCOPES,
  OAUTH_SCOPES,
  RESTRICTED_SCOPES,
  TINYCLOUD_DELEGATION_SCOPE,
  TINYCLOUD_SESSION_SCOPE,
} from '../oauth-config';
import {
  NativeDelegationPolicyError,
  enabledNativeDelegation,
  isNativeDelegationClient,
  sqlIsolatedHosts,
  validateNativeDelegationConfig,
  type NativeDelegationClient,
} from '../services/native-delegation/policy';
import { isPublicProtocolPath, nativeDelegationMetadata } from '../services/native-delegation/public-protocol';

const nativeClient: NativeDelegationClient = { type: 'native', public: true, tokenEndpointAuthMethod: 'none' };
const host = 'https://tee.node.tinycloud.xyz';
const ceiling = {
  version: 1,
  appId: 'xyz.tinycloud.tinychat',
  tinycloudHost: host,
  kv: { paths: ['xyz.tinycloud.tinychat/threads/'], actions: ['get', 'put'] },
  sql: null,
};
const sql = { databases: ['xyz.tinycloud.tinychat/threads'], actions: ['read', 'write', 'schema'] };
const isolated = { isolatedHosts: new Set([host]), allowLocalHosts: false };
const notIsolated = { isolatedHosts: new Set<string>(), allowLocalHosts: false };

function refused(input: unknown, client = nativeClient, options = isolated) {
  expect(() => validateNativeDelegationConfig(input, client, options)).toThrow(NativeDelegationPolicyError);
}

describe('tinycloud:delegation scope sets', () => {
  test('the scope is known but never a default, public, or dynamic registration scope', () => {
    expect(OAUTH_SCOPES).toContain(TINYCLOUD_DELEGATION_SCOPE);
    expect(RESTRICTED_SCOPES.has(TINYCLOUD_DELEGATION_SCOPE)).toBe(true);
    expect(DEFAULT_OAUTH_SCOPES).not.toContain(TINYCLOUD_DELEGATION_SCOPE as never);
    expect(DYNAMIC_CLIENT_REGISTRATION_ALLOWED_SCOPES).not.toContain(TINYCLOUD_DELEGATION_SCOPE);
  });

  test('delegation and manage-key are admin-managed and never dynamically registrable', () => {
    expect([...ADMIN_MANAGED_SCOPES].sort()).toEqual([TINYCLOUD_DELEGATION_SCOPE, 'tinycloud:manage-key'].sort());
    for (const scope of ADMIN_MANAGED_SCOPES) {
      expect(DYNAMIC_CLIENT_REGISTRATION_ALLOWED_SCOPES).not.toContain(scope as never);
    }
  });

  test('dynamic registration keeps its existing tinycloud:session allowance', () => {
    expect(DYNAMIC_CLIENT_REGISTRATION_ALLOWED_SCOPES).toContain(TINYCLOUD_SESSION_SCOPE);
  });
});

describe('native delegation ceiling validation', () => {
  test('accepts a native public ceiling and returns it with defaults in canonical order', () => {
    expect(validateNativeDelegationConfig(ceiling, nativeClient, notIsolated)).toEqual({
      version: 1,
      appId: 'xyz.tinycloud.tinychat',
      tinycloudHost: host,
      kv: { paths: ['xyz.tinycloud.tinychat/threads/'], actions: ['get', 'put'] },
      sql: null,
      maxDelegationTtlSeconds: 3600,
      grantLifetimeSeconds: 2_592_000,
    });
  });

  test('refuses spa, web, confidential and secret-authenticated clients', () => {
    refused(ceiling, { type: 'spa', public: true, tokenEndpointAuthMethod: 'none' });
    refused(ceiling, { type: 'web', public: false, tokenEndpointAuthMethod: 'client_secret_basic' });
    refused(ceiling, { type: 'native', public: false, tokenEndpointAuthMethod: 'none' });
    refused(ceiling, { type: 'native', public: true, tokenEndpointAuthMethod: 'client_secret_post' });
  });

  test('refuses a disabled client', () => {
    refused(ceiling, { ...nativeClient, disabled: true });
    expect(validateNativeDelegationConfig(ceiling, { ...nativeClient, disabled: false }, notIsolated).appId)
      .toBe('xyz.tinycloud.tinychat');
  });

  test('SQL entries require a host in TINYCLOUD_SQL_ISOLATED_HOSTS', () => {
    refused({ ...ceiling, sql }, nativeClient, notIsolated);
    expect(validateNativeDelegationConfig({ ...ceiling, sql }, nativeClient, isolated).sql).toEqual(sql);
    expect(sqlIsolatedHosts(` ${host} , https://node.tinycloud.xyz,`)).toEqual(new Set([host, 'https://node.tinycloud.xyz']));
    expect(sqlIsolatedHosts(undefined)).toEqual(new Set());
  });

  test('SQL databases are exact names under the appId', () => {
    for (const databases of [
      ['xyz.tinycloud.tinychat/threads/'],
      ['xyz.tinycloud.tinychat/threads/private'],
      ['other.app/threads'],
      ['xyz.tinycloud.tinychat/..'],
      ['xyz.tinycloud.tinychat/'],
    ]) {
      refused({ ...ceiling, sql: { ...sql, databases } });
    }
    refused({ ...ceiling, sql: { ...sql, actions: ['admin'] } });
  });

  test('KV paths stay in the app namespace without wildcards or dot segments', () => {
    for (const paths of [
      ['other.app/threads/'],
      ['xyz.tinycloud.tinychat'],
      ['xyz.tinycloud.tinychat/../secrets/'],
      ['xyz.tinycloud.tinychat/*'],
      ['xyz.tinycloud.tinychat//threads'],
      ['xyz.tinycloud.tinychat/threads/', 'xyz.tinycloud.tinychat/threads/'],
      [],
    ]) {
      refused({ ...ceiling, kv: { ...ceiling.kv, paths } });
    }
    refused({ ...ceiling, kv: { ...ceiling.kv, actions: ['get', 'write'] } });
    refused({ ...ceiling, appId: 'secrets', kv: { ...ceiling.kv, paths: ['secrets/x/'] } });
  });

  test('refuses unknown fields, untrusted hosts and out-of-range lifetimes', () => {
    refused({ ...ceiling, extra: true });
    refused({ ...ceiling, kv: { ...ceiling.kv, service: 'kv' } });
    refused({ ...ceiling, version: 2 });
    refused({ ...ceiling, tinycloudHost: 'https://evil.example' });
    refused({ ...ceiling, tinycloudHost: `${host}/` });
    refused({ ...ceiling, tinycloudHost: 'http://localhost:8000' });
    refused({ ...ceiling, maxDelegationTtlSeconds: 299 });
    refused({ ...ceiling, maxDelegationTtlSeconds: 86_401 });
    refused({ ...ceiling, grantLifetimeSeconds: 2_592_001 });
    refused({ ...ceiling, siweDomain: 'openkey.so/path' });
    expect(validateNativeDelegationConfig(
      { ...ceiling, tinycloudHost: 'http://localhost:8000' }, nativeClient, { ...notIsolated, allowLocalHosts: true },
    ).tinycloudHost).toBe('http://localhost:8000');
  });

  test('the runtime gate disables delegation when the stored ceiling no longer validates', () => {
    const client = {
      ...nativeClient, disabled: false, scopes: ['openid', TINYCLOUD_DELEGATION_SCOPE], tinycloudNativeDelegation: { ...ceiling, sql },
    };
    const previous = process.env.TINYCLOUD_SQL_ISOLATED_HOSTS;
    try {
      process.env.TINYCLOUD_SQL_ISOLATED_HOSTS = host;
      expect(enabledNativeDelegation(client)?.sql).toEqual(sql);
      process.env.TINYCLOUD_SQL_ISOLATED_HOSTS = '';
      expect(enabledNativeDelegation(client)).toBeNull();
    } finally {
      if (previous === undefined) delete process.env.TINYCLOUD_SQL_ISOLATED_HOSTS;
      else process.env.TINYCLOUD_SQL_ISOLATED_HOSTS = previous;
    }
    expect(enabledNativeDelegation({ ...client, tinycloudNativeDelegation: ceiling, disabled: true })).toBeNull();
    expect(enabledNativeDelegation({ ...client, tinycloudNativeDelegation: ceiling, scopes: ['openid'] })).toBeNull();
  });

  test('provider guards treat a stale scope or a stale ceiling as a delegation client', () => {
    expect(isNativeDelegationClient({ scopes: [TINYCLOUD_DELEGATION_SCOPE], tinycloudNativeDelegation: null })).toBe(true);
    expect(isNativeDelegationClient({ scopes: ['openid'], tinycloudNativeDelegation: { version: 9 } })).toBe(true);
    expect(isNativeDelegationClient({ scopes: ['openid'], tinycloudNativeDelegation: null })).toBe(false);
  });
});

describe('public protocol paths', () => {
  test('cover discovery and the public protocol endpoints only', () => {
    for (const path of [
      '/.well-known/oauth-authorization-server',
      '/.well-known/oauth-authorization-server/api/auth',
      '/.well-known/openid-configuration',
      '/api/auth/.well-known/openid-configuration',
      '/api/auth/oauth2/token',
      '/api/auth/oauth2/par',
      '/api/auth/oauth2/tinycloud/renew',
      '/api/auth/oauth2/tinycloud/revoke',
    ]) {
      expect(isPublicProtocolPath(`https://api.openkey.test${path}`), path).toBe(true);
    }
    for (const path of [
      '/api/auth/oauth2/consent',
      '/api/auth/oauth2/revoke',
      '/api/auth/oauth2/authorize',
      '/api/auth/get-session',
      '/api/oauth/tinycloud/requests/id/prepare',
      '/api/auth/oauth2/tinycloud/other',
      '/api/auth/oauth2/token/',
      '/api/auth/oauth2/tinycloud/renew/../../consent',
      '/api/auth/oauth2/%74oken',
    ]) {
      expect(isPublicProtocolPath(`https://api.openkey.test${path}`), path).toBe(false);
    }
  });

  test('metadata endpoints are built on the issuer', () => {
    expect(nativeDelegationMetadata('https://api.openkey.so/api/auth')).toEqual({
      pushed_authorization_request_endpoint: 'https://api.openkey.so/api/auth/oauth2/par',
      tinycloud_delegation_renew_endpoint: 'https://api.openkey.so/api/auth/oauth2/tinycloud/renew',
      tinycloud_delegation_revocation_endpoint: 'https://api.openkey.so/api/auth/oauth2/tinycloud/revoke',
    });
  });
});
