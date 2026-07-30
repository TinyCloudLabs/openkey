import { afterEach, describe, expect, test } from 'bun:test';
import { readConfiguration } from './ci-provision-coordinationos-oidc';

const original = { ...process.env };

afterEach(() => {
  for (const key of Object.keys(process.env)) {
    if (!(key in original)) delete process.env[key];
  }
  Object.assign(process.env, original);
});

function validEnvironment() {
  Object.assign(process.env, {
    CONFIRM_PROVISION: 'PROVISION_COORDINATIONOS_OIDC',
    COORDINATIONOS_SUPABASE_SERVICE_ROLE_KEY: 'service-role-secret',
    COORDINATIONOS_URI: 'https://coordination.example',
    OPENKEY_ISSUER: 'https://api.openkey.so/api/auth',
    SUPABASE_CALLBACK_URI: 'https://project.supabase.co/auth/v1/callback',
    SUPABASE_URL: 'https://project.supabase.co',
  });
}

describe('CoordinationOS OIDC provisioning configuration', () => {
  test('accepts the canonical production shape without returning derived secrets', () => {
    validEnvironment();
    expect(readConfiguration()).toEqual({
      callbackUri: 'https://project.supabase.co/auth/v1/callback',
      coordinationosUri: 'https://coordination.example',
      issuer: 'https://api.openkey.so/api/auth',
      serviceRoleKey: 'service-role-secret',
      supabaseUrl: 'https://project.supabase.co',
    });
  });

  test.each([
    ['CONFIRM_PROVISION', 'wrong'],
    ['SUPABASE_CALLBACK_URI', 'https://other.supabase.co/auth/v1/callback'],
    ['SUPABASE_CALLBACK_URI', 'https://project.supabase.co/auth/v1/callback?leak=1'],
    ['SUPABASE_URL', 'http://project.supabase.co'],
    ['OPENKEY_ISSUER', 'https://api.openkey.so/wrong'],
    ['COORDINATIONOS_URI', 'https://user:pass@coordination.example'],
  ])('rejects unsafe %s values', (name, value) => {
    validEnvironment();
    process.env[name] = value;
    expect(() => readConfiguration()).toThrow();
  });
});
