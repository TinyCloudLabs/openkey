import { afterEach, describe, expect, mock, test } from 'bun:test';
import {
  assertOrganizationCanOwnClient,
  readConfiguration,
} from './ci-provision-coordinationos-oidc';

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
    OPENKEY_ORGANIZATION_ID: 'org-coordination',
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
      organizationId: 'org-coordination',
      serviceRoleKey: 'service-role-secret',
      supabaseUrl: 'https://project.supabase.co',
    });
  });

  test('allows an existing client to retain its persisted organization owner', () => {
    validEnvironment();
    delete process.env.OPENKEY_ORGANIZATION_ID;
    expect(readConfiguration().organizationId).toBeUndefined();
  });

  test('allows a database-only repair after the one-time Supabase secret is removed', () => {
    validEnvironment();
    delete process.env.COORDINATIONOS_SUPABASE_SERVICE_ROLE_KEY;
    expect(readConfiguration().serviceRoleKey).toBeUndefined();
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

describe('CoordinationOS client organization ownership', () => {
  test('does not consume another app seat when the client already belongs to the organization', async () => {
    const findUnique = mock(async () => {
      throw new Error('organization lookup should not run');
    });
    await expect(assertOrganizationCanOwnClient(
      { organization: { findUnique } } as any,
      'org-coordination',
      'org-coordination',
    )).resolves.toBeUndefined();
    expect(findUnique).not.toHaveBeenCalled();
  });

  test('accepts an organization with an available app seat', async () => {
    const findUnique = mock(async () => ({
      planEntitlements: { maxApps: 3 },
      _count: { oauthClients: 2 },
    }));
    await expect(assertOrganizationCanOwnClient(
      { organization: { findUnique } } as any,
      'org-coordination',
      null,
    )).resolves.toBeUndefined();
  });

  test('rejects cross-organization reassignment, missing organizations, and exhausted app limits', async () => {
    await expect(assertOrganizationCanOwnClient(
      { organization: { findUnique: mock(async () => null) } } as any,
      'org-coordination',
      'org-other',
    )).rejects.toThrow('already belongs to another');

    await expect(assertOrganizationCanOwnClient(
      { organization: { findUnique: mock(async () => null) } } as any,
      'org-coordination',
      null,
    )).rejects.toThrow('does not identify');

    await expect(assertOrganizationCanOwnClient(
      {
        organization: {
          findUnique: mock(async () => ({
            planEntitlements: { maxApps: 1 },
            _count: { oauthClients: 1 },
          })),
        },
      } as any,
      'org-coordination',
      null,
    )).rejects.toThrow('limit is exhausted');
  });
});
