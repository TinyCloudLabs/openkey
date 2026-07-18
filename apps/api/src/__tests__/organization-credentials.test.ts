import { describe, expect, test } from 'bun:test';
import { authenticateOrganizationCredential, issueOrganizationCredential } from '../services/organization-credentials';

describe('organization credentials', () => {
  test('stores only a verifier and authenticates an active member', async () => {
    let stored: any;
    const db = {
      organizationServerCredential: {
        create: async ({ data }: any) => {
          stored = { id: 'credential-id', createdAt: new Date(), revokedAt: null, ...data };
          return stored;
        },
        findUnique: async ({ where }: any) => where.secretPrefix === stored.secretPrefix ? stored : null,
        update: async () => stored,
      },
      organizationMembership: { findFirst: async () => ({ id: 'membership' }) },
    } as any;
    const issued = await issueOrganizationCredential(db, {
      organizationId: 'organization', subjectUserId: 'member', name: 'Provisioner', kind: 'PROVISIONER',
    });
    expect(issued.secret).toStartWith('oksk_');
    expect(stored.secretHash).not.toContain(issued.secret);
    expect(stored).not.toHaveProperty('secret');
    await expect(authenticateOrganizationCredential(db, issued.secret)).resolves.toMatchObject({
      credentialId: 'credential-id', organizationId: 'organization', kind: 'PROVISIONER',
    });
    await expect(authenticateOrganizationCredential(db, `${issued.secret.slice(0, -1)}x`))
      .rejects.toMatchObject({ code: 'INVALID_CREDENTIAL' });
  });

  test('rejects issuance to members and invalidates credentials immediately on admin demotion', async () => {
    let role: 'ADMIN' | 'MEMBER' = 'MEMBER';
    let stored: any;
    const db = {
      organizationServerCredential: {
        create: async ({ data }: any) => {
          stored = { id: 'credential-id', createdAt: new Date(), revokedAt: null, ...data };
          return stored;
        },
        findUnique: async () => stored,
        update: async () => stored,
      },
      organizationMembership: {
        findFirst: async ({ where }: any) => where.role === role ? { id: 'membership' } : null,
      },
    } as any;
    const input = {
      organizationId: 'organization', subjectUserId: 'member', name: 'Provisioner', kind: 'PROVISIONER' as const,
    };
    await expect(issueOrganizationCredential(db, input)).rejects.toMatchObject({ code: 'ADMIN_REQUIRED' });
    role = 'ADMIN';
    const issued = await issueOrganizationCredential(db, input);
    await expect(authenticateOrganizationCredential(db, issued.secret)).resolves.toMatchObject({
      credentialId: 'credential-id', organizationId: 'organization', kind: 'PROVISIONER',
    });
    role = 'MEMBER';
    await expect(authenticateOrganizationCredential(db, issued.secret))
      .rejects.toMatchObject({ code: 'MEMBERSHIP_REVOKED' });
  });
});
