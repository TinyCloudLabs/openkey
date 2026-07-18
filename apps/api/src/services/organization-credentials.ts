import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { PrismaClient } from '@openkey/db';

const CREDENTIAL_PREFIX = 'oksk_';
const SECRET_BYTES = 32;

type CredentialDb = Pick<PrismaClient, 'organizationServerCredential' | 'organizationMembership'>;

export type AuthenticatedOrganization = {
  credentialId: string;
  organizationId: string;
  subjectUserId: string;
  kind: 'BROKER' | 'PROVISIONER';
};

export class OrganizationCredentialError extends Error {
  constructor(readonly code: 'INVALID_CREDENTIAL' | 'CREDENTIAL_REVOKED' | 'MEMBERSHIP_REVOKED' | 'ADMIN_REQUIRED') {
    super(code);
    this.name = 'OrganizationCredentialError';
  }
}

function digest(secret: string): Buffer {
  return createHash('sha256').update(secret, 'utf8').digest();
}

function credentialParts(value: string): { prefix: string; secret: string } | null {
  const match = /^oksk_([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{43})$/.exec(value);
  return match ? { prefix: match[1]!, secret: match[2]! } : null;
}

export async function issueOrganizationCredential(
  db: CredentialDb,
  input: {
    organizationId: string;
    subjectUserId: string;
    name: string;
    kind: 'BROKER' | 'PROVISIONER';
  },
  now = new Date(),
) {
  const adminMembership = await db.organizationMembership.findFirst({
    where: {
      organizationId: input.organizationId,
      userId: input.subjectUserId,
      role: 'ADMIN',
      status: 'ACTIVE',
      revokedAt: null,
      validFrom: { lte: now },
      OR: [{ validUntil: null }, { validUntil: { gt: now } }],
    },
    select: { id: true },
  });
  if (!adminMembership) throw new OrganizationCredentialError('ADMIN_REQUIRED');
  const prefix = randomBytes(12).toString('base64url');
  const secret = randomBytes(SECRET_BYTES).toString('base64url');
  const credential = await db.organizationServerCredential.create({
    data: {
      organizationId: input.organizationId,
      subjectUserId: input.subjectUserId,
      name: input.name,
      kind: input.kind,
      secretPrefix: prefix,
      secretHash: digest(secret).toString('hex'),
    },
    select: { id: true, organizationId: true, name: true, kind: true, createdAt: true },
  });
  return { credential, secret: `${CREDENTIAL_PREFIX}${prefix}.${secret}` };
}

export async function authenticateOrganizationCredential(
  db: CredentialDb,
  bearer: string,
  now = new Date(),
): Promise<AuthenticatedOrganization> {
  const parts = credentialParts(bearer);
  if (!parts) throw new OrganizationCredentialError('INVALID_CREDENTIAL');

  const credential = await db.organizationServerCredential.findUnique({
    where: { secretPrefix: parts.prefix },
    select: {
      id: true,
      organizationId: true,
      subjectUserId: true,
      kind: true,
      secretHash: true,
      revokedAt: true,
    },
  });
  if (!credential) throw new OrganizationCredentialError('INVALID_CREDENTIAL');

  const expected = Buffer.from(credential.secretHash, 'hex');
  const provided = digest(parts.secret);
  if (expected.length !== provided.length || !timingSafeEqual(expected, provided)) {
    throw new OrganizationCredentialError('INVALID_CREDENTIAL');
  }
  if (credential.revokedAt || !credential.subjectUserId) {
    throw new OrganizationCredentialError('CREDENTIAL_REVOKED');
  }

  const membership = await db.organizationMembership.findFirst({
    where: {
      organizationId: credential.organizationId,
      userId: credential.subjectUserId,
      role: 'ADMIN',
      status: 'ACTIVE',
      revokedAt: null,
      validFrom: { lte: now },
      OR: [{ validUntil: null }, { validUntil: { gt: now } }],
    },
    select: { id: true },
  });
  if (!membership) throw new OrganizationCredentialError('MEMBERSHIP_REVOKED');

  await db.organizationServerCredential.update({
    where: { id: credential.id },
    data: { lastUsedAt: now },
  });
  return {
    credentialId: credential.id,
    organizationId: credential.organizationId,
    subjectUserId: credential.subjectUserId,
    kind: credential.kind,
  };
}

export function bearerToken(authorization: string | undefined): string {
  const match = /^Bearer ([^\s]+)$/.exec(authorization ?? '');
  if (!match) throw new OrganizationCredentialError('INVALID_CREDENTIAL');
  return match[1]!;
}
