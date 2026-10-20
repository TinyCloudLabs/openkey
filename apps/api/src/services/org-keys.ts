import { createHash } from 'node:crypto';
import type { Hex } from 'viem';
import { verifyAuthenticationResponse, type AuthenticationResponseJSON } from '@simplewebauthn/server';
import type { PrismaClient } from '@openkey/db';
import {
  createWalletFromPrivateKey,
  generatePrivateKey,
  getAddressFromPrivateKey,
  seal,
  unseal,
  type TeeClient,
} from '@openkey/tee';
import { createSealingContext, deriveKeyForRecord } from './key-sealing';

// Capability flag for organization key custody (TC-1518). Default off: the
// org-key routes answer 404 until the flag is set to "true".
export const ORG_KEY_CUSTODY_FLAG = 'ORG_KEY_CUSTODY_ENABLED';

export function isOrgKeyCustodyEnabled(env: Record<string, string | undefined> = process.env): boolean {
  return env[ORG_KEY_CUSTODY_FLAG] === 'true';
}

// K1 D4.1: origins from which an org-key signing request may originate.
export const ORG_KEY_ORIGIN = 'https://credentials.org';
export const ORG_KEY_ORIGINS: readonly string[] = [ORG_KEY_ORIGIN];

// Domain separator for the fresh-passkey challenge (K1 D4.5).
export const ORG_KEY_SIGN_DOMAIN = 'openkey.org-key-sign/v1';

// This module is the only place that reads custody = ORG rows. Personal paths
// reach ORG rows through no query (ORG rows have userId NULL; see
// personalKeyWhere in primary-key.ts).
function activeOrgGrantWhere(userId: string) {
  return {
    granteeUserId: userId,
    revokedAt: null,
    key: {
      custody: 'ORG' as const,
      archivedAt: null,
      orgKey: { isNot: null },
    },
  };
}

export type OrgKeyPickerItem = {
  keyId: string;
  address: string;
  label: string | null;
  orgName: string;
  role: 'OWNER' | 'ADMIN';
  usage: 'org-controller';
  badge: { kind: 'org'; text: string };
};

function toPickerItem(grant: {
  role: 'OWNER' | 'ADMIN';
  key: { id: string; address: string; label: string | null; orgKey: { orgName: string } | null };
}): OrgKeyPickerItem {
  const orgName = grant.key.orgKey?.orgName ?? '';
  return {
    keyId: grant.key.id,
    address: grant.key.address,
    label: grant.key.label,
    orgName,
    role: grant.role,
    usage: 'org-controller',
    badge: { kind: 'org', text: `Org key · ${orgName}` },
  };
}

const grantSelect = {
  role: true,
  key: { select: { id: true, address: true, label: true, orgKey: { select: { orgName: true } } } },
} as const;

export async function listOrgKeysForUser(prisma: PrismaClient, userId: string): Promise<OrgKeyPickerItem[]> {
  const grants = await prisma.keyGrant.findMany({
    where: activeOrgGrantWhere(userId),
    select: grantSelect,
    orderBy: { createdAt: 'asc' },
  });
  return grants.map(toPickerItem);
}

export async function findOrgKeyForUser(
  prisma: PrismaClient,
  userId: string,
  keyId: string,
): Promise<OrgKeyPickerItem | null> {
  const grant = await prisma.keyGrant.findFirst({
    where: { keyId, ...activeOrgGrantWhere(userId) },
    select: grantSelect,
  });
  return grant ? toPickerItem(grant) : null;
}

// The active grant the caller signs under. Null means the caller has no
// active grant on this key (K1 D4.1: 403 before anything else is checked).
export async function findActiveOrgGrant(
  prisma: PrismaClient,
  userId: string,
  keyId: string,
): Promise<{ grantId: string; role: 'OWNER' | 'ADMIN' } | null> {
  const grant = await prisma.keyGrant.findFirst({
    where: { keyId, ...activeOrgGrantWhere(userId) },
    select: { id: true, role: true },
  });
  return grant ? { grantId: grant.id, role: grant.role } : null;
}

export class OrgKeyRefusal extends Error {
  constructor(
    readonly status: 400 | 403 | 404,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export type CreateOrgKeyInput = {
  userId: string;
  orgId: string;
  orgName: string;
  controllerDid: string;
  label?: string | null;
};

// Creates an ORG-custodied key with the caller as its OWNER (K1 D2). The key has
// no personal owner (userId NULL), a per-key sealing context, and is never the
// canonical TinyCloud key.
export async function createOrgKey(prisma: PrismaClient, tee: TeeClient, input: CreateOrgKeyInput) {
  const privateKey = generatePrivateKey();
  const address = getAddressFromPrivateKey(privateKey);
  const sealingContext = createSealingContext();
  const sealedBlob = await seal(privateKey, await deriveKeyForRecord(tee, { userId: null, sealingContext }));

  return prisma.$transaction(async (tx) => {
    const key = await tx.ethereumKey.create({
      data: {
        userId: null,
        custody: 'ORG',
        keyType: 'MANAGED',
        address,
        publicKey: address,
        sealedBlob,
        sealingContext,
        isCanonicalTinyCloud: false,
        label: input.label ?? input.orgName,
      },
      select: { id: true, address: true, label: true },
    });
    await tx.orgKey.create({
      data: { keyId: key.id, orgId: input.orgId, orgName: input.orgName, controllerDid: input.controllerDid },
    });
    const grant = await tx.keyGrant.create({
      data: {
        keyId: key.id,
        role: 'OWNER',
        granteeUserId: input.userId,
        invitedByUserId: input.userId,
        acceptedAt: new Date(),
      },
      select: { id: true },
    });
    return { keyId: key.id, grantId: grant.id, address: key.address, label: key.label };
  });
}

// K1 D7 refusals, then the D3 allowlist. Returns the refusal reason, or null if
// the message is one of the signable kinds. The issuer-statement and org-space
// SIWE+ReCap kinds are added with K4; until then no kind is signable.
export function refuseOrgKeyMessage(message: string): string | null {
  if (message.includes('account-binding/v1') || message.includes('org-binding/v1')) {
    return 'binding_bytes_refused';
  }
  if (message.includes('tinycloud.credentials/')) {
    return 'credentials_capability_refused';
  }
  return 'unsupported_message_kind';
}

// The fresh-passkey challenge (K1 D4.5):
// sha256("openkey.org-key-sign/v1\0" || keyId || grantId || sha256(message)).
export function orgKeySignChallenge(keyId: string, grantId: string, message: string): Buffer {
  const messageDigest = createHash('sha256').update(message, 'utf8').digest();
  return createHash('sha256')
    .update(`${ORG_KEY_SIGN_DOMAIN}\0`, 'utf8')
    .update(keyId, 'utf8')
    .update(grantId, 'utf8')
    .update(messageDigest)
    .digest();
}

export type OrgKeySignInput = {
  userId: string;
  keyId: string;
  grantId: string;
  origin: string;
  message: string;
  format: 'raw' | 'personal_sign';
  assertion: AuthenticationResponseJSON;
  rpID: string;
  expectedOrigin: string;
};

// Verifies the fresh passkey, then writes the audit row and produces the
// signature in one transaction (K1 D4.6). If the audit insert fails, the
// transaction rolls back and no signature is returned. A passkey assertion is
// consumed once: its signature hash is unique on the audit table.
export async function signOrgKeyMessage(
  prisma: PrismaClient,
  tee: TeeClient,
  input: OrgKeySignInput,
): Promise<{ signature: Hex; address: string }> {
  // Prisma drops an undefined filter, so a missing assertion id would match any
  // passkey of the user. Refuse malformed assertions before the lookup.
  if (typeof input.assertion?.id !== 'string' || typeof input.assertion.response?.signature !== 'string') {
    throw new OrgKeyRefusal(403, 'passkey_invalid', 'Passkey assertion is malformed');
  }
  const passkey = await prisma.passkey.findFirst({
    where: { userId: input.userId, credentialID: input.assertion.id },
  });
  if (!passkey) throw new OrgKeyRefusal(403, 'passkey_required', 'A fresh passkey assertion is required');

  let verification: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
  try {
    verification = await verifyAuthenticationResponse({
      response: input.assertion,
      expectedChallenge: orgKeySignChallenge(input.keyId, input.grantId, input.message).toString('base64url'),
      expectedOrigin: input.expectedOrigin,
      expectedRPID: input.rpID,
      credential: {
        id: passkey.credentialID,
        publicKey: Buffer.from(passkey.publicKey, 'base64'),
        counter: passkey.counter,
      },
      requireUserVerification: true,
    });
  } catch {
    throw new OrgKeyRefusal(403, 'passkey_invalid', 'Passkey assertion did not verify');
  }
  if (!verification.verified) {
    throw new OrgKeyRefusal(403, 'passkey_invalid', 'Passkey assertion did not verify');
  }

  const assertionHash = createHash('sha256')
    .update(Buffer.from(input.assertion.response.signature, 'base64url'))
    .digest('hex');
  const messageDigest = createHash('sha256').update(input.message, 'utf8').digest('hex');

  try {
    return await prisma.$transaction(async (tx) => {
      // Re-check the grant under the transaction so a revoked grant cannot sign.
      const grant = await tx.keyGrant.findFirst({
        where: { id: input.grantId, keyId: input.keyId, granteeUserId: input.userId, revokedAt: null },
        select: { id: true },
      });
      if (!grant) throw new OrgKeyRefusal(403, 'grant_revoked', 'No active grant on this key');

      const key = await tx.ethereumKey.findFirst({
        where: { id: input.keyId, custody: 'ORG', userId: null, archivedAt: null },
      });
      if (!key || !key.sealedBlob) throw new OrgKeyRefusal(404, 'key_not_found', 'Key not found');

      await tx.passkey.update({
        where: { id: passkey.id },
        data: { counter: verification.authenticationInfo.newCounter },
      });
      await tx.orgKeySignatureAudit.create({
        data: {
          keyId: input.keyId,
          grantId: input.grantId,
          actorUserId: input.userId,
          origin: input.origin,
          messageDigest,
          passkeyAssertionHash: assertionHash,
        },
      });

      const sealingKey = await deriveKeyForRecord(tee, key);
      let privateKey: Hex;
      try {
        privateKey = (await unseal(key.sealedBlob, sealingKey)) as Hex;
      } finally {
        sealingKey.fill(0);
      }
      const account = createWalletFromPrivateKey(privateKey);
      if (input.format === 'raw') {
        if (!/^0x[0-9a-fA-F]{64}$/.test(input.message)) {
          throw new OrgKeyRefusal(400, 'invalid_raw_digest', 'Raw signing requires a 32-byte digest');
        }
        // signMessage({raw}) is not a digest signature; sign({hash}) signs the digest directly.
        const signature = await account.sign({ hash: input.message as Hex });
        return { signature, address: key.address };
      }
      const signature = await account.signMessage({ message: input.message });
      return { signature, address: key.address };
    });
  } catch (error) {
    if (error instanceof OrgKeyRefusal) throw error;
    if ((error as { code?: string }).code === 'P2002') {
      throw new OrgKeyRefusal(403, 'assertion_consumed', 'Passkey assertion was already used');
    }
    throw error;
  }
}
