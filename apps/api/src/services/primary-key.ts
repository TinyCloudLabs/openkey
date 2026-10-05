import { randomUUID } from 'node:crypto';
import type { EthereumKey, PrismaClient } from '@openkey/db';
import { createTeeClient, getAddressFromPrivateKey, unseal } from '@openkey/tee';
import { getAddress, type Hex } from 'viem';
import { deriveKeyForRecord } from './key-sealing';
import { requestDigest } from './tinycloud-manage-key-control';

const tee = createTeeClient();
const publicKeySelect = {
  id: true, address: true, publicKey: true, keyType: true, keyIndex: true,
  label: true, archivedAt: true, createdAt: true,
} as const;
type PrimaryKey = Pick<EthereumKey, keyof typeof publicKeySelect> & { isPrimary: true };

/**
 * A user's primary key is their canonical TinyCloud key: the one active
 * managed key flagged `isCanonicalTinyCloud` (a partial unique index allows
 * at most one per user). External wallets and archived keys are never
 * primary.
 */
export function isPrimaryKey(key: {
  keyType: string;
  isCanonicalTinyCloud: boolean;
  archivedAt: Date | null;
}): boolean {
  return key.keyType === 'MANAGED' && key.isCanonicalTinyCloud === true && key.archivedAt === null;
}

/**
 * The database filter for a user's primary (canonical TinyCloud) key. Every
 * reader of the canonical identity uses it: the OAuth canonical identity
 * claim and `tinycloud:manage-key` signing.
 */
export function primaryKeyWhere(userId: string) {
  return {
    userId,
    keyType: 'MANAGED' as const,
    archivedAt: null,
    isCanonicalTinyCloud: true,
  };
}

export type SetPrimaryKeyResult =
  | { kind: 'changed'; keyId: string; previousKeyId: string | null; key: PrimaryKey }
  | { kind: 'unchanged'; keyId: string; key: PrimaryKey }
  | { kind: 'not_found' }
  | { kind: 'external_key' }
  | { kind: 'archived' }
  | { kind: 'unavailable' };

function isUniqueViolation(error: unknown): boolean {
  return !!error && typeof error === 'object' && (error as { code?: unknown }).code === 'P2002';
}

export class PrimaryKeyConflictError extends Error {
  constructor() {
    super('primary_key_conflict');
  }
}

/**
 * Makes `keyId` the user's primary key in one transaction.
 *
 * Only an active managed personal key that OpenKey can sign with is eligible.
 * Personal ownership is the userId relation; organization key custody was
 * removed by TC-488. External wallets must sign client-side.
 *
 * Write order keeps the partial unique index
 * `ethereum_keys_one_active_canonical_tinycloud_key` satisfied after every
 * statement: first clear the flag on every other key of the user, including
 * archived ones (restoring an old flagged key must not produce a second
 * primary), then set it on the target. The user row is locked first, the same
 * lock `tinycloud:manage-key` signing takes, so a switch never interleaves
 * with a signature or with another switch.
 */
export async function setPrimaryKey(
  prisma: PrismaClient,
  userId: string,
  keyId: string,
): Promise<SetPrimaryKeyResult> {
  try {
    return await prisma.$transaction(async (tx) => {
      await tx.$queryRawUnsafe('SELECT "id" FROM "user" WHERE "id" = $1 FOR UPDATE', userId);
      const user = await tx.user.findUnique({
        where: { id: userId },
        select: { tinyCloudManageKeyMode: true, tinyCloudManageKeyPolicyEpoch: true },
      });
      if (!user) return { kind: 'not_found' as const };

      const target = await tx.ethereumKey.findFirst({
        where: { id: keyId, userId },
        select: { ...publicKeySelect, userId: true, sealedBlob: true, sealingContext: true },
      });
      if (!target) return { kind: 'not_found' as const };
      if (target.keyType !== 'MANAGED') return { kind: 'external_key' as const };
      if (target.archivedAt !== null) return { kind: 'archived' as const };
      if (!target.sealedBlob) return { kind: 'unavailable' as const };
      // Resolve exactly the signing path used by delegate/sign. A nonempty
      // blob alone does not prove it can be decrypted or owns this address.
      try {
        const privateKey = await unseal(target.sealedBlob, await deriveKeyForRecord(tee, target));
        if (getAddressFromPrivateKey(privateKey as Hex) !== getAddress(target.address)) {
          return { kind: 'unavailable' as const };
        }
      } catch {
        return { kind: 'unavailable' as const };
      }

      const previous = await tx.ethereumKey.findFirst({
        where: primaryKeyWhere(userId),
        select: { id: true },
      });
      if (previous?.id === target.id) {
        const { userId: _owner, sealedBlob: _blob, sealingContext: _context, ...key } = target;
        return { kind: 'unchanged' as const, keyId: target.id, key: { ...key, isPrimary: true as const } };
      }

      await tx.ethereumKey.updateMany({
        where: { userId, isCanonicalTinyCloud: true, id: { not: target.id } },
        data: { isCanonicalTinyCloud: false },
      });
      const updated = await tx.ethereumKey.updateManyAndReturn({
        where: { id: target.id, userId, keyType: 'MANAGED', archivedAt: null },
        data: { isCanonicalTinyCloud: true },
        select: publicKeySelect,
      });
      // The row was read under the user lock; a concurrent archive is the only
      // way it can stop matching. Abort rather than leave the user without a
      // primary key.
      if (updated.length !== 1) throw new PrimaryKeyConflictError();

      const previousKeyId = previous?.id ?? null;
      await tx.tinyCloudManageKeyControlEvent.create({
        data: {
          id: randomUUID(),
          userId,
          policyEpoch: user.tinyCloudManageKeyPolicyEpoch,
          action: 'PRIMARY_KEY_CHANGED',
          mode: user.tinyCloudManageKeyMode,
          requestDigest: requestDigest({ action: 'PRIMARY_KEY_CHANGED', keyId: target.id, previousKeyId }),
        },
      });
      return { kind: 'changed' as const, keyId: target.id, previousKeyId, key: { ...updated[0]!, isPrimary: true as const } };
    }, { timeout: 10_000 });
  } catch (error) {
    if (isUniqueViolation(error)) throw new PrimaryKeyConflictError();
    throw error;
  }
}
