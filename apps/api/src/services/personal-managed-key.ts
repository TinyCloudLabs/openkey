import type { PrismaClient } from '@openkey/db';
import { createTeeClient, createWalletFromPrivateKey, unseal, type TeeClient } from '@openkey/tee';
import { authorizeKeyOperationInTransaction } from './managed-key-authorization';
import { deriveKeyForRecord } from './key-sealing';

export async function signWithUserOwnedManagedAccount(
  db: PrismaClient,
  input: {
    sessionId: string;
    managedAccountId: string;
    keyId: string;
    expectedEpoch: number;
    approvalId: string;
    message: string;
  },
  tee: TeeClient = createTeeClient(),
) {
  return db.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT "id" FROM "managed_account" WHERE "id" = ${input.managedAccountId} FOR UPDATE`;
    await authorizeKeyOperationInTransaction(tx, {
      type: 'user',
      sessionId: input.sessionId,
      managedAccountId: input.managedAccountId,
      keyId: input.keyId,
      expectedEpoch: input.expectedEpoch,
      request: { operation: 'SIGN_APPROVED_MESSAGE', approvalId: input.approvalId },
    });
    const key = await tx.ethereumKey.findUniqueOrThrow({ where: { id: input.keyId } });
    const sealingKey = await deriveKeyForRecord(tee, key);
    const privateKey = await unseal(key.sealedBlob!, sealingKey) as `0x${string}`;
    const wallet = createWalletFromPrivateKey(privateKey);
    const signature = await wallet.signMessage({ message: input.message });
    return { signature, address: key.address, custodyEpoch: input.expectedEpoch };
  }, { isolationLevel: 'Serializable' });
}
