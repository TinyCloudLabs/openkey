// A user's TinyCloud session for secrets and variables lives in the API's memory, so it is gone after a restart.
// The user's managed key opens it again.
import { createPrismaClient, type PrismaClient } from '@openkey/db';
import { createTeeClient, unseal, type TeeClient } from '@openkey/tee';
import { deriveKeyForRecord } from './key-sealing';
import { tinyCloudService } from './tinycloud-service';

let prisma: PrismaClient | undefined;
let tee: TeeClient | undefined;

export async function getUserPrivateKey(userId: string): Promise<string | null> {
  const key = await (prisma ??= createPrismaClient()).ethereumKey.findFirst({
    where: { userId, keyIndex: 0, keyType: 'MANAGED', archivedAt: null },
  });

  if (!key || !key.sealedBlob) {
    return null;
  }

  const sealingKey = await deriveKeyForRecord(tee ??= createTeeClient(), key);
  const privateKey = await unseal(key.sealedBlob, sealingKey) as string;
  // Strip 0x prefix if present
  return privateKey.startsWith('0x') ? privateKey.slice(2) : privateKey;
}

/** True when the user's TinyCloud session is open, restoring it from the managed key when the API has lost it. */
export async function restoreTinyCloudSession(userId: string): Promise<boolean> {
  if (await tinyCloudService.isEnabledForUser(userId)) return true;
  const privateKey = await getUserPrivateKey(userId);
  if (!privateKey) return false;
  try {
    await tinyCloudService.enableForUser(userId, privateKey);
    return true;
  } catch {
    return false; // the user has a key but the TinyCloud session failed: not enabled
  }
}
