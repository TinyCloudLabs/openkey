import { createPrismaClient } from '@openkey/db';
import { requireSession } from '../middleware/session';
import { signManagedKey } from '../services/managed-key-signing';
import { preparedHandoffService } from './prepared-handoffs';
import { createOwnerRevocationRouter } from './owner-revocation';

const database = createPrismaClient();
export const ownerRevocationRouter = createOwnerRevocationRouter(preparedHandoffService, {
  findKey: (keyId, userId) => database.ethereumKey.findFirst({
    where: { id: keyId, userId, archivedAt: null },
    select: { id: true, userId: true, address: true, keyType: true, sealedBlob: true, sealingContext: true },
  }),
  signManaged: signManagedKey,
}, requireSession);
