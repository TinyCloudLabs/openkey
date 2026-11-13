import { shareSessionGeneration } from '../services/share-session-generation';
import { createPrismaClient } from '@openkey/db';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import { getAddress } from 'ethers';
import { requireSession } from '../middleware/session';
import { ApprovalContinuations, type ApprovalIdentity } from '../services/approval-continuation';
import { approvalAssertionOptions, verifyApprovalAssertion } from '../services/approval-assertion';
import { ShareApprovalError } from '../services/share-approval';
import { ShareApprovalRequests, type ShareApprovalAccount } from '../services/share-approval-request';
import { registerShareSessionInvalidator, shareWindowContexts as windows } from '../services/share-window-session';
import { signManagedKey } from '../services/managed-key-signing';
import { createShareApprovalRouter, type ShareApprovalLifecycle } from './share-approval';

const db = createPrismaClient();
const requests = new ShareApprovalRequests();
// Separate purpose-bound lifecycle and issuance quotas; no sign-in token can enter this store.
const continuations = new ApprovalContinuations();
registerShareSessionInvalidator((userId, sessionId, keepGeneration) => {
  const retained = requests.invalidateSession(userId, sessionId, keepGeneration);
  continuations.cancelSession(userId, sessionId, retained);
});
const rp = { rpID: process.env.WEBAUTHN_RP_ID!, origin: process.env.WEBAUTHN_ORIGIN! };

async function findAccount(userId: string, authSessionId: string, keyId: string): Promise<ShareApprovalAccount | null> {
  const [session, key] = await Promise.all([
    db.session.findFirst({ where: { id: authSessionId, userId, expiresAt: { gt: new Date() } } }),
    db.ethereumKey.findFirst({ where: { id: keyId, userId, archivedAt: null } }),
  ]);
  if (!session || !key || (key.keyType !== 'MANAGED' && key.keyType !== 'EXTERNAL')) {
    windows.invalidateSession(userId, authSessionId);
    return null;
  }
  const authSessionGeneration = shareSessionGeneration(session);
  return { userId, authSessionId, authSessionGeneration, keyId: key.id, address: getAddress(key.address), keyType: key.keyType };
}

function identity(preview: ReturnType<ShareApprovalRequests['preview']>, account: ShareApprovalAccount): ApprovalIdentity {
  const chainId = Number(preview.ownerDid.split(':')[3]);
  return Object.freeze({ userId: account.userId, sessionId: account.authSessionId,
    requestId: preview.requestId, origin: preview.origin, keyId: account.keyId, keyType: account.keyType,
    address: account.address.toLowerCase(), chainId,
    purpose: 'share-create', serverIntentDigest: preview.intentDigest });
}

const lifecycle: ShareApprovalLifecycle = {
  options: (preview, account) => approvalAssertionOptions(db, identity(preview, account), rp, continuations),
  async verify(preview, account, token, response) {
    await verifyApprovalAssertion(db, token, identity(preview, account), response as AuthenticationResponseJSON,
      rp, continuations, async () => {
        const current = await findAccount(account.userId, account.authSessionId, account.keyId);
        if (!current) throw new ShareApprovalError('share_account_changed');
        return identity(requests.preview(preview.requestId, current), current);
      });
  },
  resume: (preview, account, token) => continuations.resume(token, identity(preview, account)),
  assertResumed: (preview, account, token) => { continuations.resumedIdentity(token, identity(preview, account)); },
  consume: (preview, account, token) => continuations.consume(token, identity(preview, account), () => true),
  cancel: (preview, account, token) => continuations.cancel(token, identity(preview, account)),
};

export const shareApprovalRouter = createShareApprovalRouter(requests, windows, {
  findAccount,
  lifecycle,
  async signManaged(account, message) {
    const current = await findAccount(account.userId, account.authSessionId, account.keyId);
    if (!current || current.address !== account.address || current.keyType !== 'MANAGED') throw new ShareApprovalError('share_account_changed');
    const key = await db.ethereumKey.findFirst({ where: { id: account.keyId, userId: account.userId, archivedAt: null } });
    if (!key?.sealedBlob || key.keyType !== 'MANAGED' || getAddress(key.address) !== account.address) throw new ShareApprovalError('share_account_changed');
    return signManagedKey(key, key.sealedBlob, message);
  },
}, requireSession);
