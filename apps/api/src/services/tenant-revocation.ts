import { createHash } from 'node:crypto';
import { type PrismaClient } from '@openkey/db';
import { createTeeClient, unseal, type TeeClient } from '@openkey/tee';
import { TinyCloudNode } from '@tinycloud/node-sdk';
import { deriveKeyForRecord } from './key-sealing';
import { enqueueLifecycleWebhook } from './lifecycle-webhooks';

export type RevocationTransport = (input: {
  privateKey: string;
  baseUrl: string;
  delegationCid: string;
}) => Promise<{ confirmed: boolean; receipt: unknown }>;

async function protocolRevokeAndConfirm(input: Parameters<RevocationTransport>[0]) {
  const node = new TinyCloudNode({ privateKey: input.privateKey, host: input.baseUrl, autoCreateSpace: false });
  await node.signIn();
  const revoked = await node.revokeDelegation(input.delegationCid);
  if (!revoked.ok) throw new Error(`TinyCloud revocation failed: ${revoked.error.message}`);
  const status = await node.delegationManager.list();
  if (!status.ok) throw new Error(`TinyCloud revocation status failed: ${status.error.message}`);
  const delegation = status.data.find((candidate) => candidate.cid === input.delegationCid);
  return {
    confirmed: delegation?.isRevoked === true,
    receipt: { cid: input.delegationCid, revoked: delegation?.isRevoked === true },
  };
}

export async function processRevocationReceipt(
  db: PrismaClient,
  receiptId: string,
  options: { tee?: TeeClient; transport?: RevocationTransport; now?: Date } = {},
) {
  const receipt = await db.ejectRevocationReceipt.findUnique({
    where: { id: receiptId },
    include: {
      node: true,
      managedAccount: { include: { key: true } },
    },
  });
  if (!receipt) return null;
  if (receipt.status === 'CONFIRMED') return receipt;
  if (receipt.managedAccount.state !== 'USER_OWNED' || receipt.managedAccount.custodyEpoch < 2) {
    throw new Error('Revocation requires committed personal custody');
  }
  const now = options.now ?? new Date();
  await db.ejectRevocationReceipt.update({
    where: { id: receipt.id },
    data: { status: 'SUBMITTED', submittedAt: receipt.submittedAt ?? now },
  });
  try {
    const sealingKey = await deriveKeyForRecord(options.tee ?? createTeeClient(), receipt.managedAccount.key);
    const privateKey = await unseal(receipt.managedAccount.key.sealedBlob!, sealingKey);
    const outcome = await (options.transport ?? protocolRevokeAndConfirm)({
      privateKey,
      baseUrl: receipt.node.baseUrl,
      delegationCid: receipt.tenantParentDelegationCid,
    });
    if (!outcome.confirmed) throw new Error('TinyCloud node did not confirm parent revocation');
    const responseDigest = createHash('sha256').update(JSON.stringify(outcome.receipt)).digest('hex');
    const updated = await db.ejectRevocationReceipt.update({
      where: { id: receipt.id },
      data: { status: 'CONFIRMED', confirmedAt: now, responseDigest },
    });
    const remaining = await db.ejectRevocationReceipt.count({
      where: { managedAccountId: receipt.managedAccountId, status: { not: 'CONFIRMED' } },
    });
    if (remaining === 0) {
      await db.$transaction(async (tx) => {
        const account = await tx.managedAccount.update({
          where: { id: receipt.managedAccountId },
          data: { revocationStatus: 'REVOKED' },
          select: { organizationId: true, custodyEpoch: true },
        });
        await enqueueLifecycleWebhook(tx, {
          organizationId: account.organizationId,
          managedAccountId: receipt.managedAccountId,
          eventType: 'tenant_access.revoked',
          custodyEpoch: account.custodyEpoch,
          payload: { managedAccountId: receipt.managedAccountId, custodyEpoch: account.custodyEpoch, tenantAccess: 'REVOKED' },
        });
      });
    }
    return updated;
  } catch (error) {
    await db.ejectRevocationReceipt.update({ where: { id: receipt.id }, data: { status: 'FAILED' } });
    throw error;
  }
}

export async function processPendingRevocations(
  db: PrismaClient,
  options: { tee?: TeeClient; transport?: RevocationTransport; limit?: number } = {},
) {
  const receipts = await db.ejectRevocationReceipt.findMany({
    where: { status: { in: ['PENDING', 'FAILED'] } },
    select: { id: true },
    orderBy: { id: 'asc' },
    take: options.limit ?? 100,
  });
  const results = [];
  for (const receipt of receipts) {
    try {
      results.push({ id: receipt.id, ok: true, result: await processRevocationReceipt(db, receipt.id, options) });
    } catch (error) {
      results.push({ id: receipt.id, ok: false, error });
    }
  }
  return results;
}
