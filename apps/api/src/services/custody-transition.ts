import { createHash } from 'node:crypto';
import { createWalletFromPrivateKey, type TeeClient, unseal } from '@openkey/tee';
import { Prisma, type PrismaClient } from '@openkey/db';
import { verifyMessage } from 'viem';
import {
  authorizeKeyOperationInTransaction,
  ManagedKeyAuthorizationError,
  type AuthorizeKeyOperationInput,
} from './managed-key-authorization';
import { deriveKeyForRecord } from './key-sealing';
import { enqueueLifecycleWebhook } from './lifecycle-webhooks';

export type CustodyTransitionResult = {
  managedAccountId: string;
  previousEpoch: number;
  custodyEpoch: number;
  state: 'MANAGED' | 'USER_OWNED';
  possessionEventId: string;
  eventHash: string;
  tenantAccess: 'NOT_REQUIRED' | 'PENDING' | 'REVOKED';
};

function canonicalJson(value: unknown): string {
  return JSON.stringify(value, (_key, item) => item instanceof Date ? item.toISOString() : item);
}

async function credentialPolicyHash(tx: Prisma.TransactionClient, ownerUserId: string): Promise<string> {
  const passkeys = await tx.passkey.findMany({
    where: { userId: ownerUserId },
    select: {
      id: true,
      credentialID: true,
      publicKey: true,
      counter: true,
      deviceType: true,
      backedUp: true,
      transports: true,
      aaguid: true,
      createdAt: true,
    },
    orderBy: { credentialID: 'asc' },
  });
  if (passkeys.length === 0) {
    throw new ManagedKeyAuthorizationError('OWNER_PASSKEY_REQUIRED', 'Managed custody requires a persisted owner passkey');
  }
  return createHash('sha256').update(canonicalJson(passkeys)).digest('hex');
}

function possessionEventHash(input: {
  managedAccountId: string;
  keyId: string;
  epoch: number;
  previousEventHash: string | null;
  fromPrincipal: string;
  toPrincipal: string;
  reason: string;
  credentialPolicyHash: string;
  createdAt: Date;
}): string {
  return createHash('sha256').update(canonicalJson(input)).digest('hex');
}

/** Internal primitive: it returns only the signature, never key material. */
async function signPossessionEvent(tee: TeeClient, key: { userId: string; sealingContext: string | null; sealedBlob: string | null }, address: string, hash: string): Promise<string> {
  if (!key.sealedBlob || !key.sealingContext) {
    throw new ManagedKeyAuthorizationError('KEY_NOT_SEALABLE', 'The managed account key cannot sign its custody event');
  }
  const sealingKey = await deriveKeyForRecord(tee, key);
  const privateKey = await unseal(key.sealedBlob, sealingKey) as `0x${string}`;
  const wallet = createWalletFromPrivateKey(privateKey);
  const signature = await wallet.signMessage({ message: hash });
  const valid = await verifyMessage({ address: address as `0x${string}`, message: hash, signature });
  if (!valid) throw new ManagedKeyAuthorizationError('KEY_NOT_SEALABLE', 'Custody event signature does not match the managed address');
  return signature;
}

async function latestEvent(tx: Prisma.TransactionClient, managedAccountId: string) {
  return tx.possessionEvent.findFirst({
    where: { managedAccountId },
    orderBy: { epoch: 'desc' },
    select: { eventHash: true },
  });
}

/**
 * Eject and initial activation both lock the managed-account row before
 * authorization, event signing, or mutation. The serializable transaction is
 * the shared database barrier for every future typed managed-key service.
 */
export async function transitionManagedAccountToUserCustody(
  db: PrismaClient,
  tee: TeeClient,
  input: AuthorizeKeyOperationInput & { nextEpoch: number; ejectRequestId?: string },
  now = new Date(),
): Promise<CustodyTransitionResult> {
  if (input.request.operation !== 'EJECT') {
    throw new ManagedKeyAuthorizationError('OPERATION_NOT_ALLOWED', 'Only EJECT can transfer custody to the owner');
  }

  return db.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT "id" FROM "managed_account" WHERE "id" = ${input.managedAccountId} FOR UPDATE`;
    const authorized = await authorizeKeyOperationInTransaction(tx, input, now);
    const current = await tx.managedAccount.findFirst({
      where: { id: authorized.managedAccountId, keyId: authorized.keyId },
      include: {
        custodyHead: true,
        nodes: { where: { active: true } },
        organization: { select: { planEntitlements: true } },
      },
    });
    if (!current) throw new ManagedKeyAuthorizationError('MANAGED_ACCOUNT_NOT_FOUND', 'Managed account not found');
    const key = await tx.ethereumKey.findUnique({
      where: { id: authorized.keyId },
      select: { userId: true, sealingContext: true, sealedBlob: true, address: true },
    });
    if (!key) throw new ManagedKeyAuthorizationError('KEY_NOT_SEALABLE', 'The managed account key was not found');
    const nextEpoch = current.custodyEpoch + 1;
    if (input.nextEpoch !== nextEpoch) {
      throw new ManagedKeyAuthorizationError('CUSTODY_EPOCH_STALE', 'Custody transitions require the exact next epoch');
    }
    if (!current.custodyHead || current.custodyHead.managedAccountId !== current.id
      || current.custodyHead.epoch !== current.custodyEpoch
      || current.custodyHead.revokedAt
      || current.custodyHead.custodianType !== 'ORGANIZATION'
      || current.custodyHead.custodianId !== current.organizationId) {
      throw new ManagedKeyAuthorizationError('CUSTODY_NOT_ACTIVE', 'Organization custody is not the current custody head');
    }

    // The row lock plus EJECTING state is the signing barrier. Any managed
    // operation queued behind this transaction re-resolves the lifecycle and
    // epoch after commit; a signing failure rolls this state change back.
    await tx.managedAccount.update({ where: { id: current.id }, data: { state: 'EJECTING' } });

    const previous = await latestEvent(tx, current.id);
    const policyHash = await credentialPolicyHash(tx, current.ownerUserId);
    const eventFields = {
      managedAccountId: current.id,
      keyId: current.keyId,
      epoch: nextEpoch,
      previousEventHash: previous?.eventHash ?? null,
      fromPrincipal: `organization:${current.organizationId}`,
      toPrincipal: `user:${current.ownerUserId}`,
      reason: 'OWNER_REQUEST',
      credentialPolicyHash: policyHash,
      createdAt: now,
    } as const;
    const hash = possessionEventHash(eventFields);
    const accountKeySignature = await signPossessionEvent(tee, key, key.address, hash);

    await tx.keyCustody.update({ where: { id: current.custodyHead.id }, data: { revokedAt: now } });
    const next = await tx.keyCustody.create({
      data: {
        managedAccountId: current.id,
        custodianType: 'USER',
        custodianId: current.ownerUserId,
        epoch: nextEpoch,
        activatedAt: now,
      },
    });
    const event = await tx.possessionEvent.create({
      data: { ...eventFields, eventHash: hash, accountKeySignature },
    });
    const clientIds = (await tx.oauthClient.findMany({
      where: { organizationId: current.organizationId },
      select: { clientId: true },
    })).map((client) => client.clientId);
    if (clientIds.length > 0) {
      await tx.oauthAccessToken.deleteMany({
        where: { clientId: { in: clientIds }, userId: current.ownerUserId, referenceId: current.id },
      });
      await tx.oauthRefreshToken.updateMany({
        where: { clientId: { in: clientIds }, userId: current.ownerUserId, referenceId: current.id },
        data: { revoked: true },
      });
    }
    if (current.nodes.length > 0 && !current.tenantParentDelegationCid) {
      throw new ManagedKeyAuthorizationError('CUSTODY_NOT_ACTIVE', 'Tenant-parent delegation is missing');
    }
    if (current.nodes.length > 0) {
      await tx.ejectRevocationReceipt.createMany({
        data: current.nodes.map((node) => ({
          possessionEventId: event.id,
          nodeId: node.id,
          managedAccountId: current.id,
          tenantParentDelegationCid: current.tenantParentDelegationCid!,
        })),
      });
    }
    const tenantAccess = current.nodes.length > 0 ? 'PENDING' as const : 'REVOKED' as const;
    await tx.managedAccount.update({
      where: { id: current.id },
      data: {
        state: 'USER_OWNED',
        custodyEpoch: nextEpoch,
        custodyHeadId: next.id,
        brokerAccessDisabledAt: now,
        revocationStatus: tenantAccess,
      },
    });
    await enqueueLifecycleWebhook(tx, {
      organizationId: current.organizationId,
      managedAccountId: current.id,
      eventType: 'custody.transfer_started',
      custodyEpoch: nextEpoch,
      payload: { managedAccountId: current.id, previousEpoch: current.custodyEpoch, custodyEpoch: nextEpoch },
    });
    await enqueueLifecycleWebhook(tx, {
      organizationId: current.organizationId,
      managedAccountId: current.id,
      eventType: 'custody.transferred',
      custodyEpoch: nextEpoch,
      payload: { managedAccountId: current.id, custody: 'USER_OWNED', custodyEpoch: nextEpoch, eventHash: hash },
    });
    if (tenantAccess === 'PENDING') {
      await enqueueLifecycleWebhook(tx, {
        organizationId: current.organizationId,
        managedAccountId: current.id,
        eventType: 'tenant_access.revocation_pending',
        custodyEpoch: nextEpoch,
        payload: { managedAccountId: current.id, custodyEpoch: nextEpoch, tenantAccess },
      });
    }
    const result = {
      managedAccountId: current.id,
      previousEpoch: current.custodyEpoch,
      custodyEpoch: nextEpoch,
      state: 'USER_OWNED' as const,
      possessionEventId: event.id,
      eventHash: hash,
      tenantAccess,
    };
    if (input.ejectRequestId) {
      await tx.ejectRequest.update({
        where: { id: input.ejectRequestId },
        data: { status: 'COMPLETED', result, completedAt: now },
      });
    }
    return result;
  }, { isolationLevel: 'Serializable' });
}

export type ProvisioningInput = AuthorizeKeyOperationInput & { nextEpoch: 1 };

/** Exactly one PROVISIONED(epoch 0, no head) -> MANAGED(epoch 1, org head). */
export async function activateProvisionedManagedAccount(
  db: PrismaClient,
  tee: TeeClient,
  input: ProvisioningInput,
  now = new Date(),
): Promise<CustodyTransitionResult> {
  if (input.request.operation !== 'TINYCLOUD_BOOTSTRAP' || input.nextEpoch !== 1) {
    throw new ManagedKeyAuthorizationError('OPERATION_NOT_ALLOWED', 'Initial activation requires the bootstrap operation at epoch 1');
  }

  return db.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT "id" FROM "managed_account" WHERE "id" = ${input.managedAccountId} FOR UPDATE`;
    const authorized = await authorizeKeyOperationInTransaction(tx, input, now);
    const current = await tx.managedAccount.findFirst({
      where: { id: authorized.managedAccountId, keyId: authorized.keyId },
      include: { custodyHead: true, organization: { select: { planEntitlements: true } } },
    });
    if (!current) throw new ManagedKeyAuthorizationError('MANAGED_ACCOUNT_NOT_FOUND', 'Managed account not found');
    const key = await tx.ethereumKey.findUnique({
      where: { id: authorized.keyId },
      select: { userId: true, sealingContext: true, sealedBlob: true, address: true },
    });
    if (!key) throw new ManagedKeyAuthorizationError('KEY_NOT_SEALABLE', 'The managed account key was not found');
    const entitlements = current.organization.planEntitlements;
    if (!entitlements || entitlements.maxManagedAccounts <= 0) {
      throw new ManagedKeyAuthorizationError('PROVISIONING_ENTITLEMENT_DENIED', 'Managed-account provisioning is not entitled');
    }
    const accountCount = await tx.managedAccount.count({
      where: { organizationId: current.organizationId, state: { in: ['PROVISIONED', 'MANAGED', 'EJECTING', 'USER_OWNED'] } },
    });
    if (accountCount > entitlements.maxManagedAccounts) {
      throw new ManagedKeyAuthorizationError('PROVISIONING_ENTITLEMENT_DENIED', 'Managed-account limit is exhausted');
    }
    if (current.state !== 'PROVISIONED' || current.custodyEpoch !== 0 || current.custodyHead) {
      throw new ManagedKeyAuthorizationError('LIFECYCLE_NOT_AUTHORIZED', 'The account has already been initialized');
    }

    const previous = await latestEvent(tx, current.id);
    const policyHash = await credentialPolicyHash(tx, current.ownerUserId);
    const eventFields = {
      managedAccountId: current.id,
      keyId: current.keyId,
      epoch: 1,
      previousEventHash: previous?.eventHash ?? null,
      fromPrincipal: 'none',
      toPrincipal: `organization:${current.organizationId}`,
      reason: 'INITIAL_ACTIVATION',
      credentialPolicyHash: policyHash,
      createdAt: now,
    } as const;
    const hash = possessionEventHash(eventFields);
    const accountKeySignature = await signPossessionEvent(tee, key, key.address, hash);
    const head = await tx.keyCustody.create({
      data: {
        managedAccountId: current.id,
        custodianType: 'ORGANIZATION',
        custodianId: current.organizationId,
        epoch: 1,
        activatedAt: now,
      },
    });
    const event = await tx.possessionEvent.create({
      data: { ...eventFields, eventHash: hash, accountKeySignature },
    });
    await tx.managedAccount.update({
      where: { id: current.id },
      data: { state: 'MANAGED', custodyEpoch: 1, custodyHeadId: head.id },
    });
    await enqueueLifecycleWebhook(tx, {
      organizationId: current.organizationId,
      managedAccountId: current.id,
      eventType: 'managed_account.created',
      custodyEpoch: 1,
      payload: {
        managedAccountId: current.id,
        externalUserId: current.externalUserId,
        address: key.address,
        state: 'MANAGED',
        policyVersion: current.policyVersion,
      },
    });
    return {
      managedAccountId: current.id,
      previousEpoch: 0,
      custodyEpoch: 1,
      state: 'MANAGED' as const,
      possessionEventId: event.id,
      eventHash: hash,
      tenantAccess: 'NOT_REQUIRED' as const,
    };
  }, { isolationLevel: 'Serializable' });
}
