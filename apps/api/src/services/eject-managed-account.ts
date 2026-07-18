import type { PrismaClient } from '@openkey/db';
import { createTeeClient, type TeeClient } from '@openkey/tee';
import { transitionManagedAccountToUserCustody, type CustodyTransitionResult } from './custody-transition';
import { ManagedKeyAuthorizationError } from './managed-key-authorization';

export class EjectRequestError extends Error {
  constructor(readonly code: 'MANAGED_ACCOUNT_NOT_FOUND' | 'IDEMPOTENCY_CONFLICT' | 'EJECT_IN_PROGRESS') {
    super(code);
    this.name = 'EjectRequestError';
  }
}

function isUniqueConstraintError(error: unknown): error is { code: 'P2002' } {
  return Boolean(error && typeof error === 'object' && 'code' in error && error.code === 'P2002');
}

export type EjectResponse = {
  managedAccountId: string;
  custody: 'USER_OWNED';
  custodyEpoch: number;
  custodyResult: 'CUSTODY_TRANSFERRED';
  tenantAccess: 'PENDING' | 'REVOKED';
  address: string;
  ownerDid: string;
  eventHash: string;
};

async function presentResult(
  db: PrismaClient,
  ownerUserId: string,
  managedAccountId: string,
  transition: Pick<CustodyTransitionResult, 'custodyEpoch' | 'tenantAccess' | 'eventHash'>,
): Promise<EjectResponse> {
  const account = await db.managedAccount.findFirst({
    where: { id: managedAccountId, ownerUserId, state: 'USER_OWNED' },
    select: { key: { select: { address: true } } },
  });
  if (!account) throw new EjectRequestError('MANAGED_ACCOUNT_NOT_FOUND');
  return {
    managedAccountId,
    custody: 'USER_OWNED',
    custodyEpoch: transition.custodyEpoch,
    custodyResult: 'CUSTODY_TRANSFERRED',
    tenantAccess: transition.tenantAccess === 'PENDING' ? 'PENDING' : 'REVOKED',
    address: account.key.address,
    ownerDid: `did:pkh:eip155:1:${account.key.address}`,
    eventHash: transition.eventHash,
  };
}

export async function ejectManagedAccount(
  db: PrismaClient,
  input: {
    ownerUserId: string;
    sessionId: string;
    managedAccountId: string;
    expectedEpoch: number;
    idempotencyKey: string;
  },
  options: { tee?: TeeClient; now?: Date } = {},
): Promise<EjectResponse> {
  const account = await db.managedAccount.findFirst({
    where: { id: input.managedAccountId, ownerUserId: input.ownerUserId },
    select: { id: true, keyId: true },
  });
  if (!account) throw new EjectRequestError('MANAGED_ACCOUNT_NOT_FOUND');

  const unique = {
    managedAccountId_ownerUserId_idempotencyKey: {
      managedAccountId: account.id,
      ownerUserId: input.ownerUserId,
      idempotencyKey: input.idempotencyKey,
    },
  } as const;
  let request = await db.ejectRequest.findUnique({ where: unique });
  if (!request) {
    try {
      request = await db.ejectRequest.create({
        data: {
          managedAccountId: account.id,
          ownerUserId: input.ownerUserId,
          idempotencyKey: input.idempotencyKey,
          expectedEpoch: input.expectedEpoch,
        },
      });
    } catch (error) {
      if (!isUniqueConstraintError(error)) throw error;
      request = await db.ejectRequest.findUniqueOrThrow({ where: unique });
    }
  }
  if (request.expectedEpoch !== input.expectedEpoch) throw new EjectRequestError('IDEMPOTENCY_CONFLICT');
  if (request.status === 'COMPLETED' && request.result) {
    return presentResult(db, input.ownerUserId, account.id, request.result as unknown as CustodyTransitionResult);
  }
  if (request.status !== 'PENDING') throw new EjectRequestError('EJECT_IN_PROGRESS');

  const transition = await transitionManagedAccountToUserCustody(db, options.tee ?? createTeeClient(), {
    type: 'user',
    sessionId: input.sessionId,
    managedAccountId: account.id,
    keyId: account.keyId,
    expectedEpoch: input.expectedEpoch,
    nextEpoch: input.expectedEpoch + 1,
    ejectRequestId: request.id,
    request: { operation: 'EJECT', reason: 'OWNER_REQUEST' },
  }, options.now);
  return presentResult(db, input.ownerUserId, account.id, transition);
}

export function ejectHttpStatus(error: unknown): number {
  if (error instanceof EjectRequestError) {
    return error.code === 'MANAGED_ACCOUNT_NOT_FOUND' ? 404 : 409;
  }
  if (error instanceof ManagedKeyAuthorizationError) {
    if (error.code === 'PASSKEY_NOT_FRESH') return 403;
    if (error.code === 'MANAGED_ACCOUNT_NOT_FOUND') return 404;
    return 409;
  }
  return 500;
}
