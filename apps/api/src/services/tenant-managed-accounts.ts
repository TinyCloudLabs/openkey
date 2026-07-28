import { createHash, randomBytes } from 'node:crypto';
import { Prisma, type PrismaClient } from '@openkey/db';
import {
  createTeeClient,
  createWalletFromPrivateKey,
  generatePrivateKey,
  getAddressFromPrivateKey,
  seal,
  unseal,
  type TeeClient,
} from '@openkey/tee';
import { isHex, validateTypedData } from 'viem';
import { deriveKeyForRecord } from './key-sealing';
import { resolvePlanEntitlements } from './plan-entitlements';
import {
  possessionEventHash,
  signPossessionEvent,
  organizationInitialActivationPolicyHash,
} from './custody-transition';

const IDENTITY_EMAIL_MAX_LENGTH = 254;
const ASCII_EMAIL_RE = /^[\x00-\x7F]+$/;
const OPERATION_REPLAY_WINDOW_MS = 24 * 60 * 60 * 1000;
const FIXED_POLICY_TEMPLATE = 'tenant-full-signing-v1';
const FIXED_POLICY_VERSION = 1;
const FIXED_POLICY_GRANTS = [
  { capability: 'kv', resource: 'applications/openkey-managed', action: 'read' },
  { capability: 'kv', resource: 'applications/openkey-managed', action: 'write' },
  { capability: 'sql', resource: 'databases/openkey-managed', action: 'read' },
  { capability: 'sql', resource: 'databases/openkey-managed', action: 'query' },
  { capability: 'vault', resource: 'secrets/openkey-managed', action: 'read' },
  { capability: 'vault', resource: 'secrets/openkey-managed', action: 'write' },
] as const;

type OperationAction =
  | 'CREATE_ACCOUNT'
  | 'SIGN_MESSAGE'
  | 'SIGN_TYPED_DATA'
  | 'SIGN_DIGEST'
  | 'SIGN_TRANSACTION'
  | 'DISABLE'
  | 'RESTORE'
  | 'BIND';

export type AuthenticatedManagementCredential = {
  credentialId: string;
  organizationId: string;
  subjectUserId: string | null;
  kind: 'MANAGEMENT';
};

export class TenantManagedAccountError extends Error {
  constructor(
    readonly code:
      | 'INVALID_REQUEST'
      | 'ACCOUNT_NOT_FOUND'
      | 'ACCOUNT_USER_OWNED'
      | 'ACCOUNT_DISABLED'
      | 'ACCOUNT_IDENTITY_CONFLICT'
      | 'IDEMPOTENCY_CONFLICT'
      | 'CUSTODY_EPOCH_STALE'
      | 'CUSTODY_NOT_ACTIVE'
      | 'OPERATION_NOT_ALLOWED'
      | 'TENANT_ACCESS_ENDED',
    message: string,
  ) {
    super(message);
    this.name = 'TenantManagedAccountError';
  }
}

export type ManagedAccountResponse = {
  id: string;
  subjectEmail: string;
  email: string;
  externalUserId: string | null;
  address: string;
  state: string;
  custodyEpoch: number;
  createdAt: Date;
  updatedAt: Date;
  tenantAccess: string;
};

export type ManagedAccountListItem = ManagedAccountResponse;
export type ManagedAccountCreationResult = ManagedAccountResponse & { created: boolean };

type AccountRecord = {
  id: string;
  ownerUserId: string | null;
  organizationId: string;
  subjectEmail: string;
  externalUserId: string | null;
  metadata: Prisma.JsonValue | null;
  keyId: string;
  state: string;
  custodyEpoch: number;
  tenantParentDelegationCid: string | null;
  revocationStatus: string;
  createdAt: Date;
  updatedAt: Date;
  key: { address: string; userId: string | null; sealedBlob: string | null; sealingContext: string | null };
  custodyHead: { custodianType: 'ORGANIZATION' | 'USER'; custodianId: string; epoch: number; revokedAt: Date | null } | null;
};

type AccountTransaction = any;

const accountSelect = {
  id: true,
  ownerUserId: true,
  organizationId: true,
  subjectEmail: true,
  externalUserId: true,
  metadata: true,
  keyId: true,
  state: true,
  custodyEpoch: true,
  tenantParentDelegationCid: true,
  revocationStatus: true,
  createdAt: true,
  updatedAt: true,
  key: { select: { address: true, userId: true, sealedBlob: true, sealingContext: true } },
  custodyHead: { select: { custodianType: true, custodianId: true, epoch: true, revokedAt: true } },
} as const;

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  const entries = Object.keys(value as Record<string, unknown>)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`);
  return `{${entries.join(',')}}`;
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function replayWindowExpiresAt(now = new Date()) {
  return new Date(now.getTime() + OPERATION_REPLAY_WINDOW_MS);
}

function trimAscii(value: string): string {
  return value.replace(/^[\t\n\r\f\v ]+|[\t\n\r\f\v ]+$/g, '');
}

// pg_advisory_xact_lock returns void. Prisma's $queryRaw cannot deserialize
// void columns, producing a "Failed to deserialize column of type 'void'" error
// on both PGlite and real PostgreSQL after the lock is successfully acquired.
// Suppress ONLY that specific void-deserialization error so the lock takes effect
// while connection failures, permission errors, and other genuine failures
// propagate to fail closed.
function catchAdvisoryLockVoidError(e: unknown): void {
  if (e instanceof Error && (
    e.message.includes("column of type 'void'") ||
    e.message.includes('Failed to deserialize column of type')
  )) return;
  throw e;
}

export function normalizeSubjectEmail(input: string): string {
  const trimmed = trimAscii(input);
  const lowered = trimmed.toLowerCase();
  if (
    !trimmed
    || lowered.length > IDENTITY_EMAIL_MAX_LENGTH
    || !ASCII_EMAIL_RE.test(lowered)
    || !lowered.includes('@')
    || lowered.startsWith('@')
    || lowered.endsWith('@')
  ) {
    throw new TenantManagedAccountError('INVALID_REQUEST', 'A valid subject email is required');
  }
  return lowered;
}

function fixedPolicy() {
  return {
    template: FIXED_POLICY_TEMPLATE,
    version: FIXED_POLICY_VERSION,
    grants: FIXED_POLICY_GRANTS,
    maxTtlSeconds: 3600,
  };
}

function accountResponse(account: AccountRecord): ManagedAccountResponse {
  return {
    id: account.id,
    subjectEmail: account.subjectEmail,
    email: account.subjectEmail,
    externalUserId: account.externalUserId,
    address: account.key.address,
    state: account.state,
    custodyEpoch: account.custodyEpoch,
    createdAt: account.createdAt,
    updatedAt: account.updatedAt,
    tenantAccess: account.revocationStatus,
  };
}

function listItem(account: AccountRecord): ManagedAccountListItem {
  return accountResponse(account);
}

async function loadAccount(tx: AccountTransaction, organizationId: string, accountId: string) {
  return tx.managedAccount.findFirst({
    where: { id: accountId, organizationId },
    select: accountSelect,
  }) as Promise<AccountRecord | null>;
}

async function loadReplay(
  tx: AccountTransaction,
  organizationId: string,
  action: OperationAction,
  idempotencyKey: string,
  requestHash: string,
  managedAccountId?: string | null,
  now = new Date(),
) {
  const existing = await tx.managedAccountOperation.findFirst({
    where: {
      organizationId,
      action,
      idempotencyKey,
    },
    orderBy: { createdAt: 'desc' },
  });
  if (!existing) return null;
  if (existing.expiresAt <= now) {
    await tx.managedAccountOperation.delete({ where: { id: existing.id } });
    return null;
  }
  if (existing.requestHash !== requestHash) {
    throw new TenantManagedAccountError('IDEMPOTENCY_CONFLICT', 'Idempotency-Key was used for a different request');
  }
  if (
    managedAccountId !== undefined
    && managedAccountId !== null
    && existing.managedAccountId !== null
    && existing.managedAccountId !== managedAccountId
  ) {
    throw new TenantManagedAccountError('IDEMPOTENCY_CONFLICT', 'Idempotency-Key was used for a different account');
  }
  return existing.response as Record<string, unknown>;
}

async function storeReplay(
  tx: AccountTransaction,
  input: {
    organizationId: string;
    managedAccountId?: string | null;
    credentialId: string;
    action: OperationAction;
    idempotencyKey: string;
    requestHash: string;
    response: Prisma.InputJsonValue;
  },
  now = new Date(),
) {
  await tx.managedAccountOperation.upsert({
    where: {
      organizationId_action_idempotencyKey: {
        organizationId: input.organizationId,
        action: input.action,
        idempotencyKey: input.idempotencyKey,
      },
    },
    create: {
      organizationId: input.organizationId,
      managedAccountId: input.managedAccountId ?? null,
      credentialId: input.credentialId,
      action: input.action,
      idempotencyKey: input.idempotencyKey,
      requestHash: input.requestHash,
      response: input.response,
      expiresAt: replayWindowExpiresAt(now),
    },
    update: {
      managedAccountId: input.managedAccountId ?? undefined,
      credentialId: input.credentialId,
      requestHash: input.requestHash,
      response: input.response,
      expiresAt: replayWindowExpiresAt(now),
    },
  });
}

async function createFixedPolicy(tx: AccountTransaction, managedAccountId: string) {
  await tx.managedAccountPolicy.upsert({
    where: {
      managedAccountId_version: {
        managedAccountId,
        version: FIXED_POLICY_VERSION,
      },
    },
    create: {
      managedAccountId,
      version: FIXED_POLICY_VERSION,
      template: FIXED_POLICY_TEMPLATE,
      grants: FIXED_POLICY_GRANTS as unknown as Prisma.InputJsonValue,
      maxTtlSeconds: 3600,
    },
    update: {
      template: FIXED_POLICY_TEMPLATE,
      grants: FIXED_POLICY_GRANTS as unknown as Prisma.InputJsonValue,
      maxTtlSeconds: 3600,
    },
  });
}

async function createInitialOrgCustody(
  tx: AccountTransaction,
  tee: TeeClient,
  accountId: string,
  key: { id: string; address: string; sealedBlob: string | null; sealingContext: string | null; userId: string | null },
  organizationId: string,
  now = new Date(),
) {
  const custody = await tx.keyCustody.create({
    data: {
      managedAccountId: accountId,
      custodianType: 'ORGANIZATION',
      custodianId: organizationId,
      epoch: 1,
      activatedAt: now,
    },
  });
  const credentialPolicyHash = organizationInitialActivationPolicyHash(organizationId, FIXED_POLICY_VERSION);
  const eventFields = {
    managedAccountId: accountId,
    keyId: key.id,
    epoch: 1,
    previousEventHash: null,
    fromPrincipal: 'none',
    toPrincipal: `organization:${organizationId}`,
    reason: 'INITIAL_ACTIVATION',
    credentialPolicyHash,
    createdAt: now,
  } as const;
  const hash = possessionEventHash(eventFields);
  const accountKeySignature = await signPossessionEvent(
    tee,
    { userId: key.userId, sealingContext: key.sealingContext, sealedBlob: key.sealedBlob },
    key.address,
    hash,
  );
  await tx.possessionEvent.create({
    data: {
      ...eventFields,
      eventHash: hash,
      accountKeySignature,
    },
  });
  await tx.managedAccount.update({
    where: { id: accountId },
    data: { state: 'MANAGED', custodyEpoch: 1, custodyHeadId: custody.id },
  });
}

function signTargetMessage(message: string, format: 'utf8' | 'hex' | undefined) {
  if (format === 'hex') {
    if (!isHex(message)) throw new TenantManagedAccountError('INVALID_REQUEST', 'message must be a hex string');
    return { raw: message as `0x${string}` };
  }
  return message;
}

function isDigest32Bytes(value: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function signAction(input: { message?: unknown; typedData?: unknown; digest?: unknown; transaction?: unknown }): OperationAction {
  if (input.message !== undefined) return 'SIGN_MESSAGE';
  if (input.typedData !== undefined) return 'SIGN_TYPED_DATA';
  if (input.digest !== undefined) return 'SIGN_DIGEST';
  if (input.transaction !== undefined) return 'SIGN_TRANSACTION';
  throw new TenantManagedAccountError('INVALID_REQUEST', 'A signing payload is required');
}

function requestHash(input: unknown): string {
  return sha256(canonicalJson(input));
}

function validateAccountStateForTenantSign(account: AccountRecord, expectedCustodyEpoch: number) {
  if (account.state === 'USER_OWNED') {
    throw new TenantManagedAccountError('TENANT_ACCESS_ENDED', 'Tenant access has ended for this account');
  }
  if (account.state === 'DISABLED') {
    throw new TenantManagedAccountError('ACCOUNT_DISABLED', 'Tenant signing is disabled for this account');
  }
  if (account.state !== 'MANAGED') {
    throw new TenantManagedAccountError('OPERATION_NOT_ALLOWED', 'Tenant signing requires active organization custody');
  }
  if (account.custodyEpoch !== expectedCustodyEpoch) {
    throw new TenantManagedAccountError('CUSTODY_EPOCH_STALE', 'The supplied custody epoch does not match the account');
  }
  if (
    !account.custodyHead
    || account.custodyHead.custodianType !== 'ORGANIZATION'
    || account.custodyHead.custodianId !== account.organizationId
    || account.custodyHead.epoch !== expectedCustodyEpoch
    || account.custodyHead.revokedAt
  ) {
    throw new TenantManagedAccountError('CUSTODY_NOT_ACTIVE', 'Tenant signing requires active organization custody');
  }
}

async function signWithAccount(
  tee: TeeClient,
  key: { sealedBlob: string | null; sealingContext: string | null; userId: string | null; address: string },
  payload: { message?: string; typedData?: unknown; digest?: `0x${string}`; transaction?: unknown },
) {
  const sealingKey = await deriveKeyForRecord(tee, key);
  const privateKey = await unseal(key.sealedBlob!, sealingKey) as `0x${string}`;
  const wallet = createWalletFromPrivateKey(privateKey);

  if (payload.message !== undefined) {
    return {
      signature: await wallet.signMessage({ message: payload.message }),
      address: key.address,
    };
  }
  if (payload.typedData !== undefined) {
    const typed = payload.typedData as Parameters<typeof wallet.signTypedData>[0];
    validateTypedData(typed);
    return {
      signature: await wallet.signTypedData(typed),
      address: key.address,
    };
  }
  if (payload.digest !== undefined) {
    // Sign the pre-computed 32-byte digest directly (no additional hashing).
    // wallet.sign({ hash }) passes the hash straight to the secp256k1 signer;
    // wallet.signMessage({ raw }) would keccak256 the digest first, producing
    // a different signature from what the caller expects.
    return {
      signature: await wallet.sign({ hash: payload.digest }),
      address: key.address,
    };
  }
  if (payload.transaction !== undefined) {
    // wallet.signTransaction accepts a viem TransactionRequest object directly.
    // parseTransaction expects a serialized RLP hex string; passing a plain
    // object would throw a TypeError ("value_.replace is not a function").
    const signedTransaction = await wallet.signTransaction(payload.transaction as any);
    return {
      signature: signedTransaction,
      address: key.address,
      signedTransaction,
    };
  }
  throw new TenantManagedAccountError('INVALID_REQUEST', 'A signing payload is required');
}

async function managementCredentialForOperation(
  db: PrismaClient,
  credentialId: string,
  organizationId: string,
) {
  const credential = await db.organizationServerCredential.findFirst({
    where: {
      id: credentialId,
      organizationId,
      revokedAt: null,
    },
    select: { id: true, organizationId: true, subjectUserId: true, kind: true },
  });
  if (!credential || credential.kind !== 'MANAGEMENT') {
    throw new TenantManagedAccountError('OPERATION_NOT_ALLOWED', 'A management credential is required');
  }
  return {
    credentialId: credential.id,
    organizationId: credential.organizationId,
    subjectUserId: credential.subjectUserId,
    kind: 'MANAGEMENT' as const,
  };
}

async function provisionManagedAccount(
  tx: AccountTransaction,
  input: {
    organizationId: string;
    email: string;
    externalUserId?: string;
    metadata?: Prisma.JsonValue;
  },
  tee: TeeClient,
  now = new Date(),
) {
  // Serialize quota consumption per-organization with an advisory lock so that
  // concurrent creates with different idempotency keys cannot both observe
  // capacity and both succeed, exceeding maxManagedAccounts.
  await (tx as any).$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${'quota:' + input.organizationId}))`.catch(catchAdvisoryLockVoidError);

  const entitlements = await resolvePlanEntitlements(tx as unknown as PrismaClient, input.organizationId);
  if (!entitlements) throw new TenantManagedAccountError('OPERATION_NOT_ALLOWED', 'Plan entitlements unavailable');
  const activeCount = await tx.managedAccount.count({
    where: {
      organizationId: input.organizationId,
      state: { in: ['PROVISIONED', 'MANAGED', 'DISABLED'] },
    },
  });
  if (activeCount >= entitlements.maxManagedAccounts) {
    throw new TenantManagedAccountError('OPERATION_NOT_ALLOWED', 'Managed-account limit is exhausted');
  }

  const subjectEmail = normalizeSubjectEmail(input.email);
  const privateKey = generatePrivateKey();
  const address = getAddressFromPrivateKey(privateKey);
  const sealingContext = randomBytes(32).toString('base64url');
  const sealingKey = await tee.deriveKey(`openkey/key/${sealingContext}`);
  const sealedBlob = await seal(privateKey, sealingKey);

  const key = await tx.ethereumKey.create({
    data: {
      address,
      publicKey: address,
      sealedBlob,
      sealingContext,
      keyType: 'MANAGED',
      keyPurpose: 'MANAGED_ACCOUNT',
      keyIndex: 0,
      label: `Managed account ${subjectEmail}`,
    },
    select: { id: true, address: true, userId: true, sealedBlob: true, sealingContext: true },
  });

  const created = await tx.managedAccount.create({
    data: {
      ownerUserId: null,
      organizationId: input.organizationId,
      subjectEmail,
      externalUserId: input.externalUserId ?? undefined,
      metadata: input.metadata ?? undefined,
      keyId: key.id,
      policyTemplate: FIXED_POLICY_TEMPLATE,
      policyVersion: FIXED_POLICY_VERSION,
    },
    select: accountSelect,
  }) as any as AccountRecord;

  await createFixedPolicy(tx, created.id);
  await createInitialOrgCustody(tx, tee, created.id, key, input.organizationId, now);

  return accountResponse({
    ...created,
    state: 'MANAGED',
    custodyEpoch: 1,
    key: { address: key.address, userId: key.userId, sealedBlob: key.sealedBlob, sealingContext: key.sealingContext },
  });
}

export async function createTenantManagedAccount(
  db: PrismaClient,
  input: {
  credential: AuthenticatedManagementCredential;
  idempotencyKey: string;
  email: string;
  externalUserId?: string;
  metadata?: Prisma.JsonValue;
  },
  tee: TeeClient = createTeeClient(),
  now = new Date(),
): Promise<ManagedAccountCreationResult> {
  const credential = await managementCredentialForOperation(db, input.credential.credentialId, input.credential.organizationId);
  const subjectEmail = normalizeSubjectEmail(input.email);
  const request = {
    email: subjectEmail,
    externalUserId: input.externalUserId ?? null,
    metadata: input.metadata ?? null,
  };
  const requestHashValue = requestHash(request);

  return db.$transaction(async (tx) => {
    const dbtx: any = tx;
    // Serialize concurrent requests sharing the same idempotency key with a
    // transaction-level advisory lock. READ COMMITTED is required (not Serializable)
    // so that after the winner commits, the loser's next statement sees the committed
    // operation row. With Serializable, PostgreSQL fixes the loser's snapshot before
    // the advisory-lock wait completes, preventing it from seeing the winner's replay.
    await dbtx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${credential.organizationId + ':CREATE_ACCOUNT:' + input.idempotencyKey}))`.catch(catchAdvisoryLockVoidError);

    const replay = await loadReplay(dbtx, credential.organizationId, 'CREATE_ACCOUNT', input.idempotencyKey, requestHashValue, undefined, now);
    if (replay) return { ...(replay as ManagedAccountResponse), created: false };

    await dbtx.managedAccountOperation.create({
      data: {
        organizationId: credential.organizationId,
        credentialId: credential.credentialId,
        action: 'CREATE_ACCOUNT',
        idempotencyKey: input.idempotencyKey,
        requestHash: requestHashValue,
        response: { status: 'PENDING' },
        expiresAt: replayWindowExpiresAt(now),
      },
    }).catch(async (createError: unknown) => {
      if (!createError || typeof createError !== 'object' || !('code' in createError) || (createError as { code?: string }).code !== 'P2002') throw createError;
      // Another concurrent transaction won the advisory lock race and already
      // created the pending operation. Re-read the replay it stored.
      const winnerReplay = await loadReplay(dbtx, credential.organizationId, 'CREATE_ACCOUNT', input.idempotencyKey, requestHashValue, undefined, now);
      if (winnerReplay) throw Object.assign(new Error('__idempotency_replay__'), { replay: winnerReplay });
    });

    const existing = await dbtx.managedAccount.findFirst({
      where: {
        organizationId: credential.organizationId,
        subjectEmail,
      },
      select: accountSelect,
    }) as any as AccountRecord | null;

    if (existing) {
      const sameIdentity = (existing.externalUserId ?? null) === (input.externalUserId ?? null)
        && canonicalJson(existing.metadata ?? null) === canonicalJson(input.metadata ?? null);
      if (existing.state === 'USER_OWNED') {
        throw new TenantManagedAccountError('ACCOUNT_USER_OWNED', 'This account is already owned by a user');
      }
      if (existing.state === 'DISABLED') {
        throw new TenantManagedAccountError('ACCOUNT_DISABLED', 'This account is disabled');
      }
      if (!sameIdentity) {
        throw new TenantManagedAccountError('ACCOUNT_IDENTITY_CONFLICT', 'An account with this email already exists');
      }
      const response = accountResponse(existing);
      await storeReplay(dbtx, {
        organizationId: credential.organizationId,
        managedAccountId: existing.id,
        credentialId: credential.credentialId,
        action: 'CREATE_ACCOUNT',
        idempotencyKey: input.idempotencyKey,
        requestHash: requestHashValue,
        response,
      }, now);
      return { ...response, created: false };
    }

    const response = await provisionManagedAccount(dbtx, {
      organizationId: credential.organizationId,
      email: subjectEmail,
      externalUserId: input.externalUserId,
      metadata: input.metadata,
    }, tee, now);
    await storeReplay(dbtx, {
      organizationId: credential.organizationId,
      managedAccountId: response.id,
      credentialId: credential.credentialId,
      action: 'CREATE_ACCOUNT',
      idempotencyKey: input.idempotencyKey,
      requestHash: requestHashValue,
      response,
    }, now);
    return { ...response, created: true };
  }, { isolationLevel: 'ReadCommitted' }).catch((err: unknown) => {
    // The advisory-lock loser surfaces the winner's replay via a sentinel error.
    if (err instanceof Error && err.message === '__idempotency_replay__') {
      const r = (err as unknown as { replay: ManagedAccountResponse }).replay;
      return { ...r, created: false };
    }
    throw err;
  });
}

export async function ensureTenantManagedAccountForVerifiedEmail(
  db: PrismaClient,
  input: {
    organizationId: string;
    email: string;
    userId?: string;
  },
  tee: TeeClient = createTeeClient(),
  now = new Date(),
): Promise<ManagedAccountCreationResult> {
  const subjectEmail = normalizeSubjectEmail(input.email);
  return db.$transaction(async (tx) => {
    const existing = await tx.managedAccount.findFirst({
      where: {
        organizationId: input.organizationId,
        subjectEmail,
      },
      select: accountSelect,
    }) as any as AccountRecord | null;

    if (existing) {
      if (existing.state === 'DISABLED') {
        throw new TenantManagedAccountError('ACCOUNT_DISABLED', 'This account is disabled');
      }
      if (existing.state === 'USER_OWNED') {
        throw new TenantManagedAccountError('TENANT_ACCESS_ENDED', 'Tenant access has ended for this account');
      }
      if (input.userId) {
        await bindAccountsForVerifiedEmailInTx(tx, { email: subjectEmail, userId: input.userId });
      }
      return { ...accountResponse(existing), created: false };
    }

    const response = await provisionManagedAccount(tx, {
      organizationId: input.organizationId,
      email: subjectEmail,
    }, tee, now);
    if (input.userId) {
      await bindAccountsForVerifiedEmailInTx(tx, { email: subjectEmail, userId: input.userId });
    }
    return { ...response, created: true };
  }, { isolationLevel: 'Serializable' });
}

export async function listTenantManagedAccounts(
  db: PrismaClient,
  organizationId: string,
  options: {
    email?: string;
    externalUserId?: string;
    status?: string;
    limit?: number;
    cursor?: string;
  } = {},
) {
  const where: any = { organizationId };
  if (options.email) where.subjectEmail = normalizeSubjectEmail(options.email);
  if (options.externalUserId !== undefined) where.externalUserId = options.externalUserId;
  if (options.status === 'disabled') where.state = 'DISABLED';
  else if (options.status === 'user_owned') where.state = 'USER_OWNED';
  else if (options.status === 'history') {
    where.state = { in: ['MANAGED', 'DISABLED', 'USER_OWNED', 'PROVISIONED', 'EJECTING', 'EXPIRED', 'FAILED'] };
  } else {
    where.state = 'MANAGED';
  }

  const take = Math.min(Math.max(options.limit ?? 50, 1), 100) + 1;
  let cursor: { id: string; createdAt: string } | null = null;
  if (options.cursor) {
    try {
      // Reject non-canonical base64url (invalid-alphabet characters, non-minimal padding).
      const decodedBytes = Buffer.from(options.cursor, 'base64url');
      if (decodedBytes.toString('base64url') !== options.cursor) {
        throw new TenantManagedAccountError('INVALID_REQUEST', 'Invalid pagination cursor');
      }
      const rawJson = decodedBytes.toString('utf8');
      const parsed: unknown = JSON.parse(rawJson);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new TenantManagedAccountError('INVALID_REQUEST', 'Invalid pagination cursor');
      }
      // Require exactly the two keys in the same insertion order that JSON.stringify
      // produces when given { id, createdAt } — "createdAt" before "id" would be
      // accepted by a naive key-presence check but is not the canonical form we generate.
      const keys = Object.keys(parsed as object);
      if (keys.length !== 2 || keys[0] !== 'id' || keys[1] !== 'createdAt') {
        throw new TenantManagedAccountError('INVALID_REQUEST', 'Invalid pagination cursor');
      }
      const { id, createdAt } = parsed as { id: unknown; createdAt: unknown };
      // Require the exact canonical ISO 8601 millisecond format produced by
      // Date.toISOString() (e.g. "2026-07-20T12:00:00.000Z"). Any other
      // Date.parse-compatible representation (e.g. "2026-07-20", RFC 2822)
      // is rejected to prevent cursor forgery via alternate date encodings.
      const ISO_MS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
      if (typeof id !== 'string' || !id.trim()
          || typeof createdAt !== 'string' || !ISO_MS_RE.test(createdAt)) {
        throw new TenantManagedAccountError('INVALID_REQUEST', 'Invalid pagination cursor');
      }
      // Require the decoded JSON to equal the exact canonical JSON.stringify form.
      // This rejects {"id":"x", "createdAt":"y"} (extra whitespace) and any
      // other non-canonical encoding that JSON.parse accepts but we do not generate.
      if (rawJson !== JSON.stringify({ id, createdAt })) {
        throw new TenantManagedAccountError('INVALID_REQUEST', 'Invalid pagination cursor');
      }
      // Validate the calendar date: the ISO_MS_RE above only validates the shape,
      // not whether month/day values are in-range (e.g. "2026-13-40T00:00:00.000Z"
      // matches the regex but is not a valid date).
      const parsedDate = new Date(createdAt);
      if (isNaN(parsedDate.getTime()) || parsedDate.toISOString() !== createdAt) {
        throw new TenantManagedAccountError('INVALID_REQUEST', 'Invalid pagination cursor');
      }
      cursor = { id, createdAt };
    } catch (err) {
      if (err instanceof TenantManagedAccountError) throw err;
      throw new TenantManagedAccountError('INVALID_REQUEST', 'Invalid pagination cursor');
    }
  }
  // Compound cursor: position using both createdAt and id (all ordering fields).
  // Prisma's cursor API only positions by a single unique field; using a where
  // clause that mirrors the compound orderBy is the only correct approach.
  const cursorWhere = cursor ? {
    OR: [
      { createdAt: { lt: new Date(cursor.createdAt) } },
      { createdAt: new Date(cursor.createdAt), id: { lt: cursor.id } },
    ],
  } : {};
  const accounts = await db.managedAccount.findMany({
    where: { ...where, ...cursorWhere },
    select: accountSelect,
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    take,
  }) as any as AccountRecord[];
  const page = accounts.slice(0, take - 1);
  const next = accounts.length > take - 1
    ? Buffer.from(JSON.stringify({ id: page[page.length - 1]?.id, createdAt: page[page.length - 1]?.createdAt.toISOString() }), 'utf8').toString('base64url')
    : null;
  return {
    accounts: page.map(listItem),
    nextCursor: next,
  };
}

export async function getTenantManagedAccount(
  db: PrismaClient,
  organizationId: string,
  accountId: string,
) {
  const account = await loadAccount(db, organizationId, accountId);
  if (!account) throw new TenantManagedAccountError('ACCOUNT_NOT_FOUND', 'Managed account not found');
  return accountResponse(account);
}

export async function tenantSafeAccount(
  db: PrismaClient,
  organizationId: string,
  managedAccountId: string,
) {
  const account = await db.managedAccount.findFirst({
    where: { id: managedAccountId, organizationId },
    select: {
      id: true,
      subjectEmail: true,
      externalUserId: true,
      state: true,
      custodyEpoch: true,
      revocationStatus: true,
      createdAt: true,
      updatedAt: true,
      key: { select: { address: true } },
    },
  });
  if (!account) throw new TenantManagedAccountError('ACCOUNT_NOT_FOUND', 'Managed account not found');
  return {
    id: account.id,
    subjectEmail: account.subjectEmail,
    externalUserId: account.externalUserId,
    address: account.key.address,
    state: account.state,
    custodyEpoch: account.custodyEpoch,
    tenantAccess: account.revocationStatus,
    createdAt: account.createdAt,
    updatedAt: account.updatedAt,
  };
}

export async function bindAccountsForVerifiedEmail(
  db: PrismaClient,
  input: { email: string; userId: string },
) {
  return db.$transaction(async (tx: any) => {
    return bindAccountsForVerifiedEmailInTx(tx, input);
  }, { isolationLevel: 'Serializable' });
}

async function bindAccountsForVerifiedEmailInTx(
  tx: any,
  input: { email: string; userId: string },
) {
  const subjectEmail = normalizeSubjectEmail(input.email);
  // Load ALL accounts for this email without pre-filtering by ownerUserId so
  // that conflicts with a different owner are detected explicitly before any
  // row is modified (fail-closed ownership verification).
  const allAccounts = await tx.managedAccount.findMany({
    where: { subjectEmail },
    select: accountSelect,
    orderBy: { createdAt: 'asc' },
  }) as any as AccountRecord[];

  // Reject the entire bind if any account is already bound to a different user.
  for (const account of allAccounts) {
    if (account.ownerUserId !== null && account.ownerUserId !== input.userId) {
      throw new TenantManagedAccountError('ACCOUNT_IDENTITY_CONFLICT', 'An account with this email is already bound to another user');
    }
    if (account.key.userId !== null && account.key.userId !== input.userId) {
      throw new TenantManagedAccountError('ACCOUNT_IDENTITY_CONFLICT', 'An account with this email is already bound to another user');
    }
  }

  // Bind only accounts that are not terminal and not yet bound.
  const bindable = allAccounts.filter((a: AccountRecord) => a.state !== 'USER_OWNED' && a.ownerUserId === null);
  for (const account of bindable) {
    await tx.managedAccount.update({
      where: { id: account.id },
      data: { ownerUserId: input.userId },
    });
    if (account.key.userId !== input.userId) {
      await tx.ethereumKey.update({
        where: { id: account.keyId },
        data: { userId: input.userId },
      });
    }
  }
  return bindable.length;
}

export async function signTenantManagedAccount(
  db: PrismaClient,
  input: {
    credential: AuthenticatedManagementCredential;
    managedAccountId: string;
    expectedCustodyEpoch: number;
    idempotencyKey: string;
    payload:
      | { message: string; format?: 'utf8' | 'hex' }
      | { typedData: unknown }
      | { digest: `0x${string}`; auditContext: string }
      | { transaction: unknown };
  },
  tee: TeeClient = createTeeClient(),
  now = new Date(),
) {
  const action = signAction(input.payload);
  const credential = await managementCredentialForOperation(db, input.credential.credentialId, input.credential.organizationId);
  if ('digest' in input.payload && (!isDigest32Bytes(input.payload.digest) || !input.payload.auditContext.trim())) {
    throw new TenantManagedAccountError('INVALID_REQUEST', 'digest must be a 32-byte hex string and auditContext is required');
  }
  const requestHashValue = requestHash({ action, expectedCustodyEpoch: input.expectedCustodyEpoch, payload: input.payload });

  return db.$transaction(async (tx: any) => {
    await tx.$queryRaw`SELECT "id" FROM "managed_account" WHERE "id" = ${input.managedAccountId} FOR UPDATE`;
    const account = await loadAccount(tx, credential.organizationId, input.managedAccountId);
    if (!account) throw new TenantManagedAccountError('ACCOUNT_NOT_FOUND', 'Managed account not found');
    validateAccountStateForTenantSign(account, input.expectedCustodyEpoch);

    const replay = await loadReplay(tx, credential.organizationId, action, input.idempotencyKey, requestHashValue, input.managedAccountId, now);
    if (replay) return replay;

    if (!account.key.sealedBlob || !account.key.sealingContext) {
      throw new TenantManagedAccountError('OPERATION_NOT_ALLOWED', 'The managed key is not sealable');
    }

    const payload =
      'message' in input.payload ? { message: signTargetMessage(input.payload.message, input.payload.format) }
      : 'typedData' in input.payload ? { typedData: input.payload.typedData }
      : 'digest' in input.payload ? { digest: input.payload.digest }
      : { transaction: input.payload.transaction };

    const result = await signWithAccount(tee, account.key, payload as any);
    await storeReplay(tx, {
      organizationId: account.organizationId,
      managedAccountId: account.id,
      credentialId: credential.credentialId,
      action,
      idempotencyKey: input.idempotencyKey,
      requestHash: requestHashValue,
      response: result as Prisma.InputJsonValue,
    }, now);
    return result;
  }, { isolationLevel: 'Serializable' });
}

export async function disableTenantManagedAccount(
  db: PrismaClient,
  input: {
    credential: AuthenticatedManagementCredential;
    managedAccountId: string;
    expectedCustodyEpoch: number;
    idempotencyKey: string;
  },
  now = new Date(),
) {
  const credential = await managementCredentialForOperation(db, input.credential.credentialId, input.credential.organizationId);
  const requestHashValue = requestHash({ expectedCustodyEpoch: input.expectedCustodyEpoch });
  return db.$transaction(async (tx: any) => {
    await tx.$queryRaw`SELECT pg_advisory_xact_lock(hashtext(${'oauth-lifecycle:' + input.managedAccountId}))`.catch(catchAdvisoryLockVoidError);
    await tx.$queryRaw`SELECT "id" FROM "managed_account" WHERE "id" = ${input.managedAccountId} FOR UPDATE`;
    const account = await loadAccount(tx, credential.organizationId, input.managedAccountId);
    if (!account) throw new TenantManagedAccountError('ACCOUNT_NOT_FOUND', 'Managed account not found');
    if (account.custodyEpoch !== input.expectedCustodyEpoch) throw new TenantManagedAccountError('CUSTODY_EPOCH_STALE', 'The supplied custody epoch does not match the account');
    if (
      !account.custodyHead
      || account.custodyHead.custodianType !== 'ORGANIZATION'
      || account.custodyHead.custodianId !== account.organizationId
      || account.custodyHead.revokedAt
    ) {
      throw new TenantManagedAccountError('CUSTODY_NOT_ACTIVE', 'Tenant signing requires active organization custody');
    }
    const replay = await loadReplay(tx, credential.organizationId, 'DISABLE', input.idempotencyKey, requestHashValue, input.managedAccountId, now);
    if (replay) return replay;
    if (account.state === 'USER_OWNED') throw new TenantManagedAccountError('TENANT_ACCESS_ENDED', 'Tenant access has ended for this account');
    if (account.state === 'DISABLED' && account.custodyEpoch !== input.expectedCustodyEpoch) throw new TenantManagedAccountError('CUSTODY_EPOCH_STALE', 'The supplied custody epoch does not match the account');
    if (account.state === 'DISABLED') {
      const response = accountResponse(account);
      await storeReplay(tx, {
        organizationId: account.organizationId,
        managedAccountId: account.id,
        credentialId: credential.credentialId,
        action: 'DISABLE',
        idempotencyKey: input.idempotencyKey,
        requestHash: requestHashValue,
        response,
      }, now);
      return response;
    }
    const updated = await tx.managedAccount.update({
      where: { id: account.id },
      data: { state: 'DISABLED', brokerAccessDisabledAt: now },
      select: accountSelect,
    }) as any as AccountRecord;
    // Revoke all tenant-managed OAuth tokens for this user so that already-issued
    // access tokens and refresh tokens cannot be used after the account is disabled.
    if (account.ownerUserId) {
      const clientIds = (await tx.oauthClient.findMany({
        where: { organizationId: account.organizationId, mode: 'TENANT_MANAGED' },
        select: { clientId: true },
      })).map((c: { clientId: string }) => c.clientId);
      if (clientIds.length > 0) {
        await tx.oauthAccessToken.updateMany({
          where: { userId: account.ownerUserId, clientId: { in: clientIds } },
          data: { expiresAt: new Date(0) },
        });
        await tx.oauthRefreshToken.updateMany({
          where: { userId: account.ownerUserId, clientId: { in: clientIds } },
          data: { revoked: now },
        });
      }
    }
    const response = accountResponse(updated);
    await storeReplay(tx, {
      organizationId: updated.organizationId,
      managedAccountId: updated.id,
      credentialId: credential.credentialId,
      action: 'DISABLE',
      idempotencyKey: input.idempotencyKey,
      requestHash: requestHashValue,
      response,
    }, now);
    return response;
  }, { isolationLevel: 'ReadCommitted' });
}

export async function restoreTenantManagedAccount(
  db: PrismaClient,
  input: {
    credential: AuthenticatedManagementCredential;
    managedAccountId: string;
    expectedCustodyEpoch: number;
    idempotencyKey: string;
  },
  now = new Date(),
) {
  const credential = await managementCredentialForOperation(db, input.credential.credentialId, input.credential.organizationId);
  const requestHashValue = requestHash({ expectedCustodyEpoch: input.expectedCustodyEpoch });
  return db.$transaction(async (tx: any) => {
    await tx.$queryRaw`SELECT "id" FROM "managed_account" WHERE "id" = ${input.managedAccountId} FOR UPDATE`;
    const account = await loadAccount(tx, credential.organizationId, input.managedAccountId);
    if (!account) throw new TenantManagedAccountError('ACCOUNT_NOT_FOUND', 'Managed account not found');
    if (account.custodyEpoch !== input.expectedCustodyEpoch) throw new TenantManagedAccountError('CUSTODY_EPOCH_STALE', 'The supplied custody epoch does not match the account');
    if (
      !account.custodyHead
      || account.custodyHead.custodianType !== 'ORGANIZATION'
      || account.custodyHead.custodianId !== account.organizationId
      || account.custodyHead.revokedAt
    ) {
      throw new TenantManagedAccountError('CUSTODY_NOT_ACTIVE', 'Tenant signing requires active organization custody');
    }
    const replay = await loadReplay(tx, credential.organizationId, 'RESTORE', input.idempotencyKey, requestHashValue, input.managedAccountId, now);
    if (replay) return replay;
    if (account.state === 'USER_OWNED') throw new TenantManagedAccountError('TENANT_ACCESS_ENDED', 'Tenant access has ended for this account');
    if (account.state !== 'DISABLED') throw new TenantManagedAccountError('OPERATION_NOT_ALLOWED', 'Only DISABLED accounts can be restored');
    const updated = await tx.managedAccount.update({
      where: { id: account.id },
      data: { state: 'MANAGED' },
      select: accountSelect,
    }) as any as AccountRecord;
    const response = accountResponse(updated);
    await storeReplay(tx, {
      organizationId: updated.organizationId,
      managedAccountId: updated.id,
      credentialId: credential.credentialId,
      action: 'RESTORE',
      idempotencyKey: input.idempotencyKey,
      requestHash: requestHashValue,
      response,
    }, now);
    return response;
  }, { isolationLevel: 'Serializable' });
}

export async function resolveManagementCredential(
  db: PrismaClient,
  credentialId: string,
  organizationId: string,
) {
  return managementCredentialForOperation(db, credentialId, organizationId);
}
