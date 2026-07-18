import type { PrismaClient, Prisma } from '@openkey/db';

const FRESH_PASSKEY_WINDOW_MS = 5 * 60 * 1000;

/**
 * Immutable OpenKey ceiling. Tenant policy may remove grants from this set,
 * but it can never add a capability, resource grammar, or action. Keeping
 * the three dimensions together prevents capability/resource/action
 * cross-products and deliberately excludes wildcard/admin namespaces.
 */
const OPENKEY_POLICY_CEILING = [
  { capability: 'kv', resource: /^applications\/[A-Za-z0-9][A-Za-z0-9._~-]{0,63}$/, actions: new Set(['read', 'write']) },
  { capability: 'sql', resource: /^databases\/[A-Za-z0-9][A-Za-z0-9._~-]{0,63}$/, actions: new Set(['read', 'query']) },
  { capability: 'vault', resource: /^secrets\/[A-Za-z0-9][A-Za-z0-9._~-]{0,63}$/, actions: new Set(['read', 'write']) },
] as const;

export type DelegationGrant = {
  capability: string;
  resource: string;
  action: string;
};

export type DelegationRequest = {
  grants: DelegationGrant[];
  ttlSeconds: number;
};

export type ManagedKeyOperationInput =
  | { operation: 'READ_MANAGED_ACCOUNT' }
  | { operation: 'TINYCLOUD_BOOTSTRAP' }
  | { operation: 'REQUEST_CHILD_DELEGATION'; delegation: DelegationRequest }
  | { operation: 'SIGN_APPROVED_MESSAGE'; approvalId: string }
  | { operation: 'SIGN_TYPED_DATA'; approvalId: string }
  | { operation: 'EJECT'; reason: 'OWNER_REQUEST' };

/** Only server-authenticated durable identifiers cross this boundary. */
export type AuthenticatedManagedKeyActor =
  | { type: 'organization'; credentialId: string }
  | { type: 'user'; sessionId: string };

export type AuthorizeKeyOperationInput = AuthenticatedManagedKeyActor & {
  managedAccountId: string;
  keyId: string;
  expectedEpoch: number;
  request: ManagedKeyOperationInput;
};

/** The concrete Prisma delegates used by the resolver, including transactions. */
export type AuthorizationDb = Pick<
  PrismaClient,
  'managedAccount' | 'organizationServerCredential' | 'organizationMembership' | 'session'
>;

const accountInclude = {
  key: true,
  custodyHead: true,
  policies: true,
  organization: { select: { planEntitlements: true } },
} as const satisfies Prisma.ManagedAccountInclude;

type AuthorizedAccount = Prisma.ManagedAccountGetPayload<{ include: typeof accountInclude }>;

type ResolvedActor =
  | { type: 'organization'; organizationId: string; credentialId: string; kind: 'BROKER' | 'PROVISIONER' }
  | { type: 'user'; userId: string; sessionId: string; lastPasskeyAt: Date | null };

export type ManagedKeyAuthorizationErrorCode =
  | 'MANAGED_ACCOUNT_NOT_FOUND'
  | 'AUTHENTICATED_ACTOR_NOT_FOUND'
  | 'CREDENTIAL_REVOKED'
  | 'MEMBERSHIP_REVOKED'
  | 'PASSKEY_NOT_FRESH'
  | 'CUSTODY_EPOCH_STALE'
  | 'CUSTODY_NOT_ACTIVE'
  | 'CUSTODIAN_NOT_AUTHORIZED'
  | 'LIFECYCLE_NOT_AUTHORIZED'
  | 'OPERATION_NOT_ALLOWED'
  | 'PLAN_ENTITLEMENTS_MISSING'
  | 'PLAN_POLICY_VERSION_DENIED'
  | 'PROVISIONING_ENTITLEMENT_DENIED'
  | 'DELEGATION_POLICY_DENIED'
  | 'OWNER_PASSKEY_REQUIRED'
  | 'KEY_NOT_SEALABLE';

export class ManagedKeyAuthorizationError extends Error {
  readonly code: ManagedKeyAuthorizationErrorCode;

  constructor(code: ManagedKeyAuthorizationErrorCode, message: string) {
    super(message);
    this.name = 'ManagedKeyAuthorizationError';
    this.code = code;
  }
}

function deny(code: ManagedKeyAuthorizationErrorCode, message: string): never {
  throw new ManagedKeyAuthorizationError(code, message);
}

function activeMembershipWhere(now: Date, organizationId: string, userId: string): Prisma.OrganizationMembershipWhereInput {
  return {
    organizationId,
    userId,
    status: 'ACTIVE',
    revokedAt: null,
    validFrom: { lte: now },
    OR: [{ validUntil: null }, { validUntil: { gt: now } }],
  };
}

async function resolveActor(db: AuthorizationDb, actor: AuthenticatedManagedKeyActor, now: Date): Promise<ResolvedActor> {
  if (actor.type === 'organization') {
    const credential = await db.organizationServerCredential.findUnique({
      where: { id: actor.credentialId },
      select: { id: true, organizationId: true, subjectUserId: true, kind: true, revokedAt: true },
    });
    if (!credential) deny('AUTHENTICATED_ACTOR_NOT_FOUND', 'Authenticated actor not found');
    if (credential.revokedAt || !credential.subjectUserId) {
      deny('CREDENTIAL_REVOKED', 'The organization credential is not active');
    }
    const membership = await db.organizationMembership.findFirst({
      where: activeMembershipWhere(now, credential.organizationId, credential.subjectUserId),
      select: { id: true },
    });
    if (!membership) deny('MEMBERSHIP_REVOKED', 'The organization membership is not active');
    return {
      type: 'organization',
      organizationId: credential.organizationId,
      credentialId: credential.id,
      kind: credential.kind,
    };
  }

  const session = await db.session.findUnique({
    where: { id: actor.sessionId },
    select: { id: true, userId: true, expiresAt: true, lastPasskeyAt: true },
  });
  if (!session || session.expiresAt <= now) {
    deny('AUTHENTICATED_ACTOR_NOT_FOUND', 'Authenticated actor not found');
  }
  return {
    type: 'user',
    userId: session.userId,
    sessionId: session.id,
    lastPasskeyAt: session.lastPasskeyAt,
  };
}

async function loadScopedAccount(
  db: AuthorizationDb,
  input: AuthorizeKeyOperationInput,
  actor: ResolvedActor,
): Promise<AuthorizedAccount> {
  const scope = actor.type === 'organization'
    ? { organizationId: actor.organizationId }
    : { ownerUserId: actor.userId };
  const account = await db.managedAccount.findFirst({
    where: { id: input.managedAccountId, keyId: input.keyId, ...scope },
    include: accountInclude,
  });
  if (!account) deny('MANAGED_ACCOUNT_NOT_FOUND', 'Managed account not found');
  return account;
}

function assertEpoch(account: AuthorizedAccount, input: AuthorizeKeyOperationInput, allowProvisioned: boolean) {
  if (!Number.isSafeInteger(input.expectedEpoch) || input.expectedEpoch !== account.custodyEpoch) {
    deny('CUSTODY_EPOCH_STALE', 'The managed account custody epoch is stale');
  }
  if (allowProvisioned && account.state === 'PROVISIONED' && account.custodyEpoch === 0 && !account.custodyHead) return;
  if (!account.custodyHead || account.custodyHead.managedAccountId !== account.id) {
    deny('CUSTODY_NOT_ACTIVE', 'The managed account has no custody head');
  }
  if (account.custodyHead.epoch !== input.expectedEpoch || account.custodyHead.revokedAt) {
    deny('CUSTODY_EPOCH_STALE', 'The managed account custody epoch is stale');
  }
}

function grantsFromPolicy(value: Prisma.JsonValue): DelegationGrant[] {
  if (!Array.isArray(value)) deny('DELEGATION_POLICY_DENIED', 'The managed account policy is malformed');
  const grants: DelegationGrant[] = [];
  for (const grant of value) {
    if (!grant || typeof grant !== 'object' || Array.isArray(grant)) {
      deny('DELEGATION_POLICY_DENIED', 'The managed account policy is malformed');
    }
    const candidate = grant as Record<string, unknown>;
    if (typeof candidate.capability !== 'string' || typeof candidate.resource !== 'string' || typeof candidate.action !== 'string') {
      deny('DELEGATION_POLICY_DENIED', 'The managed account policy is malformed');
    }
    grants.push({
      capability: candidate.capability,
      resource: candidate.resource,
      action: candidate.action,
    });
  }
  return grants;
}

function grantKey(grant: DelegationGrant): string {
  return `${grant.capability}\u0000${grant.resource}\u0000${grant.action}`;
}

function isWithinOpenKeyCeiling(grant: DelegationGrant): boolean {
  return OPENKEY_POLICY_CEILING.some((template) =>
    template.capability === grant.capability
    && template.resource.test(grant.resource)
    && template.actions.has(grant.action));
}

function narrowDelegation(account: AuthorizedAccount, requested: DelegationRequest): DelegationRequest {
  const policy = account.policies.find((candidate) => candidate.version === account.policyVersion);
  const entitlements = account.organization.planEntitlements;
  if (!policy) deny('DELEGATION_POLICY_DENIED', 'The managed account policy is unavailable');
  if (!entitlements) deny('PLAN_ENTITLEMENTS_MISSING', 'Organization plan entitlements are not configured');

  const policyGrants = new Set(grantsFromPolicy(policy.grants).map(grantKey));
  const grants = [...new Map(requested.grants.map((grant) => [grantKey(grant), grant])).values()];
  if (
    grants.length === 0 ||
    grants.some((grant) => !isWithinOpenKeyCeiling(grant) || !policyGrants.has(grantKey(grant))) ||
    !Number.isSafeInteger(requested.ttlSeconds) ||
    requested.ttlSeconds <= 0 ||
    requested.ttlSeconds > Math.min(policy.maxTtlSeconds, entitlements.maxTenantDelegationTtlSeconds)
  ) {
    deny('DELEGATION_POLICY_DENIED', 'The requested delegation exceeds the immutable policy or entitlement ceiling');
  }
  return { grants, ttlSeconds: requested.ttlSeconds };
}

function assertAuthorized(account: AuthorizedAccount, actor: ResolvedActor, input: AuthorizeKeyOperationInput, now: Date) {
  if (account.key.keyType !== 'MANAGED' || account.key.keyPurpose !== 'MANAGED_ACCOUNT' || !account.key.sealedBlob || !account.key.sealingContext) {
    deny('KEY_NOT_SEALABLE', 'The managed account key is not a managed sealed key');
  }
  if (account.policyVersion > (account.organization.planEntitlements?.maxTenantPolicyVersion ?? Number.MAX_SAFE_INTEGER)
    && input.request.operation !== 'READ_MANAGED_ACCOUNT' && input.request.operation !== 'EJECT') {
    deny('PLAN_POLICY_VERSION_DENIED', 'The organization plan does not permit this policy version');
  }

  const head = account.custodyHead;
  const activeOrganizationCustody = Boolean(head?.custodianType === 'ORGANIZATION' && head.custodianId === account.organizationId);
  const activeUserCustody = Boolean(head?.custodianType === 'USER' && head.custodianId === account.ownerUserId);

  if (actor.type === 'organization') {
    if (input.request.operation === 'TINYCLOUD_BOOTSTRAP') {
      if (actor.kind !== 'PROVISIONER' || account.state !== 'PROVISIONED') {
        deny('LIFECYCLE_NOT_AUTHORIZED', 'Provisioning requires a trusted provisioner in PROVISIONED state');
      }
      assertEpoch(account, input, true);
      if (!account.organization.planEntitlements || account.organization.planEntitlements.maxManagedAccounts <= 0) {
        deny('PROVISIONING_ENTITLEMENT_DENIED', 'Provisioning is not available for this organization');
      }
      return;
    }
    if (input.request.operation === 'READ_MANAGED_ACCOUNT') {
      if (!['PROVISIONED', 'MANAGED'].includes(account.state)) deny('LIFECYCLE_NOT_AUTHORIZED', 'Managed account is not readable');
      if (account.state === 'MANAGED' && !activeOrganizationCustody) deny('CUSTODIAN_NOT_AUTHORIZED', 'Organization custody is not active');
      assertEpoch(account, input, true);
      return;
    }
    if (account.state !== 'MANAGED' || !activeOrganizationCustody) {
      deny('LIFECYCLE_NOT_AUTHORIZED', 'Organization operations require active managed custody');
    }
    if (input.request.operation !== 'REQUEST_CHILD_DELEGATION' || actor.kind !== 'BROKER') {
      deny('OPERATION_NOT_ALLOWED', 'The organization credential cannot perform this operation');
    }
    assertEpoch(account, input, false);
    narrowDelegation(account, input.request.delegation);
    return;
  }

  if (input.request.operation === 'EJECT') {
    if (account.state !== 'MANAGED' || !activeOrganizationCustody) {
      deny('LIFECYCLE_NOT_AUTHORIZED', 'Eject requires active organization custody');
    }
    if (!isFreshPasskey(actor.lastPasskeyAt, now)) {
      deny('PASSKEY_NOT_FRESH', 'Eject requires a fresh passkey authentication recorded on the session');
    }
    assertEpoch(account, input, false);
    return;
  }
  if (input.request.operation === 'READ_MANAGED_ACCOUNT') {
    if (!['MANAGED', 'USER_OWNED'].includes(account.state)) deny('LIFECYCLE_NOT_AUTHORIZED', 'Managed account is not readable');
    if (account.state === 'MANAGED' && !activeOrganizationCustody) deny('CUSTODIAN_NOT_AUTHORIZED', 'Organization custody is not active');
    if (account.state === 'USER_OWNED' && !activeUserCustody) deny('CUSTODY_NOT_ACTIVE', 'User custody is not active');
    assertEpoch(account, input, false);
    return;
  }
  if (account.state !== 'USER_OWNED' || !activeUserCustody) deny('CUSTODIAN_NOT_AUTHORIZED', 'The user is not the active custodian');
  if (!['SIGN_APPROVED_MESSAGE', 'SIGN_TYPED_DATA'].includes(input.request.operation)) {
    deny('OPERATION_NOT_ALLOWED', 'The user operation is outside the custody boundary');
  }
  assertEpoch(account, input, false);
}

async function authorizeResolved(db: AuthorizationDb, input: AuthorizeKeyOperationInput, now: Date) {
  const actor = await resolveActor(db, input, now);
  const account = await loadScopedAccount(db, input, actor);
  assertAuthorized(account, actor, input, now);
  return {
    account,
    actor,
    narrowedDelegation: input.request.operation === 'REQUEST_CHILD_DELEGATION'
      ? narrowDelegation(account, input.request.delegation)
      : undefined,
  };
}

export async function authorizeKeyOperationInTransaction(
  db: AuthorizationDb,
  input: AuthorizeKeyOperationInput,
  now = new Date(),
) : Promise<AuthorizedKeyOperation> {
  const initial = await authorizeResolved(db, input, now);
  return toAuthorizationMetadata(initial, input);
}

/**
 * Metadata only. No sealing path, key material, signer, callback, or executor
 * crosses this boundary. Typed services must own canonical message creation
 * and keep their internal cryptographic primitive behind the account lock.
 */
export type AuthorizedKeyOperation = {
  managedAccountId: string;
  keyId: string;
  custodyEpoch: number;
  policyVersion: number;
  operation: ManagedKeyOperationInput['operation'];
  narrowedDelegation?: DelegationRequest;
};

export async function authorizeKeyOperation(
  db: AuthorizationDb,
  input: AuthorizeKeyOperationInput,
  options: { now?: Date } = {},
): Promise<AuthorizedKeyOperation> {
  const initial = await authorizeResolved(db, input, options.now ?? new Date());
  return toAuthorizationMetadata(initial, input);
}

function toAuthorizationMetadata(
  initial: Awaited<ReturnType<typeof authorizeResolved>>,
  input: AuthorizeKeyOperationInput,
): AuthorizedKeyOperation {
  return {
    managedAccountId: initial.account.id,
    keyId: initial.account.keyId,
    custodyEpoch: initial.account.custodyEpoch,
    policyVersion: initial.account.policyVersion,
    operation: input.request.operation,
    narrowedDelegation: initial.narrowedDelegation,
  };
}

export function isFreshPasskey(lastPasskeyAt: Date | null, now = new Date()): boolean {
  const age = lastPasskeyAt ? now.getTime() - lastPasskeyAt.getTime() : Number.POSITIVE_INFINITY;
  return age >= 0 && age <= FRESH_PASSKEY_WINDOW_MS;
}
