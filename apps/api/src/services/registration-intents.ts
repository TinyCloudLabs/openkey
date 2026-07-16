import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { Prisma, type PrismaClient } from '@openkey/db';
import {
  createTeeClient,
  generatePrivateKey,
  getAddressFromPrivateKey,
  seal,
  type TeeClient,
} from '@openkey/tee';
import { createSealingContext } from './key-sealing';
import { resolvePlanEntitlements } from './plan-entitlements';
import { activateProvisionedManagedAccount } from './custody-transition';
import type { AuthenticatedOrganization } from './organization-credentials';
import { TinyCloudNode, serializeDelegation, type PermissionEntry } from '@tinycloud/node-sdk';
import { trustedTinyCloudBootstrapHost } from './tinycloud-bootstrap';

const INTENT_TTL_MS = 10 * 60 * 1000;
const TOKEN_PATTERN = /^okri_([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{43})$/;

type CreateIntentInput = {
  clientId: string;
  externalUserId: string;
  redirectUri: string;
  policyTemplate: string;
  policyVersion?: number;
  metadata?: Record<string, unknown>;
};

export class RegistrationIntentError extends Error {
  constructor(
    readonly code:
      | 'INVALID_REQUEST'
      | 'CLIENT_NOT_FOUND'
      | 'REDIRECT_URI_MISMATCH'
      | 'IDEMPOTENCY_CONFLICT'
      | 'INTENT_NOT_FOUND'
      | 'INTENT_EXPIRED'
      | 'INTENT_NOT_PENDING'
      | 'OWNER_PASSKEY_REQUIRED'
      | 'PROVISIONING_NOT_ALLOWED'
      | 'PLAN_LIMIT_EXCEEDED',
    message: string,
  ) {
    super(message);
    this.name = 'RegistrationIntentError';
  }
}

export type ProvisionedTenantParent = {
  cid: string;
  delegation: Prisma.InputJsonValue;
  expiresAt: Date;
  node: { nodeId: string; baseUrl: string };
};

export type TenantParentProvisioner = (input: {
  privateKey: string;
  brokerDid: string;
  organizationId: string;
  maxTtlSeconds: number;
}) => Promise<ProvisionedTenantParent>;

function tokenSecret(): string {
  const secret = process.env.REGISTRATION_INTENT_SECRET ?? process.env.BETTER_AUTH_SECRET;
  if (!secret && process.env.NODE_ENV === 'production') {
    throw new Error('REGISTRATION_INTENT_SECRET is required in production');
  }
  return secret ?? 'openkey-registration-intent-development-only';
}

function tokenSignature(id: string, nonce: string): Buffer {
  return createHmac('sha256', tokenSecret()).update(`${id}:${nonce}`).digest();
}

function intentToken(id: string, nonce: string): string {
  return `okri_${id}.${tokenSignature(id, nonce).toString('base64url')}`;
}

function parseToken(value: string): { id: string; signature: Buffer } | null {
  const match = TOKEN_PATTERN.exec(value);
  if (!match) return null;
  return { id: match[1]!, signature: Buffer.from(match[2]!, 'base64url') };
}

function requestMatches(existing: {
  publicClientId: string;
  externalUserId: string;
  redirectUri: string;
  policyTemplate: string;
  policyVersion: number;
  metadata: Prisma.JsonValue | null;
}, input: CreateIntentInput): boolean {
  return existing.publicClientId === input.clientId
    && existing.externalUserId === input.externalUserId
    && existing.redirectUri === input.redirectUri
    && existing.policyTemplate === input.policyTemplate
    && existing.policyVersion === (input.policyVersion ?? 1)
    && JSON.stringify(existing.metadata ?? null) === JSON.stringify(input.metadata ?? null);
}

export async function createRegistrationIntent(
  db: PrismaClient,
  actor: AuthenticatedOrganization,
  idempotencyKey: string,
  input: CreateIntentInput,
  now = new Date(),
) {
  if (actor.kind !== 'PROVISIONER') {
    throw new RegistrationIntentError('PROVISIONING_NOT_ALLOWED', 'A provisioner credential is required');
  }
  const client = await db.oauthClient.findFirst({
    where: { clientId: input.clientId, organizationId: actor.organizationId, disabled: false },
    select: { clientId: true, redirectUris: true },
  });
  if (!client) throw new RegistrationIntentError('CLIENT_NOT_FOUND', 'OAuth client not found');
  if (!client.redirectUris.includes(input.redirectUri)) {
    throw new RegistrationIntentError('REDIRECT_URI_MISMATCH', 'redirectUri must exactly match a registered URI');
  }

  const entitlements = await resolvePlanEntitlements(db, actor.organizationId);
  if (!entitlements || entitlements.maxManagedAccounts <= 0) {
    throw new RegistrationIntentError('PLAN_LIMIT_EXCEEDED', 'Managed-account provisioning is unavailable');
  }
  const activeCount = await db.managedAccount.count({
    where: {
      organizationId: actor.organizationId,
      state: { in: ['PROVISIONED', 'MANAGED', 'EJECTING', 'USER_OWNED'] },
    },
  });
  if (activeCount >= entitlements.maxManagedAccounts) {
    throw new RegistrationIntentError('PLAN_LIMIT_EXCEEDED', 'Managed-account limit is exhausted');
  }

  const existing = await db.registrationIntent.findUnique({
    where: { organizationId_idempotencyKey: { organizationId: actor.organizationId, idempotencyKey } },
  });
  if (existing) {
    if (!requestMatches(existing, input)) {
      throw new RegistrationIntentError('IDEMPOTENCY_CONFLICT', 'Idempotency-Key was used for a different request');
    }
    return presentIntent(existing, intentToken(existing.id, existing.nonce));
  }

  const nonce = randomBytes(32).toString('base64url');
  const intent = await db.registrationIntent.create({
    data: {
      organizationId: actor.organizationId,
      publicClientId: input.clientId,
      externalUserId: input.externalUserId,
      redirectUri: input.redirectUri,
      policyTemplate: input.policyTemplate,
      policyVersion: input.policyVersion ?? 1,
      metadata: input.metadata ? input.metadata as Prisma.InputJsonValue : Prisma.JsonNull,
      nonce,
      idempotencyKey,
      createdByCredentialId: actor.credentialId,
      expiresAt: new Date(now.getTime() + INTENT_TTL_MS),
    },
  });
  return presentIntent(intent, intentToken(intent.id, nonce));
}

function presentIntent(intent: {
  id: string;
  status: string;
  expiresAt: Date;
  publicClientId: string;
  redirectUri: string;
  managedAccountId: string | null;
}, token?: string) {
  return {
    id: intent.id,
    ...(token ? { registrationIntent: token } : {}),
    status: intent.status,
    expiresAt: intent.expiresAt,
    clientId: intent.publicClientId,
    redirectUri: intent.redirectUri,
    managedAccountId: intent.managedAccountId,
  };
}

export async function resolveRegistrationIntent(db: PrismaClient, token: string, now = new Date()) {
  const parsed = parseToken(token);
  if (!parsed) throw new RegistrationIntentError('INTENT_NOT_FOUND', 'Registration intent not found');
  const intent = await db.registrationIntent.findUnique({
    where: { id: parsed.id },
    include: { organization: { select: { id: true, name: true, plan: true, brokerDid: true } } },
  });
  if (!intent) throw new RegistrationIntentError('INTENT_NOT_FOUND', 'Registration intent not found');
  const expected = tokenSignature(intent.id, intent.nonce);
  if (parsed.signature.length !== expected.length || !timingSafeEqual(parsed.signature, expected)) {
    throw new RegistrationIntentError('INTENT_NOT_FOUND', 'Registration intent not found');
  }
  if (intent.status === 'PENDING' && intent.expiresAt <= now) {
    await db.registrationIntent.update({ where: { id: intent.id }, data: { status: 'EXPIRED' } });
    throw new RegistrationIntentError('INTENT_EXPIRED', 'Registration intent expired');
  }
  return intent;
}

const STANDARD_POLICY_GRANTS = [
  { capability: 'kv', resource: 'applications/openkey-managed', action: 'read' },
  { capability: 'kv', resource: 'applications/openkey-managed', action: 'write' },
  { capability: 'sql', resource: 'databases/openkey-managed', action: 'read' },
  { capability: 'sql', resource: 'databases/openkey-managed', action: 'query' },
  { capability: 'vault', resource: 'secrets/openkey-managed', action: 'read' },
  { capability: 'vault', resource: 'secrets/openkey-managed', action: 'write' },
] as const;

const TENANT_PARENT_PERMISSIONS: PermissionEntry[] = [
  { service: 'tinycloud.kv', space: 'applications', path: 'openkey-managed', actions: ['get', 'put'] },
  { service: 'tinycloud.sql', space: 'applications', path: 'openkey-managed', actions: ['query'] },
  { service: 'tinycloud.vault', space: 'secrets', path: 'openkey-managed', actions: ['get', 'put'] },
];

async function provisionTenantParent(input: Parameters<TenantParentProvisioner>[0]): Promise<ProvisionedTenantParent> {
  const host = trustedTinyCloudBootstrapHost();
  const expiryMs = input.maxTtlSeconds * 1_000;
  const node = new TinyCloudNode({
    privateKey: input.privateKey,
    host,
    autoCreateSpace: true,
    enablePublicSpace: false,
    includeAccountRegistryPermissions: true,
    manifest: {
      manifest_version: 1,
      app_id: `openkey-${input.organizationId}`,
      name: 'OpenKey managed tenant parent',
      did: input.brokerDid,
      defaults: false,
      prefix: '',
      includePublicSpace: false,
      expiry: `${input.maxTtlSeconds}s`,
      permissions: TENANT_PARENT_PERMISSIONS,
    },
  });
  await node.signIn();
  const { delegation } = await node.delegateTo(input.brokerDid, TENANT_PARENT_PERMISSIONS, { expiry: expiryMs });
  const info = await fetch(`${host}/info`);
  if (!info.ok) throw new Error(`TinyCloud node info failed: HTTP ${info.status}`);
  const body = await info.json() as { nodeId?: unknown };
  if (typeof body.nodeId !== 'string' || !body.nodeId) throw new Error('TinyCloud node did not identify itself');
  return {
    cid: delegation.cid,
    delegation: JSON.parse(serializeDelegation(delegation)) as Prisma.InputJsonValue,
    expiresAt: delegation.expiry,
    node: { nodeId: body.nodeId, baseUrl: host },
  };
}

export async function completeRegistrationIntent(
  db: PrismaClient,
  token: string,
  ownerUserId: string,
  options: { tee?: TeeClient; now?: Date; provisionTenantParent?: TenantParentProvisioner } = {},
) {
  const now = options.now ?? new Date();
  const intent = await resolveRegistrationIntent(db, token, now);
  if (intent.status === 'CONSUMED' && intent.managedAccountId) {
    const owned = await db.managedAccount.findFirst({
      where: { id: intent.managedAccountId, ownerUserId },
      select: { id: true },
    });
    if (!owned) throw new RegistrationIntentError('INTENT_NOT_FOUND', 'Registration intent not found');
    return tenantSafeAccount(db, intent.organizationId, intent.managedAccountId);
  }
  if (intent.status !== 'PENDING') {
    throw new RegistrationIntentError('INTENT_NOT_PENDING', 'Registration intent is not pending');
  }
  const passkey = await db.passkey.findFirst({ where: { userId: ownerUserId }, select: { id: true } });
  if (!passkey) {
    throw new RegistrationIntentError('OWNER_PASSKEY_REQUIRED', 'Create an OpenKey passkey before activating management');
  }

  let account = await db.managedAccount.findUnique({
    where: {
      organizationId_externalUserId: {
        organizationId: intent.organizationId,
        externalUserId: intent.externalUserId,
      },
    },
  });

  const tee = options.tee ?? createTeeClient();
  if (!account) {
    const privateKey = generatePrivateKey();
    const address = getAddressFromPrivateKey(privateKey);
    const sealingContext = createSealingContext();
    const sealingKey = await tee.deriveKey(`openkey/key/${sealingContext}`);
    const sealedBlob = await seal(privateKey, sealingKey);
    if (!intent.organization.brokerDid) {
      throw new RegistrationIntentError('PROVISIONING_NOT_ALLOWED', 'Organization broker DID is not configured');
    }
    const entitlements = await resolvePlanEntitlements(db, intent.organizationId);
    if (!entitlements) throw new RegistrationIntentError('PLAN_LIMIT_EXCEEDED', 'Plan entitlements are unavailable');
    const tenantParent = await (options.provisionTenantParent ?? provisionTenantParent)({
      privateKey,
      brokerDid: intent.organization.brokerDid,
      organizationId: intent.organizationId,
      maxTtlSeconds: entitlements.maxTenantDelegationTtlSeconds,
    });
    const lastKey = await db.ethereumKey.findFirst({
      where: { userId: ownerUserId },
      orderBy: { keyIndex: 'desc' },
      select: { keyIndex: true },
    });
    try {
      account = await db.$transaction(async (tx) => {
        const key = await tx.ethereumKey.create({
          data: {
            userId: ownerUserId,
            address,
            publicKey: address,
            sealedBlob,
            sealingContext,
            keyType: 'MANAGED',
            keyPurpose: 'MANAGED_ACCOUNT',
            keyIndex: (lastKey?.keyIndex ?? -1) + 1,
            label: 'Managed account',
          },
        });
        const created = await tx.managedAccount.create({
          data: {
            ownerUserId,
            organizationId: intent.organizationId,
            externalUserId: intent.externalUserId,
            keyId: key.id,
            policyTemplate: intent.policyTemplate,
            policyVersion: intent.policyVersion,
            tenantParentDelegationCid: tenantParent.cid,
            tenantParentDelegation: tenantParent.delegation,
            tenantParentExpiresAt: tenantParent.expiresAt,
          },
        });
        await tx.managedAccountPolicy.create({
          data: {
            managedAccountId: created.id,
            version: intent.policyVersion,
            template: intent.policyTemplate,
            grants: [...STANDARD_POLICY_GRANTS],
            maxTtlSeconds: 3_600,
          },
        });
        await tx.managedAccountNode.create({
          data: {
            managedAccountId: created.id,
            nodeId: tenantParent.node.nodeId,
            baseUrl: tenantParent.node.baseUrl,
            role: 'HOST',
            lastConfirmedAt: now,
          },
        });
        return created;
      }, { isolationLevel: 'Serializable' });
    } catch (error) {
      if (!error || typeof error !== 'object' || !('code' in error) || error.code !== 'P2002') throw error;
      account = await db.managedAccount.findUnique({
        where: { organizationId_externalUserId: { organizationId: intent.organizationId, externalUserId: intent.externalUserId } },
      });
      if (!account || account.ownerUserId !== ownerUserId) {
        throw new RegistrationIntentError('INTENT_NOT_FOUND', 'Registration intent not found');
      }
    }
  }

  if (account.ownerUserId !== ownerUserId) {
    throw new RegistrationIntentError('INTENT_NOT_FOUND', 'Registration intent not found');
  }
  if (account.state === 'PROVISIONED') {
    await activateProvisionedManagedAccount(db, tee, {
      type: 'organization',
      credentialId: intent.createdByCredentialId,
      managedAccountId: account.id,
      keyId: account.keyId,
      expectedEpoch: 0,
      nextEpoch: 1,
      request: { operation: 'TINYCLOUD_BOOTSTRAP' },
    }, now);
  }

  await db.registrationIntent.update({
    where: { id: intent.id },
    data: { status: 'CONSUMED', consumedAt: now, managedAccountId: account.id },
  });
  return tenantSafeAccount(db, intent.organizationId, account.id);
}

export async function tenantSafeAccount(db: PrismaClient, organizationId: string, managedAccountId: string) {
  const account = await db.managedAccount.findFirst({
    where: { id: managedAccountId, organizationId },
    select: {
      id: true,
      externalUserId: true,
      state: true,
      custodyEpoch: true,
      policyVersion: true,
      policyTemplate: true,
      tenantParentDelegationCid: true,
      revocationStatus: true,
      createdAt: true,
      updatedAt: true,
      key: { select: { address: true } },
    },
  });
  if (!account) throw new RegistrationIntentError('INTENT_NOT_FOUND', 'Managed account not found');
  return {
    managedAccountId: account.id,
    externalUserId: account.externalUserId,
    address: account.key.address,
    ownerDid: `did:pkh:eip155:1:${account.key.address}`,
    state: account.state,
    custodyEpoch: account.custodyEpoch,
    policyTemplate: account.policyTemplate,
    policyVersion: account.policyVersion,
    tenantParentDelegationCid: account.tenantParentDelegationCid,
    tenantAccess: account.revocationStatus,
    createdAt: account.createdAt,
    updatedAt: account.updatedAt,
  };
}
