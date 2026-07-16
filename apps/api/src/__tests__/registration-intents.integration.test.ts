import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { createPrismaClient, type PrismaClient } from '@openkey/db';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { authenticateOrganizationCredential, issueOrganizationCredential } from '../services/organization-credentials';
import { createRegistrationIntent, completeRegistrationIntent, RegistrationIntentError, tenantSafeAccount } from '../services/registration-intents';
import { PUBLIC_PLAN_ENTITLEMENTS } from '../services/plan-entitlements';
import { ejectManagedAccount } from '../services/eject-managed-account';
import { processPendingRevocations } from '../services/tenant-revocation';
import { authorizeKeyOperation } from '../services/managed-key-authorization';
import { signWithUserOwnedManagedAccount } from '../services/personal-managed-key';
import { verifyMessage } from 'viem';
import { createHmac } from 'node:crypto';
import { createWebhookEndpoint, deliverWebhook } from '../services/lifecycle-webhooks';

const migrationNames = [
  '0_init',
  '20260303_add_user_encryption_key',
  '20260628_add_auto_sign_enabled',
  '20260630_add_tinycloud_bootstrap_state',
  '20260714_origin_main_schema_catchup',
  '20260715_0001_managed_accounts_phase_a_fix',
  '20260715_0002_managed_accounts_registration_api',
  '20260715_0003_managed_accounts_eject_api',
  '20260715_0004_managed_accounts_webhooks',
];

describe('managed-account registration', () => {
  let directory: string;
  let db: PrismaClient;
  let orgAIntentToken = '';

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'openkey-registration-'));
    const raw = new PGlite(directory);
    for (const name of migrationNames) {
      await raw.exec(await readFile(`packages/db/prisma/migrations/${name}/migration.sql`, 'utf8'));
    }
    await raw.close();
    db = createPrismaClient({ connectionString: `pglite:${directory}` });

    await db.user.create({
      data: { id: 'owner', email: 'owner@example.test', emailVerified: true },
    });
    await db.passkey.create({
      data: {
        id: 'passkey', userId: 'owner', publicKey: 'public-key', credentialID: 'credential-id',
        deviceType: 'singleDevice', backedUp: false,
      },
    });
    for (const [id, name] of [['org-a', 'Organization A'], ['org-b', 'Organization B']] as const) {
      await db.organization.create({ data: { id, name, brokerDid: `did:key:z${id}` } });
      await db.organizationMembership.create({
        data: { id: `membership-${id}`, organizationId: id, userId: 'owner', role: 'ADMIN' },
      });
      await db.planEntitlements.create({ data: { organizationId: id, ...PUBLIC_PLAN_ENTITLEMENTS.FREE } });
      await db.oauthClient.create({
        data: {
          id: `client-row-${id}`, clientId: `client-${id}`, organizationId: id, name: `${name} app`,
          redirectUris: [`https://${id}.example/callback`], scopes: ['openid'], contacts: [], public: true,
        },
      });
    }
  }, 30_000);

  afterAll(async () => {
    await db?.$disconnect();
    await rm(directory, { recursive: true, force: true });
  });

  test('one OpenKey owner gets isolated keys for two tenants with the same external subject', async () => {
    const accounts = [];
    for (const id of ['org-a', 'org-b'] as const) {
      const issued = await issueOrganizationCredential(db, {
        organizationId: id, subjectUserId: 'owner', name: 'Provisioner', kind: 'PROVISIONER',
      });
      const actor = await authenticateOrganizationCredential(db, issued.secret);
      const request = {
        clientId: `client-${id}`,
        externalUserId: 'same-external-user',
        redirectUri: `https://${id}.example/callback`,
        policyTemplate: 'tinycloud-standard-v1',
      };
      const first = await createRegistrationIntent(db, actor, 'registration-1', request);
      const replay = await createRegistrationIntent(db, actor, 'registration-1', request);
      expect(replay.registrationIntent).toBe(first.registrationIntent);
      if (id === 'org-a') orgAIntentToken = first.registrationIntent!;
      accounts.push(await completeRegistrationIntent(db, first.registrationIntent!, 'owner', {
        provisionTenantParent: async ({ organizationId, maxTtlSeconds }) => ({
          cid: `bafy-${organizationId}`,
          delegation: { Authorization: `ucan-${organizationId}` },
          expiresAt: new Date(Date.now() + maxTtlSeconds * 1_000),
          node: { nodeId: `node-${organizationId}`, baseUrl: 'https://node.example' },
        }),
      }));
    }

    expect(accounts[0]?.state).toBe('MANAGED');
    expect(accounts[1]?.state).toBe('MANAGED');
    expect(accounts[0]?.externalUserId).toBe('same-external-user');
    expect(accounts[1]?.externalUserId).toBe('same-external-user');
    expect(accounts[0]?.managedAccountId).not.toBe(accounts[1]?.managedAccountId);
    expect(accounts[0]?.address).not.toBe(accounts[1]?.address);
    await expect(completeRegistrationIntent(db, orgAIntentToken, 'different-user'))
      .rejects.toMatchObject({ code: 'INTENT_NOT_FOUND' });

    await expect(tenantSafeAccount(db, 'org-a', accounts[1]!.managedAccountId))
      .rejects.toMatchObject({ code: 'INTENT_NOT_FOUND' } satisfies Partial<RegistrationIntentError>);
  }, 30_000);

  test('redirect and idempotency bindings fail closed without leaking another tenant', async () => {
    const credential = await db.organizationServerCredential.findFirstOrThrow({ where: { organizationId: 'org-a' } });
    const actor = { credentialId: credential.id, organizationId: 'org-a', subjectUserId: 'owner', kind: 'PROVISIONER' as const };
    await expect(createRegistrationIntent(db, actor, 'bad-redirect', {
      clientId: 'client-org-a', externalUserId: 'x', redirectUri: 'https://evil.example/callback', policyTemplate: 'tinycloud-standard-v1',
    })).rejects.toMatchObject({ code: 'REDIRECT_URI_MISMATCH' });
    await expect(createRegistrationIntent(db, actor, 'cross-client', {
      clientId: 'client-org-b', externalUserId: 'x', redirectUri: 'https://org-b.example/callback', policyTemplate: 'tinycloud-standard-v1',
    })).rejects.toMatchObject({ code: 'CLIENT_NOT_FOUND' });
  });

  test('owner eject is idempotent, preserves identity, blocks the tenant, and converges revocation', async () => {
    const account = await db.managedAccount.findUniqueOrThrow({
      where: { organizationId_externalUserId: { organizationId: 'org-a', externalUserId: 'same-external-user' } },
      include: { key: true },
    });
    await db.session.create({
      data: {
        id: 'fresh-session', userId: 'owner', token: 'fresh-session-token',
        expiresAt: new Date(Date.now() + 60_000), lastPasskeyAt: new Date(),
      },
    });
    const input = {
      ownerUserId: 'owner', sessionId: 'fresh-session', managedAccountId: account.id,
      expectedEpoch: 1, idempotencyKey: 'eject-once',
    };
    const first = await ejectManagedAccount(db, input);
    const replay = await ejectManagedAccount(db, input);
    expect(replay).toEqual(first);
    expect(first.address).toBe(account.key.address);
    expect(first.custody).toBe('USER_OWNED');
    expect(first.tenantAccess).toBe('PENDING');
    const personalSignature = await signWithUserOwnedManagedAccount(db, {
      sessionId: 'fresh-session', managedAccountId: account.id, keyId: account.keyId,
      expectedEpoch: 2, approvalId: 'personal-approval', message: 'same-key-after-eject',
    });
    expect(personalSignature.address).toBe(account.key.address);
    expect(await verifyMessage({
      address: account.key.address as `0x${string}`,
      message: 'same-key-after-eject',
      signature: personalSignature.signature as `0x${string}`,
    })).toBe(true);

    const broker = await issueOrganizationCredential(db, {
      organizationId: 'org-a', subjectUserId: 'owner', name: 'Broker', kind: 'BROKER',
    });
    const actor = await authenticateOrganizationCredential(db, broker.secret);
    await expect(authorizeKeyOperation(db, {
      type: 'organization', credentialId: actor.credentialId, managedAccountId: account.id,
      keyId: account.keyId, expectedEpoch: 2,
      request: {
        operation: 'REQUEST_CHILD_DELEGATION',
        delegation: { grants: [{ capability: 'kv', resource: 'applications/openkey-managed', action: 'read' }], ttlSeconds: 60 },
      },
    })).rejects.toMatchObject({ code: 'LIFECYCLE_NOT_AUTHORIZED' });

    const processed = await processPendingRevocations(db, {
      transport: async ({ delegationCid }) => ({ confirmed: true, receipt: { delegationCid, revoked: true } }),
    });
    expect(processed).toHaveLength(1);
    expect(processed[0]?.ok).toBe(true);
    expect(await db.managedAccount.findUnique({ where: { id: account.id }, select: { revocationStatus: true } }))
      .toEqual({ revocationStatus: 'REVOKED' });
  }, 30_000);

  test('Free and Pro enforce different provisioning limits and lifecycle webhooks are signed', async () => {
    const orgAProvisioner = await db.organizationServerCredential.findFirstOrThrow({ where: { organizationId: 'org-a', kind: 'PROVISIONER' } });
    const actorA = { credentialId: orgAProvisioner.id, organizationId: 'org-a', subjectUserId: 'owner', kind: 'PROVISIONER' as const };
    await db.planEntitlements.update({ where: { organizationId: 'org-a' }, data: { maxManagedAccounts: 1 } });
    await expect(createRegistrationIntent(db, actorA, 'free-over-limit', {
      clientId: 'client-org-a', externalUserId: 'free-over-limit', redirectUri: 'https://org-a.example/callback', policyTemplate: 'tinycloud-standard-v1',
    })).rejects.toMatchObject({ code: 'PLAN_LIMIT_EXCEEDED' });

    await db.organization.update({ where: { id: 'org-b' }, data: { plan: 'PRO', billingState: 'ACTIVE' } });
    await db.planEntitlements.update({ where: { organizationId: 'org-b' }, data: PUBLIC_PLAN_ENTITLEMENTS.PRO });
    const orgBProvisioner = await db.organizationServerCredential.findFirstOrThrow({ where: { organizationId: 'org-b', kind: 'PROVISIONER' } });
    const actorB = { credentialId: orgBProvisioner.id, organizationId: 'org-b', subjectUserId: 'owner', kind: 'PROVISIONER' as const };
    const endpoint = await createWebhookEndpoint(db, {
      organizationId: 'org-b', url: 'https://hooks.example/openkey', eventTypes: ['managed_account.created'],
    });
    const intent = await createRegistrationIntent(db, actorB, 'pro-second-account', {
      clientId: 'client-org-b', externalUserId: 'pro-second-account', redirectUri: 'https://org-b.example/callback', policyTemplate: 'tinycloud-standard-v1',
    });
    await completeRegistrationIntent(db, intent.registrationIntent!, 'owner', {
      provisionTenantParent: async () => ({
        cid: 'bafy-pro-second', delegation: { Authorization: 'ucan-pro-second' },
        expiresAt: new Date(Date.now() + 60_000), node: { nodeId: 'node-pro-second', baseUrl: 'https://node.example' },
      }),
    });
    const delivery = await db.webhookDelivery.findFirstOrThrow({ where: { endpointId: endpoint.endpoint.id } });
    let captured: { body: string; signature: string } | undefined;
    await deliverWebhook(db, delivery.id, {
      now: new Date('2026-07-15T12:00:00.000Z'),
      fetch: async (_url, init) => {
        captured = {
          body: String(init?.body),
          signature: new Headers(init?.headers).get('OpenKey-Signature')!,
        };
        return new Response('accepted', { status: 200 });
      },
    });
    const timestamp = Math.floor(new Date('2026-07-15T12:00:00.000Z').getTime() / 1_000);
    const expected = createHmac('sha256', endpoint.secret).update(`${timestamp}.${captured!.body}`).digest('hex');
    expect(captured!.signature).toBe(`t=${timestamp},v1=${expected}`);
    expect(JSON.parse(captured!.body).type).toBe('managed_account.created');
    expect(await db.webhookDelivery.findUnique({ where: { id: delivery.id }, select: { status: true } })).toEqual({ status: 'DELIVERED' });
  }, 30_000);
});
