import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { createPrismaClient, type PrismaClient } from '@openkey/db';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { authenticateOrganizationCredential, issueOrganizationCredential } from '../services/organization-credentials';
import {
  createTenantManagedAccount,
  signTenantManagedAccount,
  disableTenantManagedAccount,
  restoreTenantManagedAccount,
  normalizeSubjectEmail,
  bindAccountsForVerifiedEmail,
} from '../services/tenant-managed-accounts';
import { PUBLIC_PLAN_ENTITLEMENTS } from '../services/plan-entitlements';
import { ejectManagedAccount } from '../services/eject-managed-account';
import { processPendingRevocations } from '../services/tenant-revocation';
import { authorizeKeyOperation } from '../services/managed-key-authorization';
import { signWithUserOwnedManagedAccount } from '../services/personal-managed-key';
import { possessionEventHash, organizationInitialActivationPolicyHash } from '../services/custody-transition';
import { verifyMessage } from 'viem';
import { createHmac } from 'node:crypto';
import {
  createWebhookEndpoint,
  deliverWebhook,
  WebhookEndpointLimitError,
} from '../services/lifecycle-webhooks';

const migrationNames = [
  '0_init',
  '20260303_add_user_encryption_key',
  '20260628_add_auto_sign_enabled',
  '20260630_add_tinycloud_bootstrap_state',
  '20260714_origin_main_schema_catchup',
  '20260714_zz_origin_main_db_push_reconciliation',
  '20260715_0001_managed_accounts_phase_a_fix',
  '20260715_0002_managed_accounts_registration_api',
  '20260715_0003_managed_accounts_eject_api',
  '20260715_0004_managed_accounts_webhooks',
  '20260720_0001_tenant_managed_email_accounts',
  '20260720_0002_management_credential_default',
  '20260720_0003_tenant_managed_account_guard_fixes',
  '20260720_0004_drop_registration_intent',
  '20260721_0001_better_auth_1_6_oauth_refresh_tokens',
  '20260728_0001_oauth_tenant_lifecycle_guard',
  '20260728_0002_coordinationos_session_grants',
  '20260730_0001_oauth_client_tinycloud_session_policy',
  '20260805_0001_canonical_tinycloud_key',
  '20260805_0002_tinycloud_manage_key_app_preferences',
  '20260805_0003_tinycloud_manage_key_global_preference',
  '20260806_0001_tinycloud_manage_key_lifecycle',
];

describe('tenant-managed-account provisioning (new API)', () => {
  let directory: string;
  let db: PrismaClient;
  let orgACredential: { credentialId: string; organizationId: string; subjectUserId: string | null; kind: 'MANAGEMENT' };
  let orgBCredential: { credentialId: string; organizationId: string; subjectUserId: string | null; kind: 'MANAGEMENT' };

  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'openkey-tenant-'));
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
      await db.organization.create({ data: { id, name } });
      await db.organizationMembership.create({
        data: { id: `membership-${id}`, organizationId: id, userId: 'owner', role: 'ADMIN' },
      });
      await db.planEntitlements.create({ data: { organizationId: id, ...PUBLIC_PLAN_ENTITLEMENTS.FREE } });
      await db.oauthClient.create({
        data: {
          id: `client-row-${id}`, clientId: `client-${id}`, organizationId: id, name: `${name} app`,
          redirectUris: [`https://${id}.example/callback`], scopes: ['openid'], contacts: [], public: true,
          mode: 'TENANT_MANAGED',
        },
      });
    }

    const issued = await issueOrganizationCredential(db, {
      organizationId: 'org-a', subjectUserId: 'owner', name: 'Management Key',
    });
    const actor = await authenticateOrganizationCredential(db, issued.secret);
    orgACredential = { credentialId: actor.credentialId, organizationId: actor.organizationId, subjectUserId: actor.subjectUserId, kind: 'MANAGEMENT' as const };

    const issuedB = await issueOrganizationCredential(db, {
      organizationId: 'org-b', subjectUserId: 'owner', name: 'Management Key',
    });
    const actorB = await authenticateOrganizationCredential(db, issuedB.secret);
    orgBCredential = { credentialId: actorB.credentialId, organizationId: actorB.organizationId, subjectUserId: actorB.subjectUserId, kind: 'MANAGEMENT' as const };
  }, 30_000);

  afterAll(async () => {
    await db?.$disconnect();
    await rm(directory, { recursive: true, force: true });
  });

  test('normalizeSubjectEmail validates format', () => {
    expect(() => normalizeSubjectEmail('not-an-email')).toThrow();
    expect(() => normalizeSubjectEmail('@')).toThrow();
    expect(() => normalizeSubjectEmail('a@')).toThrow();
    expect(() => normalizeSubjectEmail('@b')).toThrow();
    expect(normalizeSubjectEmail('  User@Example.COM  ')).toBe('user@example.com');
    expect(() => normalizeSubjectEmail('élise@example.test')).toThrow();
    expect(() => normalizeSubjectEmail('a'.repeat(300) + '@b.com')).toThrow();
  });

  test('creates isolated tenant accounts for two orgs with the same email', async () => {
    const accounts = [];
    for (const [orgId, credential] of [['org-a', orgACredential], ['org-b', orgBCredential]] as const) {
      const account = await createTenantManagedAccount(db, {
        credential,
        idempotencyKey: `create-${orgId}-1`,
        email: 'alice@example.test',
        externalUserId: 'alice-external',
        metadata: { source: orgId },
      });
      accounts.push({ ...account, orgId });
    }
    expect(accounts[0]!.state).toBe('MANAGED');
    expect(accounts[1]!.state).toBe('MANAGED');
    expect(accounts[0]!.subjectEmail).toBe('alice@example.test');
    expect(accounts[1]!.subjectEmail).toBe('alice@example.test');
    expect(accounts[0]!.id).not.toBe(accounts[1]!.id);
    expect(accounts[0]!.address).not.toBe(accounts[1]!.address);
    expect(accounts[0]!.custodyEpoch).toBe(1);
    expect(accounts[1]!.custodyEpoch).toBe(1);
  }, 30_000);

  test('idempotency: same key returns same account, different payload returns conflict', async () => {
    const first = await createTenantManagedAccount(db, {
      credential: orgACredential,
      idempotencyKey: 'idem-test-1',
      email: 'bob@example.test',
    });
    const replay = await createTenantManagedAccount(db, {
      credential: orgACredential,
      idempotencyKey: 'idem-test-1',
      email: 'bob@example.test',
    });
    expect(replay.id).toBe(first.id);

    await expect(createTenantManagedAccount(db, {
      credential: orgACredential,
      idempotencyKey: 'idem-test-1',
      email: 'different@example.test',
    })).rejects.toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' });
  }, 30_000);

  test('identity conflict: same email different externalUserId', async () => {
    await createTenantManagedAccount(db, {
      credential: orgACredential,
      idempotencyKey: 'charlie-create',
      email: 'charlie@example.test',
      externalUserId: 'charlie-v1',
    });
    await expect(createTenantManagedAccount(db, {
      credential: orgACredential,
      idempotencyKey: 'charlie-conflict',
      email: 'charlie@example.test',
      externalUserId: 'charlie-v2',
    })).rejects.toMatchObject({ code: 'ACCOUNT_IDENTITY_CONFLICT' });
  }, 30_000);

  test('disable and restore lifecycle', async () => {
    const account = await createTenantManagedAccount(db, {
      credential: orgACredential,
      idempotencyKey: 'disable-restore-create',
      email: 'disable-restore@example.test',
    });
    expect(account.state).toBe('MANAGED');

    const disabled = await disableTenantManagedAccount(db, {
      credential: orgACredential,
      managedAccountId: account.id,
      expectedCustodyEpoch: account.custodyEpoch,
      idempotencyKey: 'disable-test',
    });
    expect(disabled.state).toBe('DISABLED');

    await expect(restoreTenantManagedAccount(db, {
      credential: orgACredential,
      managedAccountId: account.id,
      expectedCustodyEpoch: account.custodyEpoch,
      idempotencyKey: 'restore-test',
    })).resolves.toMatchObject({ state: 'MANAGED' });
  }, 30_000);

  test('restore rejects non-DISABLED accounts', async () => {
    const account = await createTenantManagedAccount(db, {
      credential: orgACredential,
      idempotencyKey: 'managed-no-restore',
      email: 'managed-no-restore@example.test',
    });
    await expect(restoreTenantManagedAccount(db, {
      credential: orgACredential,
      managedAccountId: account.id,
      expectedCustodyEpoch: account.custodyEpoch,
      idempotencyKey: 'restore-managed',
    })).rejects.toMatchObject({ code: 'OPERATION_NOT_ALLOWED' });
  }, 30_000);

  test('signing disabled account is rejected', async () => {
    const account = await createTenantManagedAccount(db, {
      credential: orgACredential,
      idempotencyKey: 'sign-disabled-create',
      email: 'sign-disabled@example.test',
    });
    await disableTenantManagedAccount(db, {
      credential: orgACredential,
      managedAccountId: account.id,
      expectedCustodyEpoch: account.custodyEpoch,
      idempotencyKey: 'sign-disabled-disable',
    });
    await expect(signTenantManagedAccount(db, {
      credential: orgACredential,
      managedAccountId: account.id,
      expectedCustodyEpoch: account.custodyEpoch,
      idempotencyKey: 'sign-disabled-sign',
      payload: { message: 'hello', format: 'utf8' },
    })).rejects.toMatchObject({ code: 'ACCOUNT_DISABLED' });
  }, 30_000);

  test('cross-tenant signing is denied', async () => {
    const accountA = await createTenantManagedAccount(db, {
      credential: orgACredential,
      idempotencyKey: 'cross-tenant-create',
      email: 'cross-tenant@example.test',
    });
    await expect(signTenantManagedAccount(db, {
      credential: orgBCredential,
      managedAccountId: accountA.id,
      expectedCustodyEpoch: accountA.custodyEpoch,
      idempotencyKey: 'cross-tenant-sign',
      payload: { message: 'cross org', format: 'utf8' },
    })).rejects.toMatchObject({ code: 'ACCOUNT_NOT_FOUND' });
  }, 30_000);

  test('stale custody epoch is rejected', async () => {
    const account = await createTenantManagedAccount(db, {
      credential: orgACredential,
      idempotencyKey: 'stale-epoch-create',
      email: 'stale-epoch@example.test',
    });
    await expect(signTenantManagedAccount(db, {
      credential: orgACredential,
      managedAccountId: account.id,
      expectedCustodyEpoch: 999,
      idempotencyKey: 'stale-epoch-sign',
      payload: { message: 'stale', format: 'utf8' },
    })).rejects.toMatchObject({ code: 'CUSTODY_EPOCH_STALE' });
  }, 30_000);

  test('owner eject is idempotent, preserves identity, blocks tenant signing', async () => {
    const createdAccount = await createTenantManagedAccount(db, {
      credential: orgACredential,
      idempotencyKey: 'eject-account-create',
      email: 'eject-user@example.test',
    });

    const account = await db.managedAccount.findUniqueOrThrow({
      where: { id: createdAccount.id },
      include: { key: true },
    });

    await db.user.update({ where: { id: 'owner' }, data: { email: 'eject-user@example.test', emailVerified: true } });
    await db.$transaction(async (tx) => {
      await tx.managedAccount.update({ where: { id: account.id }, data: { ownerUserId: 'owner' } });
      await tx.ethereumKey.update({ where: { id: account.keyId }, data: { userId: 'owner' } });
    });

    await db.session.create({
      data: {
        id: 'fresh-session-eject', userId: 'owner', token: 'fresh-token-eject',
        expiresAt: new Date(Date.now() + 60_000), lastPasskeyAt: new Date(),
      },
    });

    const ejectedAccount = await db.managedAccount.findUniqueOrThrow({
      where: { id: account.id },
      include: { key: true },
    });

    const input = {
      ownerUserId: 'owner', sessionId: 'fresh-session-eject', managedAccountId: ejectedAccount.id,
      expectedEpoch: 1, idempotencyKey: 'eject-once-v2',
    };
    const first = await ejectManagedAccount(db, input);
    const replay = await ejectManagedAccount(db, input);
    expect(replay).toEqual(first);
    expect(first.address).toBe(ejectedAccount.key.address);
    expect(first.custody).toBe('USER_OWNED');

    await expect(signTenantManagedAccount(db, {
      credential: orgACredential,
      managedAccountId: ejectedAccount.id,
      expectedCustodyEpoch: 1,
      idempotencyKey: 'sign-after-eject',
      payload: { message: 'after eject', format: 'utf8' },
    })).rejects.toMatchObject({ code: 'TENANT_ACCESS_ENDED' });

    const personalSignature = await signWithUserOwnedManagedAccount(db, {
      sessionId: 'fresh-session-eject', managedAccountId: ejectedAccount.id, keyId: ejectedAccount.keyId,
      expectedEpoch: 2, approvalId: 'personal-approval-v2', message: 'same-key-after-eject',
    });
    expect(personalSignature.address).toBe(ejectedAccount.key.address);
    expect(await verifyMessage({
      address: ejectedAccount.key.address as `0x${string}`,
      message: 'same-key-after-eject',
      signature: personalSignature.signature as `0x${string}`,
    })).toBe(true);
  }, 30_000);

  test('Free plan enforces account limits and lifecycle webhooks are signed', async () => {
    await db.planEntitlements.update({ where: { organizationId: 'org-b' }, data: { maxManagedAccounts: 2 } });
    const endpoint = await createWebhookEndpoint(db, {
      organizationId: 'org-b', url: 'https://hooks.example/openkey', eventTypes: ['managed_account.created'],
    });
    await createTenantManagedAccount(db, {
      credential: orgBCredential,
      idempotencyKey: 'plan-limit-first',
      email: 'plan-limit-1@example.test',
    });
    await expect(createTenantManagedAccount(db, {
      credential: orgBCredential,
      idempotencyKey: 'plan-limit-second',
      email: 'plan-limit-2@example.test',
    })).rejects.toMatchObject({ code: 'OPERATION_NOT_ALLOWED' });

    const delivery = await db.webhookDelivery.findFirst({ where: { endpointId: endpoint.endpoint.id } });
    if (delivery) {
      let captured: { body: string; signature: string } | undefined;
      await deliverWebhook(db, delivery.id, {
        now: new Date('2026-07-20T12:00:00.000Z'),
        resolve: async () => [{ address: '93.184.216.34' }],
        fetch: async (_url, init) => {
          captured = {
            body: String(init?.body),
            signature: new Headers(init?.headers).get('OpenKey-Signature')!,
          };
          return new Response('accepted', { status: 200 });
        },
      });
      if (captured) {
        const timestamp = Math.floor(new Date('2026-07-20T12:00:00.000Z').getTime() / 1_000);
        const expected = createHmac('sha256', endpoint.secret).update(`${timestamp}.${captured.body}`).digest('hex');
        expect(captured.signature).toBe(`t=${timestamp},v1=${expected}`);
      }
    }
  }, 30_000);

  test('serializes the webhook endpoint cap under concurrent creation', async () => {
    await db.webhookEndpoint.deleteMany({ where: { organizationId: 'org-a' } });
    const results = await Promise.allSettled(Array.from({ length: 4 }, (_, index) => createWebhookEndpoint(db, {
      organizationId: 'org-a',
      url: `https://hooks-${index}.example/openkey`,
      eventTypes: ['managed_account.created'],
    })));
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(3);
    const rejected = results.filter((result) => result.status === 'rejected') as PromiseRejectedResult[];
    expect(rejected).toHaveLength(1);
    expect(rejected[0]!.reason).toBeInstanceOf(WebhookEndpointLimitError);
    expect(await db.webhookEndpoint.count({ where: { organizationId: 'org-a', active: true } })).toBe(3);
  }, 30_000);

  test('BROKER credential is rejected for management operations', async () => {
    const issued = await issueOrganizationCredential(db, {
      organizationId: 'org-a', subjectUserId: 'owner', name: 'Legacy Broker',
    });
    const actor = await authenticateOrganizationCredential(db, issued.secret);
    const managementCred = { credentialId: actor.credentialId, organizationId: 'org-a', subjectUserId: actor.subjectUserId, kind: 'MANAGEMENT' as const };

    await db.organizationServerCredential.update({
      where: { id: actor.credentialId },
      data: { kind: 'BROKER' as any },
    });

    await expect(createTenantManagedAccount(db, {
      credential: managementCred,
      idempotencyKey: 'broker-reject',
      email: 'broker-reject@example.test',
    })).rejects.toMatchObject({ code: 'OPERATION_NOT_ALLOWED' });
  }, 30_000);

  test('revoked credential is rejected', async () => {
    const issued = await issueOrganizationCredential(db, {
      organizationId: 'org-a', subjectUserId: 'owner', name: 'To Revoke',
    });
    const actor = await authenticateOrganizationCredential(db, issued.secret);
    const cred = { credentialId: actor.credentialId, organizationId: 'org-a', subjectUserId: actor.subjectUserId, kind: 'MANAGEMENT' as const };

    await db.organizationServerCredential.update({
      where: { id: actor.credentialId },
      data: { revokedAt: new Date() },
    });

    await expect(createTenantManagedAccount(db, {
      credential: cred,
      idempotencyKey: 'revoked-cred-test',
      email: 'revoked-cred@example.test',
    })).rejects.toMatchObject({ code: 'OPERATION_NOT_ALLOWED' });
  }, 30_000);

  test('ensureTenantManagedAccountForVerifiedEmail: DISABLED returns ACCOUNT_DISABLED, USER_OWNED returns TENANT_ACCESS_ENDED', async () => {
    const { ensureTenantManagedAccountForVerifiedEmail } = await import('../services/tenant-managed-accounts');

    // Create and disable an account
    const disabledAccount = await createTenantManagedAccount(db, {
      credential: orgACredential,
      idempotencyKey: 'oauth-disabled-create',
      email: 'oauth-disabled@example.test',
    });
    await disableTenantManagedAccount(db, {
      credential: orgACredential,
      managedAccountId: disabledAccount.id,
      expectedCustodyEpoch: 1,
      idempotencyKey: 'oauth-disabled-disable',
    });

    // OAuth flow must reject DISABLED accounts with structured ACCOUNT_DISABLED code
    await expect(
      ensureTenantManagedAccountForVerifiedEmail(db, {
        organizationId: 'org-a',
        email: 'oauth-disabled@example.test',
      }),
    ).rejects.toMatchObject({ code: 'ACCOUNT_DISABLED' });

    // Create an account owned by a user (ejected): bind then eject with a fresh session
    await db.user.update({ where: { id: 'owner' }, data: { email: 'oauth-ejected@example.test', emailVerified: true } });
    const ejectedBase = await createTenantManagedAccount(db, {
      credential: orgACredential,
      idempotencyKey: 'oauth-ejected-create',
      email: 'oauth-ejected@example.test',
    });
    await bindAccountsForVerifiedEmail(db, { email: 'oauth-ejected@example.test', userId: 'owner' });
    await db.session.upsert({
      where: { id: 'session-oauth-eject' },
      create: {
        id: 'session-oauth-eject', userId: 'owner', token: 'token-oauth-eject',
        expiresAt: new Date(Date.now() + 60_000), lastPasskeyAt: new Date(),
      },
      update: { lastPasskeyAt: new Date(), expiresAt: new Date(Date.now() + 60_000) },
    });
    await ejectManagedAccount(db, {
      ownerUserId: 'owner',
      sessionId: 'session-oauth-eject',
      managedAccountId: ejectedBase.id,
      expectedEpoch: 1,
      idempotencyKey: 'oauth-ejected-eject',
    });

    // Restore the owner email for other tests
    await db.user.update({ where: { id: 'owner' }, data: { email: 'owner@example.test' } });

    // OAuth flow must reject USER_OWNED accounts with structured TENANT_ACCESS_ENDED code
    await expect(
      ensureTenantManagedAccountForVerifiedEmail(db, {
        organizationId: 'org-a',
        email: 'oauth-ejected@example.test',
      }),
    ).rejects.toMatchObject({ code: 'TENANT_ACCESS_ENDED' });
  }, 30_000);

  test('eject revokes TENANT_MANAGED OAuth tokens for the user', async () => {
    const email = 'eject-revoke-tokens@example.test';
    const account = await createTenantManagedAccount(db, {
      credential: orgACredential,
      idempotencyKey: 'eject-revoke-tokens-create',
      email,
    });
    // Update user email to match so bindAccountsForVerifiedEmail can find them
    await db.user.update({ where: { id: 'owner' }, data: { email, emailVerified: true } });
    await bindAccountsForVerifiedEmail(db, { email, userId: 'owner' });

    // Create a fresh session with recent passkey activity
    await db.session.upsert({
      where: { id: 'session-eject-revoke' },
      create: {
        id: 'session-eject-revoke', userId: 'owner', token: 'token-eject-revoke-tokens',
        expiresAt: new Date(Date.now() + 60_000), lastPasskeyAt: new Date(),
      },
      update: { lastPasskeyAt: new Date(), expiresAt: new Date(Date.now() + 60_000), token: 'token-eject-revoke-tokens' },
    });

    // Seed OAuth tokens for org-a TENANT_MANAGED client (clientId: 'client-org-a')
    await db.oauthAccessToken.create({
      data: {
        id: 'at-eject-test', token: 'access-token-eject-test', clientId: 'client-org-a',
        userId: 'owner', scopes: ['openid'], expiresAt: new Date(Date.now() + 3600_000),
      },
    });
    await db.oauthRefreshToken.create({
      data: {
        id: 'rt-eject-test', token: 'refresh-token-eject-test', clientId: 'client-org-a',
        userId: 'owner', scopes: ['openid'], expiresAt: new Date(Date.now() + 86400_000),
      },
    });

    await ejectManagedAccount(db, {
      ownerUserId: 'owner',
      sessionId: 'session-eject-revoke',
      managedAccountId: account.id,
      expectedEpoch: 1,
      idempotencyKey: 'eject-revoke-tokens-eject',
    });

    // Restore owner email for remaining tests
    await db.user.update({ where: { id: 'owner' }, data: { email: 'owner@example.test' } });

    // Allow async token revocation to complete
    await new Promise((resolve) => setTimeout(resolve, 200));

    const accessToken = await db.oauthAccessToken.findUnique({ where: { id: 'at-eject-test' } });
    const refreshToken = await db.oauthRefreshToken.findUnique({ where: { id: 'rt-eject-test' } });
    expect(accessToken?.expiresAt.getTime()).toBeLessThanOrEqual(Date.now());
    expect(refreshToken?.revoked).toBeInstanceOf(Date);
  }, 30_000);

  test('provision writes canonical possessionEventHash signed by the managed account key', async () => {
    const account = await createTenantManagedAccount(db, {
      credential: orgACredential,
      idempotencyKey: 'hash-sig-verify',
      email: 'hash-sig@example.test',
    });
    const managedAccount = await db.managedAccount.findUniqueOrThrow({
      where: { id: account.id },
      include: { key: true },
    });
    const event = await db.possessionEvent.findFirstOrThrow({
      where: { managedAccountId: account.id },
    });
    const expectedHash = possessionEventHash({
      managedAccountId: account.id,
      keyId: managedAccount.keyId,
      epoch: 1,
      previousEventHash: null,
      fromPrincipal: 'none',
      toPrincipal: `organization:${orgACredential.organizationId}`,
      reason: 'INITIAL_ACTIVATION',
      credentialPolicyHash: organizationInitialActivationPolicyHash(orgACredential.organizationId, 1),
      createdAt: event.createdAt,
    });
    expect(event.eventHash).toBe(expectedHash);
    expect(await verifyMessage({
      address: managedAccount.key.address as `0x${string}`,
      message: expectedHash,
      signature: event.accountKeySignature as `0x${string}`,
    })).toBe(true);
  }, 30_000);

  test('disable and restore use row locks (sequential requests do not interleave)', async () => {
    const account = await createTenantManagedAccount(db, {
      credential: orgACredential,
      idempotencyKey: 'row-lock-create',
      email: 'row-lock@example.test',
    });
    // Run disable and restore concurrently – with row locks both must serialize
    const [disableResult] = await Promise.all([
      disableTenantManagedAccount(db, {
        credential: orgACredential,
        managedAccountId: account.id,
        expectedCustodyEpoch: 1,
        idempotencyKey: 'row-lock-disable',
      }),
      // A concurrent disable with the same key must replay cleanly
      disableTenantManagedAccount(db, {
        credential: orgACredential,
        managedAccountId: account.id,
        expectedCustodyEpoch: 1,
        idempotencyKey: 'row-lock-disable',
      }),
    ]);
    expect(disableResult.state).toBe('DISABLED');
    // Restore brings it back to MANAGED
    const restored = await restoreTenantManagedAccount(db, {
      credential: orgACredential,
      managedAccountId: account.id,
      expectedCustodyEpoch: 1,
      idempotencyKey: 'row-lock-restore',
    });
    expect(restored.state).toBe('MANAGED');
  }, 30_000);
});
