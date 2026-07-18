import { describe, expect, test } from 'bun:test';
import { OpenKeyManagementClient } from '../packages/sdk/src/index';

describe('OpenKeyManagementClient', () => {
  test('exposes the server-owned webhook endpoint entitlement', async () => {
    const fetch = async () => new Response(JSON.stringify({
      entitlements: {
        plan: 'FREE', version: 1, maxApps: 1, maxOrganizationMembers: 3, maxManagedAccounts: 100,
        monthlyActiveManagedUsers: 100, storageBytesPerManagedAccount: '100000000', requestsPerMinute: 60,
        maxTenantDelegationTtlSeconds: 3600, maxTenantPolicyVersion: 1, webhookDelivery: true,
        maxWebhookEndpoints: 3, auditRetentionDays: 7,
      },
      usage: { managedAccounts: 1 },
    }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    const client = new OpenKeyManagementClient({ serverCredential: 'oksk_test', fetch: fetch as typeof globalThis.fetch });
    const result = await client.getEntitlements();
    expect(result.entitlements.maxWebhookEndpoints).toBe(3);
  });
});
