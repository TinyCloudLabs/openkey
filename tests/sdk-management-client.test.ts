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

  test('calls the tenant management API and tinycloud signer endpoints', async () => {
    const calls: Array<{ path: string; init?: RequestInit }> = [];
    const fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = typeof input === 'string' ? input : input.toString();
      const url = new URL(path, 'https://api.example.test');
      const pathname = url.pathname;
      calls.push({ path, init });
      if (pathname === '/v1/accounts' && init?.method === 'POST') {
        return new Response(JSON.stringify({
          id: 'account-1',
          subjectEmail: 'alice@example.test',
          externalUserId: null,
          email: 'alice@example.test',
          address: '0x1111111111111111111111111111111111111111',
          state: 'MANAGED',
          custodyEpoch: 1,
          tenantAccess: 'NOT_REQUIRED',
          createdAt: '2026-07-20T00:00:00.000Z',
          updatedAt: '2026-07-20T00:00:00.000Z',
        }), { status: 201, headers: { 'Content-Type': 'application/json' } });
      }
      if (pathname === '/v1/accounts' && init?.method !== 'POST') {
        return new Response(JSON.stringify({
          accounts: [{
            id: 'account-1',
            subjectEmail: 'alice@example.test',
            externalUserId: null,
            email: 'alice@example.test',
            address: '0x1111111111111111111111111111111111111111',
            state: 'MANAGED',
            custodyEpoch: 7,
            tenantAccess: 'NOT_REQUIRED',
            createdAt: '2026-07-20T00:00:00.000Z',
            updatedAt: '2026-07-20T00:00:00.000Z',
          }],
          nextCursor: null,
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      if (pathname === '/v1/accounts/account-1') {
        return new Response(JSON.stringify({
          id: 'account-1',
          subjectEmail: 'alice@example.test',
          externalUserId: null,
          email: 'alice@example.test',
          address: '0x1111111111111111111111111111111111111111',
          state: 'MANAGED',
          custodyEpoch: 7,
          tenantAccess: 'NOT_REQUIRED',
          createdAt: '2026-07-20T00:00:00.000Z',
          updatedAt: '2026-07-20T00:00:00.000Z',
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      if (pathname === '/v1/accounts/account-1/sign') {
        const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
        if ('message' in body) {
          return new Response(JSON.stringify({ signature: '0xsigned-message', address: '0x1111111111111111111111111111111111111111' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
        if ('transaction' in body) {
          return new Response(JSON.stringify({ signature: '0xsigned-transaction', signedTransaction: '0xsigned-transaction', address: '0x1111111111111111111111111111111111111111' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
        return new Response(JSON.stringify({ signature: '0xsigned-other', address: '0x1111111111111111111111111111111111111111' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      if (pathname === '/v1/credentials/credential-1/rotate') {
        return new Response(JSON.stringify({
          credential: {
            id: 'credential-2',
            name: 'Management',
            kind: 'MANAGEMENT',
            secretPrefix: 'prefix-2',
            subjectUserId: 'admin',
            createdAt: '2026-07-20T00:00:00.000Z',
            lastUsedAt: null,
            revokedAt: null,
          },
          secret: 'oksk_prefix-2.secret',
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      if (pathname === '/v1/credentials/credential-1') {
        return new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      throw new Error(`Unexpected fetch path: ${path}`);
    };
    const client = new OpenKeyManagementClient({ serverCredential: 'oksk_test', fetch: fetch as typeof globalThis.fetch });
    await expect(client.createAccount({ email: 'Alice@example.test' }, 'idem-1')).resolves.toMatchObject({
      subjectEmail: 'alice@example.test',
    });
    await expect(client.listAccounts({ email: 'alice@example.test' })).resolves.toMatchObject({ accounts: expect.any(Array) });
    await expect(client.getAccount('account-1')).resolves.toMatchObject({ custodyEpoch: 7 });
    await expect(client.sign('account-1', { message: 'hello' }, 'idem-2', 7)).resolves.toMatchObject({
      signature: '0xsigned-message',
    });
    const signer = client.createTinyCloudSigner({ accountId: 'account-1', chainId: 1, idempotencyKeyFactory: () => 'sign-idem' });
    await expect(signer.getAddress()).resolves.toBe('0x1111111111111111111111111111111111111111');
    await expect(signer.signMessage('hello')).resolves.toBe('0xsigned-message');
    await expect(signer.signTransaction({ type: 'eip1559', chainId: 1 })).resolves.toBe('0xsigned-transaction');
    await expect(client.rotateCredential('credential-1', 'rotate-idem')).resolves.toMatchObject({
      credential: { kind: 'MANAGEMENT' },
    });
    await expect(client.revokeCredential('credential-1')).resolves.toEqual({ success: true });
    expect(calls.some((call) => call.path.endsWith('/v1/accounts/account-1/sign'))).toBe(true);
    expect(calls.some((call) => call.path.endsWith('/v1/credentials/credential-1/rotate'))).toBe(true);
  });
});
