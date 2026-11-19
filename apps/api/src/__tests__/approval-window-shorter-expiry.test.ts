// TC-2272: the owner may approve a signed approval request for LESS than the lifetime the requester
// signed, never for more.
import { describe, expect, test } from 'bun:test';
import { ApprovalResultService } from '../services/approval-results';

const x = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const permissions = [{ service: 'tinycloud.kv', space: 'default', path: 'notes', actions: ['tinycloud.kv/get'] }];
const now = new Date('2026-10-31T12:00:00.000Z');
const record = {
  id: 'req', expiresAt: new Date(now.getTime() + 600_000), resultRef: null,
  request: { nodeOrigin: 'https://node.example.test', targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x }, permissions, grantLifetimeSeconds: 3600 },
};
const service = new ApprovalResultService({ findById: async () => record } as never, {
  retentionSeconds: 600, apiOrigin: 'https://api.example.test', now: () => now,
} as never);
const base = { jwk: { kty: 'OKP', crv: 'Ed25519', x }, host: record.request.nodeOrigin, permissions };

describe('approval request lifetime', () => {
  test.each([['the signed lifetime', 3600], ['a shorter one', 600], ['the one-minute minimum', 60]])('accepts %s on prepare', async (_name, seconds) => {
    await expect(service.assertDelegationWindow('req', { ...base, expiryMs: seconds * 1000 })).resolves.toBe(record as never);
  });

  test('refuses a longer one on prepare', async () => {
    await expect(service.assertDelegationWindow('req', { ...base, expiryMs: 3601 * 1000 })).rejects.toMatchObject({ code: 'request_binding' });
  });
});
