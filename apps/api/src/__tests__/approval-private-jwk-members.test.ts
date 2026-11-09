// An approval-bound delegation refuses a session JWK with any private member,
// before the delegate routes use, return, or save it.
import { describe, expect, mock, test } from 'bun:test';
import { ApprovalResultService } from '../services/approval-results';

const x = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const permissions = [{ service: 'tinycloud.kv', space: 'default', path: 'notes', actions: ['tinycloud.kv/get'] }];
const now = new Date('2026-10-31T12:00:00.000Z');
const record = {
  id: 'req', expiresAt: new Date(now.getTime() + 600_000), resultRef: null,
  request: { nodeOrigin: 'https://node.example.test', targetPublicJwk: { kty: 'OKP', crv: 'Ed25519', x }, permissions, grantLifetimeSeconds: 3600 },
};
const approve = mock(async () => {});
const service = new ApprovalResultService({ findById: async () => record, approve } as never, {
  retentionSeconds: 600, apiOrigin: 'https://api.example.test', now: () => now,
} as never);
const publicJwk = { kty: 'OKP', crv: 'Ed25519', x };

describe('approval-bound session JWK', () => {
  test('a public key is accepted', async () => {
    await expect(service.assertDelegationWindow('req', { jwk: publicJwk, host: record.request.nodeOrigin, permissions })).resolves.toBe(record as never);
  });

  test.each(['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'])('one with `%s` is refused with the binding error and never saved', async (member) => {
    const secret = `private-${member}-value`;
    const body = { jwk: { ...publicJwk, [member]: secret }, host: record.request.nodeOrigin, permissions };
    const refusal = { code: 'request_binding', status: 400, message: 'Delegation binding does not match the immutable approval request' };
    await expect(service.assertDelegationWindow('req', body)).rejects.toMatchObject(refusal);
    await expect(service.approve('req', 'user_1', body, { siwe: 'signed', signature: '0x', jwk: body.jwk })).rejects.toMatchObject(refusal);
    expect(approve).not.toHaveBeenCalled();
  });
});
