import { describe, expect, test } from 'bun:test';
import { MemoryPreparedHandoffStore, PreparedHandoffService } from '../services/prepared-handoff';

const now = Date.parse('2026-10-26T12:00:00.000Z');
const ownerDid = 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111';
const cid = 'bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe';
const opaque = (seed: number) => Buffer.alloc(32, seed).toString('base64url');
const claim = {
  transportVersion: 2,
  request: { kind: 'owner-revocation', ownerDid, cid, nonce: '0123456789abcdef0123456789abcdef', expiresAt: '2026-10-26T12:10:00.000Z' },
  delivery: { handoffId: opaque(1), state: opaque(2), cancelSecret: opaque(3) },
};

describe('prepared owner revocation', () => {
  test('claims, binds one owner key, and completes once with the original delivery state', async () => {
    const service = new PreparedHandoffService(new MemoryPreparedHandoffStore(), { now: () => now });
    expect((await service.claim(claim, 'owner')).ticket).toBe(claim.delivery.handoffId);
    await service.bindOwnerRevocation(claim.delivery.handoffId, 'owner', 'key-owner', '2026-10-26T12:00:00.000Z.secret');
    await service.reserveSigning(claim.delivery.handoffId, 'owner', '2026-10-26T12:00:00.000Z.secret', 'key-owner');
    expect(await service.completeSigning(claim.delivery.handoffId, 'owner', '2026-10-26T12:00:00.000Z.secret', 'key-owner')).toEqual({ deliveryState: claim.delivery.state, selectedKeyId: 'key-owner' });
    await expect(service.reserveSigning(claim.delivery.handoffId, 'owner', '2026-10-26T12:00:00.000Z.secret', 'key-owner')).rejects.toThrow('already signed');
  });
  test.each([
    [{ ...claim.request, kind: 'unknown' }, 'kind'],
    [{ ...claim.request, extra: 'text' }, 'field'],
    [{ ...claim.request, expiresAt: '2026-10-26T11:59:59.000Z' }, 'expired'],
  ])('refuses invalid owner claim', async (request, reason) => {
    const service = new PreparedHandoffService(new MemoryPreparedHandoffStore(), { now: () => now });
    await expect(service.claim({ ...claim, request }, 'owner')).rejects.toThrow(reason);
  });
  test('caps a later request expiry before storing the signed request', async () => {
    const service = new PreparedHandoffService(new MemoryPreparedHandoffStore(), { now: () => now });
    await service.claim({ ...claim, request: { ...claim.request, expiresAt: '2026-10-26T13:00:00.000Z' } }, 'owner');
    expect((await service.ownerRevocation(claim.delivery.handoffId, 'owner')).expiresAt).toBe('2026-10-26T12:10:00.000Z');
  });
});
