import { expect, test } from 'bun:test';
import { buildOwnerRevocationSiwe } from '@openkey/capability-review';
import { MemoryPreparedHandoffStore, PreparedHandoffService } from '../services/prepared-handoff';

const now = Date.parse('2026-10-26T12:00:00.000Z');
const cid = 'bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe';
const opaque = (seed: number) => Buffer.alloc(32, seed).toString('base64url');

function admission(offsetMs: number) {
  const service = new PreparedHandoffService(new MemoryPreparedHandoffStore(), { now: () => now });
  const delivery = { handoffId: opaque(1), state: opaque(2), cancelSecret: opaque(3) };
  const request = { kind: 'owner-revocation', ownerDid: 'did:pkh:eip155:1:0x1111111111111111111111111111111111111111',
    cid, nonce: '0123456789abcdef0123456789abcdef', expiresAt: new Date(now + offsetMs).toISOString() };
  return { service, delivery, claim: service.claim({ transportVersion: 2, request, delivery }, 'owner') };
}

test('server accepts ten minutes and 59 seconds of request-clock skew but signs for at most ten minutes', async () => {
  for (const offsetMs of [600_000, 659_000]) {
    const { service, delivery, claim } = admission(offsetMs);
    expect((await claim).ticket).toBe(delivery.handoffId);
    const request = await service.ownerRevocation(delivery.handoffId, 'owner');
    const siwe = buildOwnerRevocationSiwe(request, 'openkey.so', new Date(now + 1_000));
    const issuedAt = Date.parse(siwe.match(/^Issued At: (.+)$/m)![1]!);
    const expiresAt = Date.parse(siwe.match(/^Expiration Time: (.+)$/m)![1]!);
    expect(expiresAt - issuedAt).toBeGreaterThan(0);
    expect(expiresAt - issuedAt).toBeLessThanOrEqual(600_000);
    expect(expiresAt).toBe(now + 600_000);
  }
});

test('server refuses expiry beyond ten minutes plus 60 seconds or at or before now', async () => {
  for (const offsetMs of [661_000, 0, -1_000]) {
    const { claim } = admission(offsetMs);
    await expect(claim).rejects.toThrow(offsetMs > 0 ? 'expiry' : 'expired');
  }
});
