import { expect, test } from 'bun:test';
import { privateKeyToAccount } from 'viem/accounts';
import { MemoryPreparedHandoffStore, PreparedHandoffService } from '../services/prepared-handoff';

const address = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef').address;

test('a revocation ticket cannot enter the ordinary context or signing reservation', async () => {
  const service = new PreparedHandoffService(new MemoryPreparedHandoffStore());
  const ticket = Buffer.alloc(32, 4).toString('base64url');
  await service.claim({
    transportVersion: 2,
    request: { kind: 'owner-revocation', ownerDid: `did:pkh:eip155:1:${address}`,
      cid: 'bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe',
      nonce: '0123456789abcdef0123456789abcdef', expiresAt: new Date(Date.now() + 590_000).toISOString() },
    delivery: { handoffId: ticket, state: Buffer.alloc(32, 5).toString('base64url'), cancelSecret: Buffer.alloc(32, 6).toString('base64url') },
  }, 'owner');
  await service.bindOwnerRevocation(ticket, 'owner', 'owner-key', 'owner-context');
  await expect(service.assertContext(ticket, 'owner', 'owner-context')).rejects.toMatchObject({ code: 'binding_mismatch' });
  await expect(service.reserveSigning(ticket, 'owner', 'owner-context', 'owner-key')).rejects.toMatchObject({ code: 'binding_mismatch' });
  expect((await service.assertContext(ticket, 'owner', 'owner-context', 'owner-revocation')).selectedKeyId).toBe('owner-key');
  await service.reserveSigning(ticket, 'owner', 'owner-context', 'owner-key', 'owner-revocation');
});

test('ordinary prepared sign-in does not accept a revocation URI as its SIWE', async () => {
  const service = new PreparedHandoffService(new MemoryPreparedHandoffStore());
  const message = [
    'openkey.so wants you to sign in with your Ethereum account:',
    address, '', '',
    'URI: ucan:bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe',
    'Version: 1', 'Chain ID: 1', 'Nonce: 0123456789abcdef0123456789abcdef',
    `Issued At: ${new Date().toISOString()}`, `Expiration Time: ${new Date(Date.now() + 600_000).toISOString()}`,
  ].join('\n');
  await expect(service.claim({
    transportVersion: 2,
    request: { protocolVersion: 1, siwe: message, jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }, host: 'https://node.tinycloud.xyz', sessionDid: 'did:key:session-cli' },
    delivery: { handoffId: Buffer.alloc(32, 7).toString('base64url'), state: Buffer.alloc(32, 8).toString('base64url'), cancelSecret: Buffer.alloc(32, 9).toString('base64url') },
  }, 'owner')).rejects.toMatchObject({ code: 'invalid_request' });
});
