import { describe, expect, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { verifyMessage } from 'ethers';
import { MemoryPreparedHandoffStore, PreparedHandoffService } from '../services/prepared-handoff';
import { createOwnerRevocationRouter } from '../routes/owner-revocation';

const account = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
const cid = 'bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe';
const opaque = (byte: number) => Buffer.alloc(32, byte).toString('base64url');
const user = { id: 'owner', email: 'owner@example.test' };

async function fixture(address = account.address) {
  const service = new PreparedHandoffService(new MemoryPreparedHandoffStore());
  const claim = { transportVersion: 2, request: { kind: 'owner-revocation', ownerDid: `did:pkh:eip155:1:${account.address}`, cid, nonce: '0123456789abcdef0123456789abcdef', expiresAt: new Date(Date.now() + 590_000).toISOString() }, delivery: { handoffId: opaque(1), state: opaque(2), cancelSecret: opaque(3) } };
  await service.claim(claim, user.id);
  const router = createOwnerRevocationRouter(service, {
    findKey: async () => ({ id: 'owner-key', userId: user.id, address, keyType: 'MANAGED', sealedBlob: 'sealed', sealingContext: null }),
    signManaged: async (_key, _blob, message) => account.signMessage({ message }),
  }, createMiddleware(async (c, next) => { c.set('user', user); await next(); }));
  const post = async (path: string, body: unknown) => {
    const res = await router.request(path, { method: 'POST', headers: { Origin: 'http://localhost:5173', 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    return { status: res.status, body: await res.json() as Record<string, unknown> };
  };
  return { claim, post };
}

describe('owner revocation HTTP signing', () => {
  test('prepares server text, signs once with the owner, and returns state and exact SIWE', async () => {
    const { claim, post } = await fixture();
    const prepared = await post('/prepare', { ticket: claim.delivery.handoffId, keyId: 'owner-key' });
    expect(prepared.status).toBe(200);
    const siwe = prepared.body.siwe as string;
    expect(siwe).toContain(`URI: ucan:${cid}\nVersion: 1\nChain ID: 1\nNonce: ${claim.request.nonce}`);
    const result = await post('/sign', { ticket: claim.delivery.handoffId, keyId: 'owner-key', authorizationContextToken: prepared.body.authorizationContextToken });
    expect(result.status).toBe(200);
    expect(result.body).toEqual({ siwe, signature: result.body.signature, deliveryState: claim.delivery.state, selectedKeyId: 'owner-key' });
    expect(verifyMessage(siwe, result.body.signature as string)).toBe(account.address);
    expect((await post('/sign', { ticket: claim.delivery.handoffId, keyId: 'owner-key', authorizationContextToken: prepared.body.authorizationContextToken })).status).toBe(409);
  });
  test('refuses a signed-in key with a different owner address', async () => {
    const { claim, post } = await fixture('0x2222222222222222222222222222222222222222');
    const result = await post('/prepare', { ticket: claim.delivery.handoffId, keyId: 'owner-key' });
    expect(result.status).toBe(403);
    expect(result.body.error).toContain('owner');
  });
});
