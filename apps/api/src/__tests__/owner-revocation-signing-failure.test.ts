// TC-2382: an owner-revocation handoff whose managed signing fails is released, so the owner can sign again.
import { describe, expect, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { verifyMessage } from 'ethers';
import { MemoryPreparedHandoffStore, PreparedHandoffService } from '../services/prepared-handoff';
import { createOwnerRevocationRouter } from '../routes/owner-revocation';

const account = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
const other = privateKeyToAccount('0x1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
const cid = 'bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe';
const opaque = (byte: number) => Buffer.alloc(32, byte).toString('base64url');
const user = { id: 'owner', email: 'owner@example.test' };

async function fixture(signManaged: (message: string) => Promise<string>) {
  const service = new PreparedHandoffService(new MemoryPreparedHandoffStore());
  const claim = { transportVersion: 2, request: { kind: 'owner-revocation', ownerDid: `did:pkh:eip155:1:${account.address}`, cid, nonce: '0123456789abcdef0123456789abcdef', expiresAt: new Date(Date.now() + 590_000).toISOString() }, delivery: { handoffId: opaque(1), state: opaque(2), cancelSecret: opaque(3) } };
  await service.claim(claim, user.id);
  const router = createOwnerRevocationRouter(service, {
    findKey: async () => ({ id: 'owner-key', userId: user.id, address: account.address, keyType: 'MANAGED', sealedBlob: 'sealed', sealingContext: null }),
    signManaged: async (_key, _blob, message) => signManaged(message),
  }, createMiddleware(async (c, next) => { c.set('user', user); await next(); }));
  const post = (path: string, body: unknown) =>
    router.request(path, { method: 'POST', headers: { Origin: 'http://localhost:5173', 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const ticket = claim.delivery.handoffId;
  const prepared = await (await post('/prepare', { ticket, keyId: 'owner-key' })).json() as { authorizationContextToken: string; siwe: string };
  return { siwe: prepared.siwe, sign: () => post('/sign', { ticket, keyId: 'owner-key', authorizationContextToken: prepared.authorizationContextToken }) };
}

describe('owner revocation handoff when managed signing fails', () => {
  test('a signing that throws releases the handoff: the next attempt signs and delivers', async () => {
    let failures = 1;
    const { sign, siwe } = await fixture(async (message) => {
      if (failures-- > 0) throw new Error('TEE unavailable');
      return account.signMessage({ message });
    });
    const failed = await sign();
    expect(failed.status).toBe(500);
    expect(await failed.json()).toEqual({ error: 'TEE unavailable', code: 'sign_failed' });
    const retry = await sign();
    expect(retry.status).toBe(200);
    const result = await retry.json() as { signature: string };
    expect(verifyMessage(siwe, result.signature)).toBe(account.address);
  });

  test('a signature by the wrong account is refused and also releases the handoff', async () => {
    let wrong = true;
    const { sign } = await fixture(async (message) => (wrong ? other : account).signMessage({ message }));
    expect((await sign()).status).toBe(403);
    wrong = false;
    expect((await sign()).status).toBe(200);
  });
});
