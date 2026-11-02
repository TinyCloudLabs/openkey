import { afterEach, expect, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { MemoryPreparedHandoffStore, PreparedHandoffService } from '../services/prepared-handoff';
import { createOwnerRevocationRouter } from '../routes/owner-revocation';

const account = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
const previous = { cors: process.env.CORS_ORIGIN, webauthn: process.env.WEBAUTHN_ORIGIN };
afterEach(() => {
  if (previous.cors === undefined) delete process.env.CORS_ORIGIN;
  else process.env.CORS_ORIGIN = previous.cors;
  if (previous.webauthn === undefined) delete process.env.WEBAUTHN_ORIGIN;
  else process.env.WEBAUTHN_ORIGIN = previous.webauthn;
});

test('revocation signing is limited to the web signing origin, not the console origin', async () => {
  process.env.CORS_ORIGIN = 'https://openkey.so,https://console.openkey.so';
  process.env.WEBAUTHN_ORIGIN = 'https://openkey.so';
  const service = new PreparedHandoffService(new MemoryPreparedHandoffStore());
  const ticket = Buffer.alloc(32, 1).toString('base64url');
  await service.claim({
    transportVersion: 2,
    request: { kind: 'owner-revocation', ownerDid: `did:pkh:eip155:1:${account.address}`,
      cid: 'bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe',
      nonce: '0123456789abcdef0123456789abcdef', expiresAt: new Date(Date.now() + 590_000).toISOString() },
    delivery: { handoffId: ticket, state: Buffer.alloc(32, 2).toString('base64url'), cancelSecret: Buffer.alloc(32, 3).toString('base64url') },
  }, 'owner');
  const router = createOwnerRevocationRouter(service, {
    findKey: async () => ({ id: 'owner-key', userId: 'owner', address: account.address, keyType: 'MANAGED', sealedBlob: 'sealed' }),
    signManaged: async (_key, _blob, message) => account.signMessage({ message }),
  }, createMiddleware(async (c, next) => { c.set('user', { id: 'owner', email: 'owner@example.test' }); await next(); }));
  const prepare = (origin: string) => router.request('/prepare', {
    method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' }, body: JSON.stringify({ ticket, keyId: 'owner-key' }),
  });
  const consoleResponse = await prepare('https://console.openkey.so');
  expect(consoleResponse.status).toBe(403);
  const webResponse = await prepare('https://openkey.so');
  expect(webResponse.status).toBe(200);
  const { authorizationContextToken, siwe } = await webResponse.json() as { authorizationContextToken: string; siwe: string };
  expect(siwe.startsWith('openkey.so wants you to sign in with your Ethereum account:')).toBe(true);
  const consoleSign = await router.request('/sign', {
    method: 'POST', headers: { Origin: 'https://console.openkey.so', 'Content-Type': 'application/json' },
    body: JSON.stringify({ ticket, keyId: 'owner-key', authorizationContextToken }),
  });
  expect(consoleSign.status).toBe(410);
  const webSign = await router.request('/sign', {
    method: 'POST', headers: { Origin: 'https://openkey.so', 'Content-Type': 'application/json' },
    body: JSON.stringify({ ticket, keyId: 'owner-key', authorizationContextToken }),
  });
  expect(webSign.status).toBe(200);
  expect((await webSign.json() as { siwe: string }).siwe).toBe(siwe);
});
