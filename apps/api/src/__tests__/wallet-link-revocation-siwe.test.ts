import { beforeAll, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import type { keysRouter } from '../routes/keys';
import { mockModules, replaceModules } from './mock-module';

const account = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
const createKey = mock(async () => ({ id: 'linked' }));
replaceModules({
  '../middleware/session': () => ({ requireSession: createMiddleware(async (c, next) => {
    c.set('user', { id: 'owner' });
    await next();
  }) }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => ({ ethereumKey: {
    findUnique: async () => null, findFirst: async () => null, create: createKey,
  } }) }),
  '@openkey/tee': () => ({ createTeeClient: () => ({}) }),
  '../services/tinycloud-bootstrap': () => ({ ensureTinyCloudBootstrapForApprovedSign: async () => ({ status: 'skipped' }) }),
});
let router: typeof keysRouter;
beforeAll(async () => { ({ keysRouter: router } = await import('../routes/keys?wallet-link-revocation-siwe' as string)); });

test('a signed ucan: SIWE cannot satisfy an OpenKey wallet verification challenge', async () => {
  const challengeResponse = await router.request('/link/challenge', { method: 'POST' });
  expect(challengeResponse.status).toBe(200);
  const { nonce } = await challengeResponse.json() as { nonce: string };
  const message = `openkey.so wants you to sign in with your Ethereum account:\n${account.address}\n\n\nURI: ucan:bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe\nVersion: 1\nChain ID: 1\nNonce: ${nonce}\nIssued At: 2026-10-26T12:00:00.000Z\nExpiration Time: 2026-10-26T12:10:00.000Z`;
  const signature = await account.signMessage({ message });
  const response = await router.request('/link', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ address: account.address, message, signature }),
  });
  expect(response.status).toBe(400);
  expect(createKey).not.toHaveBeenCalled();
});
