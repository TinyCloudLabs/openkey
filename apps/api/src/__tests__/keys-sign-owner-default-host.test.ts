// POST /api/keys/:id/sign from a site that is not TinyCloud's own, for a message that hosts the owner's `default`
// space: signed when the owner's primary space has a complete bootstrap row, refused without one.

import { afterAll, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { generateHostSIWEMessage } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const user = { id: 'user_1', email: 'alice@example.test' };
const keyRecord = {
  id: 'key_1', userId: user.id, address: account.address, keyType: 'MANAGED' as const,
  archivedAt: null, sealedBlob: 'sealed-blob', sealingContext: null,
};
const spaceId = (name: string) => `tinycloud:pkh:eip155:1:${account.address}:${name}`;
const THIRD_PARTY = 'https://app.example.test';
const PEER = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

let row: { status: string } | null = null;
let signedMessages: string[] = [];
const unseal = mock(async () => privateKey);
const prisma = {
  ethereumKey: { findFirst: mock(async () => keyRecord) },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: { findUnique: mock(async () => row) },
};

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', user);
      c.set('session', { id: 'session_1', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({ deriveKey: mock(async () => new Uint8Array(32)), getQuote: mock(async () => 'quote'), isInTee: () => false }),
    seal: mock(async () => 'sealed-private-key'),
    unseal,
    createWalletFromPrivateKey: (key: string) => {
      const wallet = privateKeyToAccount(key as `0x${string}`);
      return { address: wallet.address, signMessage: async (args: { message: string }) => { signedMessages.push(args.message); return wallet.signMessage(args); } };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => account.address,
  }),
});

let keysRouter: typeof import('../routes/keys')['keysRouter'];
const savedEnv = { on: process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN, host: process.env.TINYCLOUD_BOOTSTRAP_HOST };
beforeAll(async () => {
  process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN = 'off';
  delete process.env.TINYCLOUD_BOOTSTRAP_HOST;
  ({ keysRouter } = await import('../routes/keys?keys-sign-owner-default-host' as string));
});
afterAll(() => {
  for (const [name, value] of Object.entries({ TINYCLOUD_BOOTSTRAP_ON_SIGN: savedEnv.on, TINYCLOUD_BOOTSTRAP_HOST: savedEnv.host })) {
    if (value === undefined) delete process.env[name]; else process.env[name] = value;
  }
});
beforeEach(() => {
  row = null;
  signedMessages = [];
  unseal.mockClear();
});

const hostSiwe = (name: string) => generateHostSIWEMessage({
  address: account.address, chainId: 1, domain: 'app.example.test', issuedAt: new Date().toISOString(), spaceId: spaceId(name), peerId: PEER,
});

async function sign(message: string) {
  const response = await keysRouter.request('/key_1/sign', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'http://localhost:5173' },
    body: JSON.stringify({ message, requestOrigin: THIRD_PARTY }),
  });
  return { status: response.status, body: (await response.json()) as { signature?: string; code?: string } };
}

describe('POST /api/keys/:id/sign for a message that hosts the owner\'s `default` space, from a site that is not TinyCloud\'s own', () => {
  test('signs when the owner\'s primary space has a complete bootstrap row', async () => {
    row = { status: 'complete' };
    const message = hostSiwe('default');
    const signed = await sign(message);

    expect(signed.status).toBe(200);
    expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
    expect(signedMessages).toEqual([message]);
  });

  test('is refused without a complete bootstrap row, and the key is not unsealed', async () => {
    for (const unknown of [null, { status: 'pending' }, { status: 'in_progress' }, { status: 'failed' }]) {
      row = unknown;
      const signed = await sign(hostSiwe('default'));

      expect(signed.status).toBe(403);
      expect(signed.body.code).toBe('host_signing_first_party_only');
      expect(signed.body.signature).toBeUndefined();
    }
    expect(unseal).not.toHaveBeenCalled();
    expect(signedMessages).toEqual([]);
  });
});
