// POST /api/keys/:id/sign refuses a site that is not TinyCloud's own a message that hosts the owner's `default` space
// (`host_signing_first_party_only`) while the owner's account is not set up on TinyCloud hosting. The refusal says so
// (`accountSetup: 'required'`) for a managed key, so the sign widget offers OpenKey's own account setup page. A set-up
// owner is signed for; a refusal for any other reason carries no `accountSetup`.

import { afterAll, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { generateHostSIWEMessage } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const other = privateKeyToAccount('0x1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
const user = { id: 'user_setup_keys_sign', email: 'setup@example.test' };
const keyRecord = {
  id: 'key_setup_keys_sign', userId: user.id, address: account.address, keyType: 'MANAGED' as const,
  archivedAt: null, sealedBlob: 'sealed-blob', sealingContext: null,
};
const THIRD_PARTY = 'https://app.example.test';
const PEER = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

let row: { status: string } | null = null;
let lookupFails = false;
let signedMessages: string[] = [];
const unseal = mock(async () => privateKey);
const prisma = {
  ethereumKey: { findFirst: mock(async () => keyRecord) },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {
    findUnique: mock(async () => {
      if (lookupFails) throw new Error('database unavailable');
      return row;
    }),
  },
};

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', user);
      c.set('session', { id: 'session_setup_keys_sign', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
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
  ({ keysRouter } = await import('../routes/keys?keys-sign-account-setup-refusal' as string));
});
afterAll(() => {
  for (const [name, value] of Object.entries({ TINYCLOUD_BOOTSTRAP_ON_SIGN: savedEnv.on, TINYCLOUD_BOOTSTRAP_HOST: savedEnv.host })) {
    if (value === undefined) delete process.env[name]; else process.env[name] = value;
  }
});
beforeEach(() => {
  row = null;
  lookupFails = false;
  signedMessages = [];
  keyRecord.keyType = 'MANAGED';
  unseal.mockClear();
});

const hostSiwe = (owner: string) => generateHostSIWEMessage({
  address: account.address, chainId: 1, domain: 'app.example.test', issuedAt: new Date().toISOString(),
  spaceId: `tinycloud:pkh:eip155:1:${owner}:default`, peerId: PEER,
});

async function sign(message: string) {
  const response = await keysRouter.request(`/${keyRecord.id}/sign`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'http://localhost:5173' },
    body: JSON.stringify({ message, requestOrigin: THIRD_PARTY }),
  });
  return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

describe('POST /api/keys/:id/sign for a message that hosts the owner\'s `default` space, from a site that is not TinyCloud\'s own', () => {
  test('says account setup is required while the managed key has no complete setup row', async () => {
    for (const state of [null, { status: 'pending' }, { status: 'in_progress' }, { status: 'failed' }]) {
      row = state;
      const signed = await sign(hostSiwe(account.address));

      expect(signed.status).toBe(403);
      expect(signed.body).toEqual({ error: expect.any(String), code: 'host_signing_first_party_only', accountSetup: 'required' });
    }
    expect(unseal).not.toHaveBeenCalled();
    expect(signedMessages).toEqual([]);
  });

  test('signs for an owner whose account is set up', async () => {
    row = { status: 'complete' };
    const message = hostSiwe(account.address);
    const signed = await sign(message);

    expect(signed.status).toBe(200);
    expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
    expect(signedMessages).toEqual([message]);
  });

  test('carries no `accountSetup` for a space of another owner of a set-up account', async () => {
    row = { status: 'complete' };
    const signed = await sign(hostSiwe(other.address));

    expect(signed.status).toBe(403);
    expect(signed.body).toEqual({ error: expect.any(String), code: 'host_signing_first_party_only' });
  });

  test('carries no `accountSetup` when the setup row cannot be read', async () => {
    lookupFails = true;
    const signed = await sign(hostSiwe(account.address));

    expect(signed.status).toBe(403);
    expect(signed.body).toEqual({ error: expect.any(String), code: 'host_signing_first_party_only' });
  });
});
