// POST /api/keys/:id/sign for two sign-ins observed from apps that are not first-party: the account app (a space
// `list`) and a TinyChat preview (one space `info`). Neither names a host ability: both are signed, with a complete
// bootstrap row and without one.

import { afterAll, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { mockModules, replaceModules } from './mock-module';
import { accountAppMessage, tinyChatPreviewMessage } from './space-recap-shapes';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const user = { id: 'user_1', email: 'alice@example.test' };
const keyRecord = {
  id: 'key_1', userId: user.id, address: account.address, keyType: 'MANAGED' as const,
  archivedAt: null, sealedBlob: 'sealed-blob', sealingContext: null,
};
const ACCOUNT_APP = 'https://account.tinycloud.xyz';
const TINYCHAT_PREVIEW = 'https://0a31bc70.tinychat.pages.dev';

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
  ({ keysRouter } = await import('../routes/keys?keys-sign-app-shapes' as string));
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

async function sign(message: string, requestOrigin: string) {
  const response = await keysRouter.request('/key_1/sign', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'http://localhost:5173' },
    body: JSON.stringify({ message, requestOrigin }),
  });
  return { status: response.status, body: (await response.json()) as { signature?: string; code?: string } };
}

const ROWS: Array<[string, { status: string } | null]> = [['a complete bootstrap row', { status: 'complete' }], ['no bootstrap row', null]];

describe('POST /api/keys/:id/sign for the account app, a third-party origin', () => {
  for (const [label, rowValue] of ROWS) {
    test(`is signed with ${label}`, async () => {
      row = rowValue;
      const message = accountAppMessage(account.address);
      const signed = await sign(message, ACCOUNT_APP);

      expect(signed.status).toBe(200);
      expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
      expect(signedMessages).toEqual([message]);
    });
  }
});

describe('POST /api/keys/:id/sign for a TinyChat preview, a third-party origin', () => {
  for (const [label, rowValue] of ROWS) {
    test(`is signed with ${label}`, async () => {
      row = rowValue;
      const message = tinyChatPreviewMessage(account.address, '0a31bc70.tinychat.pages.dev');
      const signed = await sign(message, TINYCHAT_PREVIEW);

      expect(signed.status).toBe(200);
      expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
      expect(signedMessages).toEqual([message]);
    });
  }
});
