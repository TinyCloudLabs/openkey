// POST /api/delegate/authorize-sign-prepare, -preview and -sign for two sign-ins observed from apps that are not
// first-party: the account app (a space `list`) and a TinyChat preview (one space `info`). Neither names a host
// ability: both are signed, with a complete bootstrap row and without one. The request's top-level `host` field
// (the node the session activates against) is bound into the authorization context and never reaches the host rule:
// a node URL, another node URL, an empty string and a value that is not a string all give the same answer.

import { afterAll, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { mockModules, replaceModules } from './mock-module';
import { accountAppMessage, tinyChatPreviewMessage } from './space-recap-shapes';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const user = { id: 'user_hosts', email: 'hosts@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const ACCOUNT_APP = 'https://account.tinycloud.xyz';
const TINYCHAT_PREVIEW = 'https://0a31bc70.tinychat.pages.dev';
const keyRecord = {
  id: 'key_hosts', userId: user.id, address: account.address, keyType: 'MANAGED' as const,
  archivedAt: null, sealedBlob: 'sealed-blob', sealingContext: null,
};

let row: { status: string } | null = null;
let signed: string[] = [];
const prisma = {
  ethereumKey: {
    findFirst: mock(async () => keyRecord),
    findMany: mock(async () => [keyRecord]),
    findUnique: mock(async () => keyRecord),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: { findUnique: mock(async () => row) },
};

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', user);
      c.set('session', { id: 'session_hosts', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({ deriveKey: mock(async () => new Uint8Array(32)), getQuote: mock(async () => 'quote'), isInTee: () => false }),
    unseal: mock(async () => privateKey),
    createWalletFromPrivateKey: (key: string) => {
      const wallet = privateKeyToAccount(key as `0x${string}`);
      return { address: wallet.address, signMessage: async (input: { message: string }) => { signed.push(input.message); return wallet.signMessage(input); } };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => account.address,
  }),
});

let router: typeof import('../routes/delegate')['delegateRouter'];
const savedOnSign = process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN;
beforeAll(async () => {
  process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN = 'off';
  ({ delegateRouter: router } = await import('../routes/delegate?authorize-sign-app-shapes' as string));
});
afterAll(() => {
  if (savedOnSign === undefined) delete process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN;
  else process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN = savedOnSign;
});
beforeEach(() => {
  row = null;
  signed = [];
});

type Reply = { status: number; body: { signature?: string; signedMessage?: string; code?: string; authorizationContextToken?: string; allowedActionIds?: string[]; previewApprovalToken?: string } };
async function post(path: string, body: Record<string, unknown>): Promise<Reply> {
  const response = await router.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: response.status, body: (await response.json()) as Reply['body'] };
}

/** Prepare, preview and approve as the sign-in screen does; the reply of the step that stopped it, or of the sign. */
async function signIn(siwe: string, requestOrigin: string | undefined, host: unknown = 'https://node.tinycloud.xyz'): Promise<Reply> {
  const prepared = await post('/authorize-sign-prepare', {
    keyId: keyRecord.id, siwe, jwk, host, ...(requestOrigin ? { requestOrigin } : {}),
  });
  if (prepared.status !== 200) return prepared;
  const previewed = await post('/authorize-sign-preview', {
    authorizationContextToken: prepared.body.authorizationContextToken, selectedActionIds: prepared.body.allowedActionIds,
  });
  if (previewed.status !== 200) return previewed;
  return post('/authorize-sign', {
    authorizationContextToken: prepared.body.authorizationContextToken,
    previewApprovalToken: previewed.body.previewApprovalToken,
    selectedActionIds: prepared.body.allowedActionIds,
    protocolVersion: 1,
  });
}

const ROWS: Array<[string, { status: string } | null]> = [['a complete bootstrap row', { status: 'complete' }], ['no bootstrap row', null]];
const expectSigned = (reply: Reply, message: string) => {
  expect(reply.status).toBe(200);
  expect(reply.body.signedMessage).toBe(message);
  expect(reply.body.signature).toMatch(/^0x[0-9a-f]+$/i);
  expect(signed).toEqual([message]);
};

describe('the account app, a third-party origin', () => {
  for (const [label, rowValue] of ROWS) {
    test(`is prepared and signed with ${label}`, async () => {
      row = rowValue;
      const message = accountAppMessage(account.address);
      expectSigned(await signIn(message, ACCOUNT_APP), message);
    });
  }
});

describe('a TinyChat preview, a third-party origin', () => {
  for (const [label, rowValue] of ROWS) {
    test(`is prepared and signed with ${label}`, async () => {
      row = rowValue;
      const message = tinyChatPreviewMessage(account.address, '0a31bc70.tinychat.pages.dev');
      expectSigned(await signIn(message, TINYCHAT_PREVIEW), message);
    });
  }

  for (const [label, rowValue] of ROWS) {
    test(`is prepared and signed with ${label} whatever the top-level host field holds`, async () => {
      row = rowValue;
      for (const host of ['https://node.tinycloud.xyz', 'https://node.example.test', '', {}, null, 42]) {
        signed = [];
        const message = tinyChatPreviewMessage(account.address, '0a31bc70.tinychat.pages.dev');
        const reply = await signIn(message, TINYCHAT_PREVIEW, host);
        expect([JSON.stringify(host), reply.status]).toEqual([JSON.stringify(host), 200]);
        expectSigned(reply, message);
      }
    });
  }

  test('the host field does not make the prepare step refuse', async () => {
    row = null;
    const message = tinyChatPreviewMessage(account.address, '0a31bc70.tinychat.pages.dev');
    for (const host of ['https://node.tinycloud.xyz', '', undefined]) {
      const prepared = await post('/authorize-sign-prepare', {
        keyId: keyRecord.id, siwe: message, jwk, ...(host === undefined ? {} : { host }), requestOrigin: TINYCHAT_PREVIEW,
        reportedOrigin: TINYCHAT_PREVIEW, expiryChangeable: true,
      });
      expect([String(host), prepared.status]).toEqual([String(host), 200]);
      expect(prepared.body.code).toBeUndefined();
    }
  });
});
