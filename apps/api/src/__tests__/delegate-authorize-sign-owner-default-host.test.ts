// POST /api/delegate/authorize-sign-prepare from a site that is not TinyCloud's own, for a sign-in that hosts the
// owner's `default` space: signed when the owner's primary space has a complete bootstrap row, refused without one.

import { afterAll, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { generateHostSIWEMessage } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const user = { id: 'user_hosts', email: 'hosts@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const PEER = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const THIRD_PARTY = 'https://app.example.test';
const FIRST_PARTY = 'https://home.tinycloud.xyz';
const keyRecord = {
  id: 'key_hosts', userId: user.id, address: account.address, keyType: 'MANAGED' as const,
  archivedAt: null, sealedBlob: 'sealed-blob', sealingContext: null,
};
const spaceId = (name: string) => `tinycloud:pkh:eip155:1:${account.address}:${name}`;

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
  ({ delegateRouter: router } = await import('../routes/delegate?authorize-sign-owner-default-host' as string));
});
afterAll(() => {
  if (savedOnSign === undefined) delete process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN;
  else process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN = savedOnSign;
});
beforeEach(() => {
  row = null;
  signed = [];
});

/** A host message for `name`, from the site at `origin`, with the expiry the sign-in screen needs. */
function hostSiwe(name: string, origin = THIRD_PARTY) {
  return generateHostSIWEMessage({
    address: account.address, chainId: 1, domain: new URL(origin).host, issuedAt: new Date().toISOString(), spaceId: spaceId(name), peerId: PEER,
  }).replace(/^(Issued At: .*)$/m, `$1\nExpiration Time: ${new Date(Date.now() + 3_600_000).toISOString()}`);
}
type Reply = { status: number; body: { signature?: string; signedMessage?: string; code?: string; authorizationContextToken?: string; allowedActionIds?: string[]; previewApprovalToken?: string } };
async function post(path: string, body: Record<string, unknown>): Promise<Reply> {
  const response = await router.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: response.status, body: (await response.json()) as Reply['body'] };
}

/** Prepare, preview and approve as the sign-in screen does; the reply of the step that stopped it, or of the sign. */
async function signIn(siwe: string, requestOrigin: string | undefined): Promise<Reply> {
  const prepared = await post('/authorize-sign-prepare', {
    keyId: keyRecord.id, siwe, jwk, host: 'https://node.tinycloud.xyz', ...(requestOrigin ? { requestOrigin } : {}),
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

describe('a sign-in that hosts the owner\'s `default` space, from a site that is not TinyCloud\'s own', () => {
  test('is prepared and signed when the owner\'s primary space has a complete bootstrap row', async () => {
    row = { status: 'complete' };
    const message = hostSiwe('default');
    const reply = await signIn(message, THIRD_PARTY);

    expect(reply.status).toBe(200);
    expect(reply.body.signedMessage).toBe(message);
    expect(reply.body.signature).toMatch(/^0x[0-9a-f]+$/i);
    expect(signed).toEqual([message]);
  });

  test('is refused at prepare without a bootstrap row, and nothing is signed', async () => {
    for (const unknown of [null, { status: 'pending' }, { status: 'in_progress' }, { status: 'failed' }]) {
      row = unknown;
      const prepared = await post('/authorize-sign-prepare', { keyId: keyRecord.id, siwe: hostSiwe('default'), jwk, host: 'https://node.tinycloud.xyz', requestOrigin: THIRD_PARTY });

      expect(prepared.status).toBe(403);
      expect(prepared.body.code).toBe('host_signing_first_party_only');
      expect(prepared.body.signature).toBeUndefined();
      expect(signed).toEqual([]);
    }
  });
});
