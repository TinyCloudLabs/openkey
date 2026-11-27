// `/api/keys/:keyId/sign`: a KV resource written `<space>/kv` (no path, the whole space) is signed for 30 days, like
// `<space>/kv/` and another folder. A read of the secrets vault is refused past 7 days however its resource is written.

import './tc1777-test-env';
import { beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const address = privateKeyToAccount(privateKey).address;
const user = { id: 'user_1', email: 'test@example.com' };
const SPACE = `tinycloud:pkh:eip155:1:${address}:applications`;
const SITE = 'https://thirdparty.example';
const DAY_MS = 86_400_000;
const KV = 'tinycloud.kv/';

let calls: string[] = [];
const unseal = mock(async () => privateKey);
const keyRecord = { id: 'key_1', userId: user.id, address, keyType: 'MANAGED', sealedBlob: 'sealed-private-key', archivedAt: null };
const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: Record<string, unknown> }) =>
      where.userId === user.id && where.id === keyRecord.id && where.archivedAt === null ? keyRecord : null),
  },
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
      return {
        ...wallet,
        signMessage: async (args: { message: string }) => {
          calls.push('sign');
          return wallet.signMessage(args);
        },
      };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => address,
  }),
  '../services/tinycloud-bootstrap': () => ({ ensureTinyCloudBootstrapForApprovedSign: mock(async () => ({ status: 'complete' as const })) }),
});

beforeEach(() => {
  calls = [];
  unseal.mockClear();
});

function siweFor(rawAbilities: Record<string, string[]>, lifetimeMs: number): string {
  const now = new Date();
  return prepareSession({
    address,
    chainId: 1,
    domain: new URL(SITE).host,
    issuedAt: now.toISOString(),
    expirationTime: new Date(now.getTime() + lifetimeMs).toISOString(),
    spaceId: SPACE,
    jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
    abilities: { kv: { [SPACE]: ['tinycloud.kv/get'] } } as never,
    rawAbilities,
  }).siwe;
}

async function sign(message: string, format = 'personal_sign') {
  // Loaded after the module mocks above, under its own specifier so no other test file's copy is reused.
  const { keysRouter } = await import('../routes/keys?keys-sign-kv-space-root-lifetime' as string);
  return keysRouter.request('/key_1/sign', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'http://localhost:5173' },
    body: JSON.stringify({ message, format, requestOrigin: SITE, elevatedAcknowledged: true }),
  });
}
const hex = (text: string) => `0x${Buffer.from(text, 'utf8').toString('hex')}`;

const REFUSED = {
  error: 'This request asks for secret access longer than 7 days. Secret access lasts at most 7 days, so ask again with an expiry of 7 days or less.',
  code: 'secret_lifetime_exceeded',
};

const WHOLE_SPACE_SHAPES: Array<[string, Record<string, string[]>]> = [
  ['get, list, put, del and metadata on <space>/kv', { [`${SPACE}/kv`]: ['get', 'list', 'put', 'del', 'metadata'].map((verb) => `${KV}${verb}`) }],
  ['sync on <space>/kv', { [`${SPACE}/kv`]: [`${KV}sync`] }],
  ['get and list on <space>/kv/', { [`${SPACE}/kv/`]: [`${KV}get`, `${KV}list`] }],
  ['get on <space>/kv/notes/', { [`${SPACE}/kv/notes/`]: [`${KV}get`] }],
];

describe('raw signing of a KV grant on the whole space or another folder', () => {
  test.each(WHOLE_SPACE_SHAPES)('%s for 30 days is signed, as text and as hex', async (_name, raw) => {
    const siwe = siweFor(raw, 30 * DAY_MS);
    for (const [message, format] of [[siwe, 'personal_sign'], [hex(siwe), 'raw']] as const) {
      const res = await sign(message, format);
      expect(res.status, `${format}: ${await res.clone().text()}`).toBe(200);
    }
    expect(calls).toEqual(['sign', 'sign']);
  });
});

describe('raw signing of a KV read of the secrets vault', () => {
  test.each([
    ['get on <space>/kv/vault/secrets/', { [`${SPACE}/kv/vault/secrets/`]: [`${KV}get`] }],
    ['get on <space>/kv/vault/secrets', { [`${SPACE}/kv/vault/secrets`]: [`${KV}get`] }],
    ['get on <space>/kv/secrets/x', { [`${SPACE}/kv/secrets/x`]: [`${KV}get`] }],
    ['a whole-space read with a vault read beside it', { [`${SPACE}/kv`]: [`${KV}get`], [`${SPACE}/kv/vault/secrets/`]: [`${KV}get`] }],
  ] as Array<[string, Record<string, string[]>]>)('%s for 30 days is refused, and 7 days is signed', async (_name, raw) => {
    const refused = await sign(siweFor(raw, 30 * DAY_MS));
    expect(refused.status).toBe(400);
    expect(await refused.json()).toEqual(REFUSED);
    expect(unseal).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
    const signed = await sign(siweFor(raw, 7 * DAY_MS));
    expect(signed.status, await signed.clone().text()).toBe(200);
  });
});
