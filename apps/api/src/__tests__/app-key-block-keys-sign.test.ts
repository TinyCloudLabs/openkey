// `key.block` and `key.unblock` on an encryption key or prefix outside `apps/`
// are refused on the generic signing route (`/api/keys/:keyId/sign`), as text
// and as `0x` hex. The route has a verified `requestOrigin` but no manifest and
// no app id, so it cannot tell whose key a block names and refuses whatever the
// origin.

import './tc1777-test-env';
import { beforeEach, describe, expect, mock, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const address = privateKeyToAccount(privateKey).address;
const user = { id: 'user_1', email: 'test@example.com' };
const OWNER = `did:pkh:eip155:1:${address}`;
const SPACE = `tinycloud:pkh:eip155:1:${address}:default`;
const ORIGIN = 'https://tinycloud.chat';
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;

let calls: string[] = [];
const unseal = mock(async () => privateKey);
const ensureTinyCloudBootstrapForApprovedSign = mock(async () => {
  calls.push('bootstrap');
  return { status: 'complete' as const };
});
const keyRecord = {
  id: 'key_1',
  userId: user.id,
  address,
  keyType: 'MANAGED',
  sealedBlob: 'sealed-private-key',
  archivedAt: null,
};
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
  '../services/tinycloud-bootstrap': () => ({ ensureTinyCloudBootstrapForApprovedSign }),
});

beforeEach(() => {
  calls = [];
  unseal.mockClear();
  ensureTinyCloudBootstrapForApprovedSign.mockClear();
});

function siweWith(rawAbilities: Record<string, string[]> = {}): string {
  const now = new Date();
  return prepareSession({
    address,
    chainId: 1,
    domain: 'tinycloud.chat',
    issuedAt: now.toISOString(),
    expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
    spaceId: SPACE,
    jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
    abilities: { kv: { [SPACE]: ['tinycloud.kv/get'] } } as never,
    ...(Object.keys(rawAbilities).length > 0 ? { rawAbilities } : {}),
  }).siwe;
}

const APPS_KEY = { [urn('/apps/xyz.tinycloud.listen/k')]: ['tinycloud.encryption/decrypt'] };
const KEY_DELETE = { [urn('/secrets/x')]: ['tinycloud.encryption/key.delete'] };
const BLOCK = ['tinycloud.encryption/key.block'];
const UNBLOCK = ['tinycloud.encryption/key.unblock'];

async function sign(body: Record<string, unknown>) {
  const { keysRouter } = await import('../routes/keys?app-key-block-keys-sign' as string);
  return keysRouter.request('/key_1/sign', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ requestOrigin: ORIGIN, ...body }),
  });
}
const hex = (text: string) => `0x${Buffer.from(text, 'utf8').toString('hex')}`;

describe('POST /api/keys/:keyId/sign with key.block or key.unblock outside apps/', () => {
  const outside = [
    ['a key', urn('/secrets/k')],
    ['a prefix', urn('/secrets/')],
    ['the default network', urn('')],
  ] as const;

  test.each(outside.flatMap(([name, resource]) => [
    [name, resource, BLOCK],
    [name, resource, UNBLOCK],
  ] as const))('refuses %s %s %j as text, before the key is unsealed', async (_name, resource, abilities) => {
    const response = await sign({ message: siweWith({ [resource]: [...abilities] }) });
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({ code: 'app_key_grant_refused' });
    expect(unseal).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  test.each(['raw', 'personal_sign'])('refuses the same message as hex with format %s', async (format) => {
    const response = await sign({ message: hex(siweWith({ [urn('/secrets/k')]: BLOCK })), format });
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({ code: 'app_key_grant_refused' });
    expect(calls).toEqual([]);
  });

  test('refuses it from an OpenKey web origin too: the route does not know whose key it is', async () => {
    const response = await sign({ message: siweWith({ [urn('/secrets/k')]: BLOCK }), requestOrigin: ORIGIN });
    expect(response.status).toBe(403);
    expect(calls).toEqual([]);
  });

  test('refuses it beside other abilities on the same resource', async () => {
    const response = await sign({ message: siweWith({ [urn('/secrets/k')]: ['tinycloud.encryption/decrypt', ...BLOCK] }) });
    expect(response.status).toBe(403);
    expect(calls).toEqual([]);
  });

  test('still signs decrypt on the same key', async () => {
    const response = await sign({ message: siweWith({ [urn('/secrets/k')]: ['tinycloud.encryption/decrypt'] }) });
    expect(response.status).toBe(200);
    expect(calls).toEqual(['bootstrap', 'sign']);
  });
});
