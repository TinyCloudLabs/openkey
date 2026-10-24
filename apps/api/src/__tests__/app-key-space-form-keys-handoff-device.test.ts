// The same route checks as app-key-refusal-keys-handoff-device.test.ts, with every
// `urn:tinycloud:encryption:<owner>:default/<path>` resource written in the
// space-path form `<space>/encryption/<path>`.
// `apps/` key resources and `key.delete` are refused on the generic signing
// route (`/api/keys/:id/sign`), at the prepared CLI handoff claim, and in the
// device sign-in request.

import { beforeEach, describe, expect, mock, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { mockModules, replaceModules } from './mock-module';
import { MemoryPreparedHandoffStore, PreparedHandoffService } from '../services/prepared-handoff';
import { deviceRequestPermissions } from '../services/device-authorization';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const address = privateKeyToAccount(privateKey).address;
const user = { id: 'user_1', email: 'test@example.com' };
const OWNER = `did:pkh:eip155:1:${address}`;
const SPACE = `tinycloud:pkh:eip155:1:${address}:default`;
const ORIGIN = 'https://listen.tinycloud.xyz';
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


/** The space-path form of the same resources: `urn:…:default/<path>` becomes `<space>/encryption/<path>`. */
function toSpacePathForm(rawAbilities: Record<string, string[]>): { rawAbilities: Record<string, string[]>; encryption: Record<string, string[]> } {
  const prefix = `urn:tinycloud:encryption:${OWNER}:default/`;
  const raw: Record<string, string[]> = {};
  const encryption: Record<string, string[]> = {};
  for (const [resource, abilities] of Object.entries(rawAbilities)) {
    if (resource.startsWith(prefix)) encryption[resource.slice(prefix.length)] = abilities;
    else raw[resource] = abilities;
  }
  return { rawAbilities: raw, encryption };
}

function siweWith(rawAbilities: Record<string, string[]> = {}): string {
  const now = new Date();
  return prepareSession({
    address,
    chainId: 1,
    domain: 'listen.tinycloud.xyz',
    issuedAt: now.toISOString(),
    expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
    spaceId: SPACE,
    jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
    abilities: { kv: { [SPACE]: ['tinycloud.kv/get'] }, ...(Object.keys(toSpacePathForm(rawAbilities).encryption).length > 0 ? { encryption: toSpacePathForm(rawAbilities).encryption } : {}) } as never,
    ...(Object.keys(toSpacePathForm(rawAbilities).rawAbilities).length > 0 ? { rawAbilities: toSpacePathForm(rawAbilities).rawAbilities } : {}),
  }).siwe;
}

const APPS_KEY = { [urn('/apps/xyz.tinycloud.listen/k')]: ['tinycloud.encryption/decrypt'] };
const KEY_DELETE = { [urn('/secrets/x')]: ['tinycloud.encryption/key.delete'] };

describe('POST /api/keys/:keyId/sign', () => {
  async function sign(body: Record<string, unknown>) {
    const { keysRouter } = await import('../routes/keys?app-key-space-form-keys' as string);
    return keysRouter.request('/key_1/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ requestOrigin: ORIGIN, ...body }),
    });
  }
  const hex = (text: string) => `0x${Buffer.from(text, 'utf8').toString('hex')}`;

  test.each([
    ['an app key', APPS_KEY, 'app_key_grant_refused'],
    ['key.delete', KEY_DELETE, 'key_delete_not_grantable'],
  ])('refuses %s as text', async (_name, raw, code) => {
    const response = await sign({ message: siweWith(raw) });
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({ code });
    expect(unseal).not.toHaveBeenCalled();
    expect(ensureTinyCloudBootstrapForApprovedSign).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  test.each(['raw', 'personal_sign'])('refuses an app key written as hex with format %s', async (format) => {
    const response = await sign({ message: hex(siweWith(APPS_KEY)), format });
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({ code: 'app_key_grant_refused' });
    expect(calls).toEqual([]);
  });

  test('refuses a ReCap that cannot be read exactly', async () => {
    const message = siweWith().replace(/(- urn:recap:)\S*/, '$1%%%');
    const response = await sign({ message });
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({ code: 'invalid_siwe_recap' });
    expect(calls).toEqual([]);
  });

  test('still signs a message with no app keys', async () => {
    const response = await sign({ message: siweWith() });
    expect(response.status).toBe(200);
    expect(calls).toEqual(['bootstrap', 'sign']);
  });
});

describe('prepared CLI handoff claim', () => {
  const callback = 'http://127.0.0.1:42317/callback/AAAAAAAAAAAAAAAAAAAAAA';
  const delivery = {
    handoffId: Buffer.alloc(32, 3).toString('base64url'),
    callback,
    state: Buffer.alloc(32, 1).toString('base64url'),
    cancelSecret: Buffer.alloc(32, 2).toString('base64url'),
  };

  function claim(rawAbilities: Record<string, string[]>) {
    const jwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
    const now = new Date('2026-10-24T09:00:00.000Z');
    const siwe = prepareSession({
      address,
      chainId: 1,
      domain: 'cli.tinycloud.xyz',
      issuedAt: now.toISOString(),
      expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
      spaceId: SPACE,
      jwk,
      abilities: { kv: { [SPACE]: ['tinycloud.kv/get'] }, ...(Object.keys(toSpacePathForm(rawAbilities).encryption).length > 0 ? { encryption: toSpacePathForm(rawAbilities).encryption } : {}) } as never,
      ...(Object.keys(toSpacePathForm(rawAbilities).rawAbilities).length > 0 ? { rawAbilities: toSpacePathForm(rawAbilities).rawAbilities } : {}),
    }).siwe;
    const service = new PreparedHandoffService(new MemoryPreparedHandoffStore(), { now: () => now.getTime() });
    return service.claim({
      transportVersion: 2,
      request: { protocolVersion: 1, siwe, jwk, host: 'https://node.tinycloud.xyz', sessionDid: 'did:key:session-cli', keyId: 'key-one' },
      delivery,
    }, 'owner');
  }

  test('claims a request with no app keys', async () => {
    await expect(claim({})).resolves.toMatchObject({ ticket: delivery.handoffId });
  });

  test.each([
    ['an app key', APPS_KEY, 'app_key_grant_refused', 'App keys can only be requested from a website, not from the command line or a device sign-in.'],
    ['key.delete', KEY_DELETE, 'key_delete_not_grantable', "Apps can't be given permission to delete keys, so OpenKey didn't approve this request."],
  ])('refuses %s', async (_name, raw, code, message) => {
    await expect(claim(raw)).rejects.toMatchObject({ code, status: 403, message });
  });
});

describe('device sign-in request', () => {
  const entry = (over: Record<string, unknown>) => ({
    service: 'tinycloud.encryption',
    space: 'default',
    path: '',
    actions: ['tinycloud.encryption/decrypt'],
    ...over,
  });
  const NON_BROWSER = 'App keys can only be requested from a website, not from the command line or a device sign-in.';

  test('accepts the default-key decrypt request', () => {
    expect(deviceRequestPermissions([entry({})])).toHaveLength(1);
  });

  test.each([
    ['an apps/ key path', entry({ path: 'apps/xyz.tinycloud.listen/k' })],
    ['an apps/ prefix', entry({ path: 'apps/xyz.tinycloud.listen/', actions: ['tinycloud.encryption/key.create'] })],
    ['an apps/ path in capitals', entry({ path: 'APPS/x/y' })],
    ['a key URN', entry({ path: urn('/apps/xyz.tinycloud.listen/k') })],
    ['a key URN outside apps/', entry({ path: urn('/secrets/x') })],
    ['a key.create action with an apps/ path', entry({ path: 'apps/x/k', actions: ['tinycloud.encryption/key.create', 'tinycloud.encryption/decrypt'] })],
  ])('refuses %s with the command-line wording', (_name, permission) => {
    expect(() => deviceRequestPermissions([permission])).toThrow(NON_BROWSER);
  });

  test.each([
    ['key.create on the default network', entry({ actions: ['tinycloud.encryption/key.create'] })],
    ['key.delete on the default network', entry({ actions: ['tinycloud.encryption/key.delete'] })],
    ['block and decrypt together', entry({ actions: ['tinycloud.encryption/key.block', 'tinycloud.encryption/decrypt'] })],
  ])('refuses %s', (_name, permission) => {
    expect(() => deviceRequestPermissions([permission])).toThrow('actions must be exactly tinycloud.encryption/decrypt');
  });

  test('an apps/ path on a kv entry is an ordinary path', () => {
    const kv = { service: 'tinycloud.kv', space: 'default', path: 'apps/x', actions: ['tinycloud.kv/get'] };
    const capabilities = { service: 'tinycloud.capabilities', space: 'default', path: '', actions: ['tinycloud.capabilities/read'] };
    expect(deviceRequestPermissions([kv, capabilities])).toHaveLength(2);
  });
});
