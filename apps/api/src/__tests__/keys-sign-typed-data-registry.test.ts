// Hardening: typed-data signing. `/api/keys/:keyId/sign-typed-data` and its passkey offer sign the registry's
// node-location struct only for TinyCloud One / Home; any other origin, and a request that names no origin, is refused
// before a passkey is offered and before the key is unsealed. Other typed data is signed as before.

import './tc1777-test-env';
import { beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const address = privateKeyToAccount(privateKey).address;
const user = { id: 'user_1', email: 'test@example.com' };
const FOREIGN = 'https://thirdparty.example';
const REFUSAL = {
  error: "Only TinyCloud One can request a signature that sets the account's node location through OpenKey. Nothing was signed.",
  code: 'registry_record_sign_refused',
};
const ALLOWED_ORIGINS = ['https://home.tinycloud.xyz', 'https://tinycloud.one', 'https://app.tinycloud.one'];

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
        signTypedData: async (args: Parameters<typeof wallet.signTypedData>[0]) => {
          calls.push('sign');
          return wallet.signTypedData(args);
        },
      };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => address,
  }),
});

beforeEach(() => {
  calls = [];
  unseal.mockClear();
  prisma.ethereumKey.findFirst.mockClear();
});

const SET_NODE_FIELDS = [
  { name: 'action', type: 'string' },
  { name: 'owner', type: 'address' },
  { name: 'node', type: 'string' },
  { name: 'nonce', type: 'uint256' },
  { name: 'deadline', type: 'uint256' },
];
const REGISTRY_DOMAIN = { name: 'TinyCloudRegistry', version: '1', chainId: 1, verifyingContract: '0x5FbDB2315678afecb367f032d93F642f64180aa3' };
const SET_NODE_MESSAGE = { action: 'set', owner: address, node: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', nonce: 1, deadline: 1900000000 };

const setNode = (over: Record<string, unknown> = {}) => ({
  domain: REGISTRY_DOMAIN,
  types: { SetNode: SET_NODE_FIELDS },
  primaryType: 'SetNode',
  message: SET_NODE_MESSAGE,
  ...over,
});

const REGISTRY_SHAPES: Array<[string, Record<string, unknown>]> = [
  ['the registry struct', setNode()],
  ['the struct name in capitals', setNode({ types: { SETNODE: SET_NODE_FIELDS }, primaryType: 'SETNODE' })],
  ['the struct name in lower case', setNode({ types: { setnode: SET_NODE_FIELDS }, primaryType: 'setnode' })],
  ['the struct name with spaces around it', setNode({ primaryType: '  SetNode  ' })],
  ['the struct name with a tab and a newline', setNode({ primaryType: '\tSetNode\n' })],
  ['the registry domain with another primary type', setNode({ types: { Other: SET_NODE_FIELDS }, primaryType: 'Other' })],
  ['the registry domain name in lower case', setNode({ domain: { ...REGISTRY_DOMAIN, name: 'tinycloudregistry' }, types: { Other: SET_NODE_FIELDS }, primaryType: 'Other' })],
  ['the registry domain name with spaces', setNode({ domain: { ...REGISTRY_DOMAIN, name: ' TinyCloudRegistry ' }, types: { Other: SET_NODE_FIELDS }, primaryType: 'Other' })],
  ['the registry domain with another version', setNode({ domain: { ...REGISTRY_DOMAIN, version: '2' }, types: { Other: SET_NODE_FIELDS }, primaryType: 'Other' })],
  ['the struct defined but another primary type', setNode({ domain: { name: 'Example' }, types: { Mail: [{ name: 'node', type: 'SetNode' }], SetNode: SET_NODE_FIELDS }, primaryType: 'Mail', message: { node: SET_NODE_MESSAGE } })],
];

const MAIL = {
  domain: { name: 'Example', version: '1', chainId: 1 },
  types: { Mail: [{ name: 'contents', type: 'string' }] },
  primaryType: 'Mail',
  message: { contents: 'hello' },
};

async function post(path: string, body: Record<string, unknown>) {
  const { keysRouter } = await import('../routes/keys?keys-sign-typed-data-registry' as string);
  return keysRouter.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'http://localhost:5173' },
    body: JSON.stringify(body),
  });
}
const signTypedData = (body: Record<string, unknown>) => post('/key_1/sign-typed-data', body);

describe('/api/keys/:keyId/sign-typed-data refuses the registry struct from any other origin', () => {
  test.each(REGISTRY_SHAPES)('%s', async (_label, typedData) => {
    for (const requestOrigin of [FOREIGN, 'http://localhost:5173', 'tauri://localhost', 'null', '*', '', 'https://sub.tinycloud.one', 'https://home.tinycloud.xyz/']) {
      const res = await signTypedData({ ...typedData, requestOrigin });
      expect(res.status, requestOrigin).toBe(403);
      expect(await res.json(), requestOrigin).toEqual(REFUSAL);
    }
    const unattributed = await signTypedData(typedData);
    expect(unattributed.status).toBe(403);
    expect(await unattributed.json()).toEqual(REFUSAL);
    expect(calls).toEqual([]);
    expect(unseal).not.toHaveBeenCalled();
    expect(prisma.ethereumKey.findFirst).not.toHaveBeenCalled();
  });

  test('a non-string origin is refused', async () => {
    for (const requestOrigin of [1, ['https://tinycloud.one'], { origin: 'https://tinycloud.one' }]) {
      const res = await signTypedData({ ...setNode(), requestOrigin });
      expect(res.status).toBe(403);
    }
    expect(calls).toEqual([]);
  });

  test('it is refused even when the typed data would not validate', async () => {
    const res = await signTypedData({ ...setNode({ message: { action: 'set' } }), requestOrigin: FOREIGN });
    expect(res.status).toBe(403);
    expect(calls).toEqual([]);
  });
});

describe('/api/keys/:keyId/sign-typed-data/passkey does not offer a passkey for it', () => {
  test.each(REGISTRY_SHAPES)('%s', async (_label, typedData) => {
    for (const requestOrigin of [FOREIGN, undefined]) {
      const res = await post('/key_1/sign-typed-data/passkey', { ...typedData, requestOrigin });
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual(REFUSAL);
    }
    expect(prisma.ethereumKey.findFirst).not.toHaveBeenCalled();
  });
});

describe('/api/keys/:keyId/sign-typed-data signs the registry struct for TinyCloud One and Home', () => {
  test.each(ALLOWED_ORIGINS)('%s', async (requestOrigin) => {
    for (const [label, typedData] of REGISTRY_SHAPES) {
      calls = [];
      const res = await signTypedData({ ...typedData, requestOrigin });
      // A shape the contract could not verify may still be rejected as malformed typed data, but never as a refusal.
      expect(await res.json(), label).not.toEqual(REFUSAL);
    }
    calls = [];
    const res = await signTypedData({ ...setNode(), requestOrigin });
    expect(res.status).toBe(200);
    expect(calls).toEqual(['sign']);
  });
});

describe('every other typed data is signed as before, from any origin', () => {
  const ordinary: Array<[string, Record<string, unknown>]> = [
    ['an unrelated request', MAIL],
    ['a domain that only contains the registry name', { ...MAIL, domain: { name: 'TinyCloudRegistryMirror', version: '1' } }],
    ['a domain named TinyCloud', { ...MAIL, domain: { name: 'TinyCloud', version: '1' } }],
    ['a struct that only contains the name', { ...MAIL, types: { MySetNode: [{ name: 'contents', type: 'string' }] }, primaryType: 'MySetNode' }],
    ['a request with no domain name', { ...MAIL, domain: { chainId: 1 } }],
  ];

  test.each(ordinary)('%s', async (_label, typedData) => {
    for (const requestOrigin of [FOREIGN, 'https://tinycloud.one', undefined]) {
      calls = [];
      const res = await signTypedData({ ...typedData, ...(requestOrigin ? { requestOrigin } : {}) });
      expect(res.status, String(requestOrigin)).toBe(200);
      expect(calls, String(requestOrigin)).toEqual(['sign']);
    }
  });
});
