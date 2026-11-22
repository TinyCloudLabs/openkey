// Hardening: registry record signing. `/api/keys/:keyId/sign` and its passkey offer sign a registry record payload
// (v1 or v2 canonical JSON, as text or as 0x hex) only for TinyCloud One / Home; any other origin, and a request that
// names no origin, is refused before a passkey is offered and before the key is unsealed.

import './tc1777-test-env';
import { beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { recoverMessageAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const address = privateKeyToAccount(privateKey).address;
const user = { id: 'user_1', email: 'test@example.com' };
const SPACE = `tinycloud:pkh:eip155:1:${address}:default`;
const FOREIGN = 'https://thirdparty.example';
const REFUSAL = {
  error: "Only TinyCloud One can request a signature that sets the account's node location through OpenKey. Nothing was signed.",
  code: 'registry_record_sign_refused',
};
const ALLOWED_ORIGINS = [
  'https://home.tinycloud.xyz',
  'https://secrets.tinycloud.xyz',
  'https://share.tinycloud.xyz',
  'https://tinycloud.one',
];

let calls: string[] = [];
const unseal = mock(async () => privateKey);
const ensureTinyCloudBootstrapForApprovedSign = mock(async () => ({ status: 'complete' as const }));
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
  '../services/tinycloud-bootstrap': () => ({ ensureTinyCloudBootstrapForApprovedSign }),
});

beforeEach(() => {
  calls = [];
  unseal.mockClear();
  prisma.ethereumKey.findFirst.mockClear();
  ensureTinyCloudBootstrapForApprovedSign.mockClear();
});

const DID = `did:pkh:eip155:1:${address}`;
const NODE_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const V1 = {
  version: 1,
  subject: DID,
  multiaddrs: ['/dns4/node.example/tcp/443/https'],
  updated_at: '2026-11-22T14:00:00.000Z',
  sequence: 7,
};
const V2 = {
  version: 2,
  subject: DID,
  nodes: [{ did: NODE_DID, url: 'https://node.example' }],
  spaces: [{ space: `tinycloud:pkh:eip155:1:${address}:default`, nodes: [{ did: NODE_DID, mode: 'read-write' }] }],
  encryptionNode: NODE_DID,
  updated_at: '2026-11-22T14:00:00.000Z',
  sequence: 8,
};
const reordered = (record: Record<string, unknown>) => Object.fromEntries(Object.entries(record).reverse());
const hex = (text: string) => `0x${Buffer.from(text, 'utf8').toString('hex')}`;

const PAYLOADS: Array<[string, string, 'raw' | undefined]> = [
  ['v1 text', JSON.stringify(V1), undefined],
  ['v1 hex', hex(JSON.stringify(V1)), 'raw'],
  ['v2 text', JSON.stringify(V2), undefined],
  ['v2 hex', hex(JSON.stringify(V2)), 'raw'],
  ['v1 with its keys reordered and spaced out', JSON.stringify(reordered(V1), null, 2), undefined],
  ['v2 with its keys reordered and spaced out, as hex', hex(JSON.stringify(reordered(V2), null, 4)), 'raw'],
  ['v1 hex sent as plain text', hex(JSON.stringify(V1)), undefined],
  ['v1 hex with capital digits', `0x${Buffer.from(JSON.stringify(V1), 'utf8').toString('hex').toUpperCase()}`, 'raw'],
];

async function post(path: string, body: Record<string, unknown>, headers: Record<string, string | null> = {}) {
  const { keysRouter } = await import('../routes/keys?keys-sign-registry-record' as string);
  const sent: Record<string, string> = { 'content-type': 'application/json', origin: 'http://localhost:5173' };
  for (const [name, value] of Object.entries(headers)) {
    if (value === null) delete sent[name];
    else sent[name] = value;
  }
  return keysRouter.request(path, { method: 'POST', headers: sent, body: JSON.stringify(body) });
}
const sign = (body: Record<string, unknown>) => post('/key_1/sign', body);

describe('/api/keys/:keyId/sign refuses a registry record payload from any other origin', () => {
  test.each(PAYLOADS)('%s', async (_label, message, format) => {
    for (const requestOrigin of [FOREIGN, 'http://localhost:5173', 'null', '*', '']) {
      const res = await sign({ message, ...(format ? { format } : {}), requestOrigin });
      expect(res.status, requestOrigin).toBe(403);
      expect(await res.json(), requestOrigin).toEqual(REFUSAL);
    }
    const unattributed = await sign({ message, ...(format ? { format } : {}) });
    expect(unattributed.status).toBe(403);
    expect(await unattributed.json()).toEqual(REFUSAL);
    expect(calls).toEqual([]);
    expect(unseal).not.toHaveBeenCalled();
    expect(prisma.ethereumKey.findFirst).not.toHaveBeenCalled();
  });

  test('an origin that only looks like an allowed one is refused', async () => {
    const lookalikes = [
      'https://home.tinycloud.xyz.evil.example',
      'https://evil.example/https://home.tinycloud.xyz',
      'http://home.tinycloud.xyz',
      'https://HOME.tinycloud.xyz',
      'https://home.tinycloud.xyz/',
      'https://sub.tinycloud.one',
      'tauri://localhost',
      'http://tauri.localhost',
      'tinycloudone://app.tinycloud.one',
      'http://localhost:5173',
      'tauri://localhost:1420',
    ];
    for (const requestOrigin of lookalikes) {
      const res = await sign({ message: JSON.stringify(V2), requestOrigin });
      expect(res.status, requestOrigin).toBe(403);
    }
    expect(calls).toEqual([]);
  });

  test('a non-string origin is refused', async () => {
    for (const requestOrigin of [1, ['https://home.tinycloud.xyz'], { origin: 'https://home.tinycloud.xyz' }]) {
      const res = await sign({ message: JSON.stringify(V1), requestOrigin });
      expect(res.status).toBe(403);
    }
    expect(calls).toEqual([]);
  });

  test('a bearer call with no Origin gets the existing refusal and signs nothing', async () => {
    const res = await post('/key_1/sign', { message: JSON.stringify(V1), requestOrigin: ALLOWED_ORIGINS[0] }, { origin: null, authorization: 'Bearer cli-token' });
    expect(res.status).toBe(403);
    expect(calls).toEqual([]);
    expect(unseal).not.toHaveBeenCalled();
  });
});

describe('/api/keys/:keyId/sign/passkey does not offer a passkey for it', () => {
  test.each(PAYLOADS)('%s', async (_label, message, format) => {
    const res = await post('/key_1/sign/passkey', { message, ...(format ? { format } : {}), requestOrigin: FOREIGN });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual(REFUSAL);
    expect(prisma.ethereumKey.findFirst).not.toHaveBeenCalled();
  });
});

describe('/api/keys/:keyId/sign signs it for TinyCloud One and Home', () => {
  test.each(ALLOWED_ORIGINS)('%s', async (requestOrigin) => {
    for (const [, message, format] of PAYLOADS) {
      calls = [];
      const res = await sign({ message, ...(format ? { format } : {}), requestOrigin });
      expect(res.status, message).toBe(200);
      expect(calls, message).toEqual(['sign']);
    }
  });

  test('the signature is the owner\'s over the exact bytes', async () => {
    const res = await sign({ message: JSON.stringify(V1), requestOrigin: 'https://home.tinycloud.xyz' });
    const body = (await res.json()) as { signature: `0x${string}` };
    expect(await recoverMessageAddress({ message: JSON.stringify(V1), signature: body.signature })).toBe(address);
  });
});

describe('every other message is signed as before, from any origin', () => {
  const siwe = (origin: string) => {
    const now = new Date();
    return prepareSession({
      address,
      chainId: 1,
      domain: new URL(origin).host,
      issuedAt: now.toISOString(),
      expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
      spaceId: SPACE,
      jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
      abilities: { kv: { [SPACE]: ['tinycloud.kv/get'] } } as never,
    }).siwe;
  };
  const ordinary: Array<[string, (origin: string) => string, 'raw' | undefined]> = [
    ['plain text', (_o) => 'Sign in to Example', undefined],
    ['a SIWE message for the requesting site', siwe, undefined],
    ['unrelated JSON', () => JSON.stringify({ hello: 'world', sequence: 1 }), undefined],
    ['a record missing one of its fields', () => JSON.stringify({ ...V1, multiaddrs: undefined }), undefined],
    ['a v1 record with the version of another format', () => JSON.stringify({ ...V1, version: 3 }), undefined],
    ['a JSON array holding a record', () => JSON.stringify([V1]), undefined],
    ['a JSON string holding a record', () => JSON.stringify(JSON.stringify(V1)), undefined],
    ['hex of unrelated JSON', () => hex(JSON.stringify({ a: 1 })), 'raw'],
    ['hex that is not UTF-8 JSON', () => '0x00ff10', 'raw'],
    ['empty hex', () => '0x', 'raw'],
  ];

  test.each(ordinary)('%s', async (_label, build, format) => {
    for (const requestOrigin of [FOREIGN, 'https://home.tinycloud.xyz']) {
      calls = [];
      const res = await sign({ message: build(requestOrigin), ...(format ? { format } : {}), requestOrigin });
      expect(res.status, requestOrigin).toBe(200);
      expect(calls, requestOrigin).toEqual(['sign']);
    }
  });
});

describe('typed data cannot carry a registry record signature', () => {
  test('the EIP-712 signature does not verify as a signature over the record text', async () => {
    const res = await post('/key_1/sign-typed-data', {
      domain: { name: 'Example', version: '1' },
      types: { Record: [{ name: 'subject', type: 'string' }, { name: 'sequence', type: 'uint256' }] },
      primaryType: 'Record',
      message: { subject: V1.subject, sequence: V1.sequence },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { signature: `0x${string}` };
    for (const record of [V1, V2]) {
      expect(await recoverMessageAddress({ message: JSON.stringify(record), signature: body.signature })).not.toBe(address);
    }
  });
});

describe('the app subdomain of One is not an allowed origin', () => {
  test('a registry record from it is refused on both sign routes', async () => {
    for (const path of ['/key_1/sign', '/key_1/sign/passkey']) {
      const res = await post(path, { message: JSON.stringify(V1), requestOrigin: 'https://app.tinycloud.one' });
      expect(res.status, path).toBe(403);
      expect(await res.json()).toEqual(REFUSAL);
    }
    expect(calls).toEqual([]);
    expect(unseal).not.toHaveBeenCalled();
  });
});
