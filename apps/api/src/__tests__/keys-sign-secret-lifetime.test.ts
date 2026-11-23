// `/api/keys/:keyId/sign`: signed bytes cannot be shortened, so a message that may `decrypt` or `key.create`
// on a key or prefix under `default/secrets/` for more than 7 days is refused before the key is unsealed. A whole
// network's `decrypt` is refused the same way only while `OPENKEY_NETWORK_DECRYPT_CAP=enabled`.

import './tc1777-test-env';
import { afterEach, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const address = privateKeyToAccount(privateKey).address;
const user = { id: 'user_1', email: 'test@example.com' };
const OWNER = `did:pkh:eip155:1:${address}`;
const SPACE = `tinycloud:pkh:eip155:1:${address}:default`;
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;
const E = 'tinycloud.encryption/';
const SITE = 'https://thirdparty.example';
const DAY_MS = 86_400_000;

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
afterEach(() => {
  delete process.env.OPENKEY_NETWORK_DECRYPT_CAP;
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
  const { keysRouter } = await import('../routes/keys?keys-sign-secret-lifetime' as string);
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
const NETWORK_REFUSED = {
  error: 'This request asks for access to secrets or encrypted data longer than 7 days. Access to secrets or encrypted data lasts at most 7 days, so ask again with an expiry of 7 days or less.',
  code: 'secret_lifetime_exceeded',
};

const SECRET_SHAPES: Array<[string, Record<string, string[]>]> = [
  ["decrypt on one secret's key", { [urn('/secrets/openai_api_key')]: [`${E}decrypt`] }],
  ['key.create on a scoped secret key', { [urn('/secrets/scoped/work/api_key')]: [`${E}key.create`] }],
  ['decrypt on every secret (secrets/)', { [urn('/secrets/')]: [`${E}decrypt`] }],
];

describe('raw signing of a grant on secret keys', () => {
  test.each(SECRET_SHAPES)('%s for 8 days is refused, as text and as hex, before the key is unsealed', async (_name, raw) => {
    const siwe = siweFor(raw, 8 * DAY_MS);
    for (const [message, format] of [[siwe, 'personal_sign'], [hex(siwe), 'raw']] as const) {
      const res = await sign(message, format);
      expect(res.status, format).toBe(400);
      expect(await res.json()).toEqual(REFUSED);
    }
    expect(unseal).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  test.each(SECRET_SHAPES)('%s for 7 days is signed', async (_name, raw) => {
    const res = await sign(siweFor(raw, 7 * DAY_MS));
    expect(res.status, await res.clone().text()).toBe(200);
    expect(calls).toEqual(['sign']);
  });

  test('decrypt on a whole network for 30 days is signed while the network cap is off, refused while it is on', async () => {
    const siwe = siweFor({ [urn('')]: [`${E}decrypt`] }, 30 * DAY_MS);
    expect((await sign(siwe)).status).toBe(200);
    process.env.OPENKEY_NETWORK_DECRYPT_CAP = 'enabled';
    const res = await sign(siwe);
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual(NETWORK_REFUSED);
    expect((await sign(siweFor({ [urn('')]: [`${E}decrypt`] }, 7 * DAY_MS))).status).toBe(200);
  });

  test('a secret key beside a whole network decrypt, with the network cap on, gets the wider words', async () => {
    process.env.OPENKEY_NETWORK_DECRYPT_CAP = 'enabled';
    const res = await sign(siweFor({ [urn('')]: [`${E}decrypt`], [urn('/secrets/openai_api_key')]: [`${E}decrypt`] }, 30 * DAY_MS));
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual(NETWORK_REFUSED);
  });

  test('decrypt on share/ for 30 days is not held to 7 days', async () => {
    process.env.OPENKEY_NETWORK_DECRYPT_CAP = 'enabled';
    const res = await sign(siweFor({ [urn('/share/')]: [`${E}decrypt`] }, 30 * DAY_MS));
    expect(res.status, await res.clone().text()).toBe(200);
  });
});

describe('raw signing of a grant on secret keys, in odd forms', () => {
  const secret = SECRET_SHAPES[0]![1];

  test('a message with no Expiration Time is refused', async () => {
    const res = await sign(siweFor(secret, 30 * DAY_MS).replace(/^Expiration Time: .+\n/m, ''));
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual(REFUSED);
    expect(calls).toEqual([]);
  });

  test('hex in capitals is refused', async () => {
    const res = await sign(`0x${Buffer.from(siweFor(secret, 30 * DAY_MS), 'utf8').toString('hex').toUpperCase()}`, 'raw');
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual(REFUSED);
    expect(calls).toEqual([]);
  });

  test('abilities named without the tinycloud. prefix are refused', async () => {
    const res = await sign(siweFor({ [urn('/secrets/openai_api_key')]: ['encryption/decrypt'] }, 30 * DAY_MS));
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual(REFUSED);
    expect(calls).toEqual([]);
  });

  test('SECRETS/ in capitals is held like secrets/', async () => {
    const res = await sign(siweFor({ [urn('/SECRETS/openai_api_key')]: [`${E}decrypt`] }, 30 * DAY_MS));
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual(REFUSED);
    expect(calls).toEqual([]);
  });

  test('a ReCap that cannot be read is refused, and nothing is signed', async () => {
    const siwe = siweFor({ [urn('/share/')]: [`${E}decrypt`] }, 30 * DAY_MS);
    const res = await sign(siwe.replace(/^- urn:recap:[A-Za-z0-9_-]+$/m, '- urn:recap:%%%not-base64%%%'));
    expect(res.status).toBe(400);
    expect(calls).toEqual([]);
  });
});

// A read of the secrets vault in the KV store is held to 7 days like a grant on secret keys, with no flag.
const KV_VAULT_SHAPES: Array<[string, Record<string, string[]>]> = [
  ['get on one secret', { [`${SPACE}/kv/vault/secrets/OPENAI_API_KEY`]: ['tinycloud.kv/get'] }],
  ['get on a scoped secret', { [`${SPACE}/kv/vault/secrets/scoped/work/API_KEY`]: ['tinycloud.kv/get'] }],
  ['get on the whole vault', { [`${SPACE}/kv/vault/secrets/`]: ['tinycloud.kv/get'] }],
  ['list on the whole vault', { [`${SPACE}/kv/vault/secrets/`]: ['tinycloud.kv/list'] }],
  ['get, named without the tinycloud. prefix', { [`${SPACE}/kv/vault/secrets/OPENAI_API_KEY`]: ['kv/get'] }],
];

describe('raw signing of a KV read of the secrets vault', () => {
  test.each(KV_VAULT_SHAPES)('%s for 8 days is refused, as text and as hex, before the key is unsealed', async (_name, raw) => {
    const siwe = siweFor(raw, 8 * DAY_MS);
    for (const [message, format] of [[siwe, 'personal_sign'], [hex(siwe), 'raw']] as const) {
      const res = await sign(message, format);
      expect(res.status, format).toBe(400);
      expect(await res.json()).toEqual(REFUSED);
    }
    expect(unseal).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  test.each(KV_VAULT_SHAPES)('%s for 7 days is signed', async (_name, raw) => {
    const res = await sign(siweFor(raw, 7 * DAY_MS));
    expect(res.status, await res.clone().text()).toBe(200);
    expect(calls).toEqual(['sign']);
  });

  test('a read of another folder for 30 days is signed', async () => {
    const res = await sign(siweFor({ [`${SPACE}/kv/notes/`]: ['tinycloud.kv/get'] }, 30 * DAY_MS));
    expect(res.status, await res.clone().text()).toBe(200);
  });

  test('a KV read on a resource that cannot be read as a space path counts as the vault: 8 days is refused, 7 signed', async () => {
    const raw = { [`${SPACE}/share/x`]: ['tinycloud.kv/get'] };
    const refused = await sign(siweFor(raw, 8 * DAY_MS));
    expect(refused.status).toBe(400);
    expect(await refused.json()).toEqual(REFUSED);
    expect(calls).toEqual([]);
    const signed = await sign(siweFor(raw, 7 * DAY_MS));
    expect(signed.status, await signed.clone().text()).toBe(200);
  });
});

// Any action of the secrets service is held to 7 days, with no flag: nothing shows that one returns only ciphertext.
const SECRETS_SERVICE_SHAPES: Array<[string, Record<string, string[]>]> = [
  ['get', { [`${SPACE}/secrets/mailchimp-api-key`]: ['tinycloud.secrets/get'] }],
  ['read', { [`${SPACE}/secrets/mailchimp-api-key`]: ['tinycloud.secrets/read'] }],
  ['list on the whole service', { [`${SPACE}/secrets/`]: ['tinycloud.secrets/list'] }],
  ['an action the service is not known to have', { [`${SPACE}/secrets/mailchimp-api-key`]: ['tinycloud.secrets/rotate'] }],
];

describe('raw signing of a grant on the secrets service', () => {
  test.each(SECRETS_SERVICE_SHAPES)('%s for 8 days is refused, before the key is unsealed', async (_name, raw) => {
    const res = await sign(siweFor(raw, 8 * DAY_MS));
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual(REFUSED);
    expect(unseal).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  test.each(SECRETS_SERVICE_SHAPES)('%s for 7 days is signed', async (_name, raw) => {
    const res = await sign(siweFor(raw, 7 * DAY_MS));
    expect(res.status, await res.clone().text()).toBe(200);
    expect(calls).toEqual(['sign']);
  });
});
