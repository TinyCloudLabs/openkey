// `/api/keys/:keyId/sign` (TC-2927): exact-byte signing. A message that asks to `decrypt` or `key.create` on the
// encryption network, or on keys outside `apps/`, may be signed from any site, ours or not, once the owner decided
// on it on the warning screen (`elevatedAcknowledged`): these exact bytes cannot be narrowed, so the choice is all or
// nothing. An exact share key (`share/<id>`) is never signed from any site. Everything is checked before the key is
// unsealed, for the SIWE text and for the same text as `0x` hex.

import './tc1777-test-env';
import { beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { mockModules, replaceModules } from './mock-module';
import { exactShareKeyRefusal, exactShareKeyRefusalForMessage, messageHasElevatedPermissions } from '../services/app-key-refusal';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const address = privateKeyToAccount(privateKey).address;
const user = { id: 'user_1', email: 'test@example.com' };
const OWNER = `did:pkh:eip155:1:${address}`;
const SPACE = `tinycloud:pkh:eip155:1:${address}:default`;
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;
const E = 'tinycloud.encryption/';
const THIRD_PARTY = 'https://thirdparty.example';

let calls: string[] = [];
const unseal = mock(async () => privateKey);
const ensureTinyCloudBootstrapForApprovedSign = mock(async () => ({ status: 'complete' as const }));
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

/** The SIWE domain a site at `origin` must name: its host. */
const domainOf = (origin: string) => new URL(origin).host;

function siweWith(origin: string, rawAbilities: Record<string, string[]> = {}, abilities?: Record<string, unknown>): string {
  const now = new Date();
  return prepareSession({
    address,
    chainId: 1,
    domain: domainOf(origin),
    issuedAt: now.toISOString(),
    expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
    spaceId: SPACE,
    jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
    abilities: (abilities ?? { kv: { [SPACE]: ['tinycloud.kv/get'] } }) as never,
    ...(Object.keys(rawAbilities).length > 0 ? { rawAbilities } : {}),
  }).siwe;
}

async function sign(body: Record<string, unknown>) {
  const { keysRouter } = await import('../routes/keys?keys-sign-elevated-permissions' as string);
  return keysRouter.request('/key_1/sign', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'http://localhost:5173' },
    body: JSON.stringify(body),
  });
}
const hex = (text: string) => `0x${Buffer.from(text, 'utf8').toString('hex')}`;

/** A field of a JSON answer, read without trusting its shape. */
async function fieldOf(res: Response, name: string): Promise<unknown> {
  const body: unknown = await res.json();
  return typeof body === 'object' && body !== null && name in body ? Object.getOwnPropertyDescriptor(body, name)?.value : undefined;
}

const SHARE_REFUSED = { error: "This site isn't allowed to request that access.", code: 'app_key_grant_refused' };
const NOT_DECIDED = 'elevated_not_decided';

// The shapes a site may now ask for with the warning screen.
const SHAPES: Array<[string, Record<string, string[]>]> = [
  ['decrypt on the bare network', { [urn('')]: [`${E}decrypt`] }],
  ['decrypt and network.create on the bare network (the SDK default)', { [urn('')]: [`${E}decrypt`, `${E}network.create`] }],
  ['key.create on the bare network', { [urn('')]: [`${E}key.create`] }],
  ['decrypt on share/', { [urn('/share/')]: [`${E}decrypt`] }],
  ['decrypt and key.create on a folder', { [urn('/qa/')]: [`${E}key.create`, `${E}decrypt`] }],
  ['decrypt on an exact key outside apps/ and outside share/', { [urn('/secrets/k')]: [`${E}decrypt`] }],
];
const ORIGINS = [THIRD_PARTY, 'https://share.tinycloud.xyz', 'https://tinycloud.one', 'https://gk.gbafa.com'];

describe('a message that asks for extra permissions', () => {
  test.each(SHAPES.flatMap(([name, raw]) => ORIGINS.flatMap((origin) => [
    [name, origin, raw, 'text'] as const,
    [name, origin, raw, 'hex'] as const,
  ])))('%s from %s (%s) is refused until the owner decided, and the key is not unsealed', async (_name, origin, raw, form) => {
    const siwe = siweWith(origin, raw);
    const res = await sign({ message: form === 'hex' ? hex(siwe) : siwe, format: form === 'hex' ? 'raw' : 'personal_sign', requestOrigin: origin });
    expect(res.status).toBe(403);
    expect(await fieldOf(res, 'code')).toBe(NOT_DECIDED);
    expect(unseal).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  test.each(SHAPES.flatMap(([name, raw]) => ORIGINS.map((origin) => [name, origin, raw] as const)))(
    '%s from %s is signed once the owner decided (elevatedAcknowledged)', async (_name, origin, raw) => {
      const siwe = siweWith(origin, raw);
      const res = await sign({ message: siwe, requestOrigin: origin, elevatedAcknowledged: true });
      expect(res.status, await res.clone().text()).toBe(200);
      expect(calls).toEqual(['sign']);
    },
  );

  test('is signed as 0x hex too once the owner decided', async () => {
    const siwe = siweWith(THIRD_PARTY, { [urn('')]: [`${E}decrypt`] });
    const res = await sign({ message: hex(siwe), format: 'raw', requestOrigin: THIRD_PARTY, elevatedAcknowledged: true });
    expect(res.status, await res.clone().text()).toBe(200);
  });

  test('only an explicit true counts as the owner having decided', async () => {
    const siwe = siweWith(THIRD_PARTY, { [urn('')]: [`${E}decrypt`] });
    for (const elevatedAcknowledged of [false, 'true', 1, null, {}]) {
      const res = await sign({ message: siwe, requestOrigin: THIRD_PARTY, elevatedAcknowledged });
      expect(res.status, JSON.stringify(elevatedAcknowledged)).toBe(403);
    }
    expect(unseal).not.toHaveBeenCalled();
  });

  test('a sign-in with no extra permission needs no decision: network.create alone, no encryption row, and a message that is not a sign-in', async () => {
    for (const raw of [{}, { [urn('')]: [`${E}network.create`] }]) {
      const res = await sign({ message: siweWith(THIRD_PARTY, raw), requestOrigin: THIRD_PARTY });
      expect(res.status, JSON.stringify(raw)).toBe(200);
    }
    const plain = await sign({ message: 'hello world' });
    expect(plain.status).toBe(200);
  });
});

describe('an exact share key', () => {
  const SHARE_SHAPES: Array<[string, Record<string, string[]>]> = [
    ['decrypt on an exact share key', { [urn('/share/abc123')]: [`${E}decrypt`] }],
    ['key.create on an exact share key', { [urn('/share/abc123')]: [`${E}key.create`] }],
  ];

  test.each(SHARE_SHAPES.flatMap(([name, raw]) => ORIGINS.flatMap((origin) => [
    [name, origin, raw, 'text'] as const,
    [name, origin, raw, 'hex'] as const,
  ])))('%s from %s (%s) is refused for every site, even when the owner decided', async (_name, origin, raw, form) => {
    const siwe = siweWith(origin, raw);
    const res = await sign({ message: form === 'hex' ? hex(siwe) : siwe, format: form === 'hex' ? 'raw' : 'personal_sign', requestOrigin: origin, elevatedAcknowledged: true });
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toEqual(SHARE_REFUSED);
    expect(unseal).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  test('is refused beside an otherwise allowed row', async () => {
    const siwe = siweWith(THIRD_PARTY, { [urn('')]: [`${E}decrypt`], [urn('/share/abc123')]: [`${E}decrypt`] });
    const res = await sign({ message: siwe, requestOrigin: THIRD_PARTY, elevatedAcknowledged: true });
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toEqual(SHARE_REFUSED);
  });

  test('the share/ prefix and a longer path are not exact share keys', async () => {
    for (const raw of [{ [urn('/share/')]: [`${E}decrypt`] }, { [urn('/share/a/b')]: [`${E}decrypt`] }]) {
      const res = await sign({ message: siweWith(THIRD_PARTY, raw), requestOrigin: THIRD_PARTY, elevatedAcknowledged: true });
      expect(res.status, JSON.stringify(raw)).toBe(200);
    }
  });
});

describe('the earlier answers are unchanged', () => {
  test('an apps/ key is refused as before, a SIWE for another site by the origin check, key.delete always', async () => {
    const apps = await sign({ message: siweWith(THIRD_PARTY, { [urn('/apps/x.y/k')]: [`${E}decrypt`] }), requestOrigin: THIRD_PARTY, elevatedAcknowledged: true });
    expect(apps.status).toBe(403);
    expect(await fieldOf(apps, 'code')).toBe('app_key_grant_refused');
    const other = await sign({ message: siweWith(THIRD_PARTY, { [urn('')]: [`${E}decrypt`] }), requestOrigin: 'https://other.example', elevatedAcknowledged: true });
    expect(other.status).toBe(403);
    expect(await fieldOf(other, 'code')).toBe('siwe_origin_refused');
    const del = await sign({ message: siweWith(THIRD_PARTY, { [urn('/qa/k')]: [`${E}key.delete`] }), requestOrigin: THIRD_PARTY, elevatedAcknowledged: true });
    expect(del.status).toBe(403);
    expect(unseal).not.toHaveBeenCalled();
  });
});

describe('the shared checks', () => {
  test('exactShareKeyRefusal refuses a ReCap it cannot read, instead of passing it', () => {
    const unreadable = 'x wants you to sign in with your Ethereum account:\n0x0\n\nURI: https://x\nVersion: 1\nChain ID: 1\nNonce: 12345678\nIssued At: 2026-01-01T00:00:00.000Z\nResources:\n- urn:recap:!!!';
    expect(exactShareKeyRefusal(unreadable)?.reason).toBe('recap_unreadable');
    expect(exactShareKeyRefusalForMessage(unreadable)?.reason).toBe('recap_unreadable');
  });

  test('messageHasElevatedPermissions names exactly the shapes that need a decision', () => {
    expect(messageHasElevatedPermissions(siweWith(THIRD_PARTY, { [urn('')]: [`${E}decrypt`] }))).toBe(true);
    expect(messageHasElevatedPermissions(siweWith(THIRD_PARTY, { [urn('/share/')]: [`${E}key.create`] }))).toBe(true);
    expect(messageHasElevatedPermissions(siweWith(THIRD_PARTY, { [urn('')]: [`${E}network.create`] }))).toBe(false);
    expect(messageHasElevatedPermissions(siweWith(THIRD_PARTY, { [urn('/apps/a.b/')]: [`${E}decrypt`] }))).toBe(false);
    expect(messageHasElevatedPermissions('hello world')).toBe(false);
  });
});
