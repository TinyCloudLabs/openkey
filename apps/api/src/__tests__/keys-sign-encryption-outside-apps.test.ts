// `/api/keys/:keyId/sign` (TC-2247): a message that names encryption `decrypt` or
// `key.create` outside `apps/`, a bare network (no path) included, is signed only for a
// first-party origin (services/first-party-origins.ts). Any other verified origin gets the
// existing `app_key_grant_refused` 403 before the key is unsealed, for the SIWE text and for
// the same text as `0x` hex. A ReCap that cannot be read is refused, never passed.

import './tc1777-test-env';
import { beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { mockModules, replaceModules } from './mock-module';
import {
  FIRST_PARTY_ENCRYPTION_ORIGINS,
  FIRST_PARTY_PAGES_SUBDOMAINS,
  isFirstPartyEncryptionOrigin,
} from '../services/first-party-origins';
import { encryptionOutsideAppsRefusal, encryptionOutsideAppsRefusalForMessage } from '../services/app-key-refusal';
import { extractRecapAttenuations } from './cli-consumer-check';

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

/** The SIWE domain a site at `origin` must name: its host, or `localhost` for Tauri's custom scheme. */
const domainOf = (origin: string) => (origin === 'tauri://localhost' ? 'localhost' : new URL(origin).host);

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
  const { keysRouter } = await import('../routes/keys?keys-sign-encryption-outside-apps' as string);
  return keysRouter.request('/key_1/sign', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}
const hex = (text: string) => `0x${Buffer.from(text, 'utf8').toString('hex')}`;

const NOT_DECLARED = "This website doesn't list the key this app asked for, so OpenKey didn't approve it.";
const REFUSED = { error: NOT_DECLARED, code: 'app_key_grant_refused' };

// The six shapes a site could use to reach decrypt or key.create outside apps/.
const SHAPES: Array<[string, Record<string, string[]>]> = [
  ['decrypt on the bare network', { [urn('')]: [`${E}decrypt`] }],
  ['decrypt and network.create on the bare network (the SDK default)', { [urn('')]: [`${E}decrypt`, `${E}network.create`] }],
  ['key.create on the bare network', { [urn('')]: [`${E}key.create`] }],
  ['decrypt on share/', { [urn('/share/')]: [`${E}decrypt`] }],
  ['decrypt and key.create on a folder', { [urn('/qa/')]: [`${E}key.create`, `${E}decrypt`] }],
  ['decrypt on an exact key outside apps/', { [urn('/secrets/k')]: [`${E}decrypt`] }],
];

describe('an origin that is not first-party', () => {
  test.each(SHAPES.flatMap(([name, raw]) => [
    [name, 'text', raw],
    [name, 'hex', raw],
  ] as const))('is refused %s as %s, and nothing is unsealed', async (_name, form, raw) => {
    const siwe = siweWith(THIRD_PARTY, raw);
    const res = await sign(
      form === 'text'
        ? { message: siwe, requestOrigin: THIRD_PARTY }
        : { message: hex(siwe), format: 'raw', requestOrigin: THIRD_PARTY },
    );
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toEqual(REFUSED);
    expect(unseal).not.toHaveBeenCalled();
    expect(ensureTinyCloudBootstrapForApprovedSign).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  test('is refused a ReCap that cannot be read exactly, never passed', async () => {
    const siwe = siweWith(THIRD_PARTY).replace(/(- urn:recap:)\S*/, `$1${Buffer.from('{"att":{},"att":{}}').toString('base64url')}`);
    const res = await sign({ message: siwe, requestOrigin: THIRD_PARTY });
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toMatchObject({ code: 'invalid_siwe_recap' });
    expect(unseal).not.toHaveBeenCalled();
  });

  test('still signs a sign-in with a manifest that has no encryption entry (the documented shape)', async () => {
    const siwe = siweWith(THIRD_PARTY, {}, {
      kv: { [SPACE]: ['tinycloud.kv/get', 'tinycloud.kv/put', 'tinycloud.kv/list'] },
      capabilities: { [SPACE]: ['tinycloud.capabilities/read'] },
    });
    const res = await sign({ message: siwe, requestOrigin: THIRD_PARTY });
    expect(res.status, await res.clone().text()).toBe(200);
    expect(unseal).toHaveBeenCalledTimes(1);
    expect(calls).toEqual(['sign']);
  });

  test('still signs a sign-in that names network.create alone and a message that is not a sign-in', async () => {
    for (const message of [siweWith(THIRD_PARTY, { [urn('')]: [`${E}network.create`] }), 'hello from a website']) {
      const res = await sign({ message, requestOrigin: THIRD_PARTY });
      expect(res.status, await res.clone().text()).toBe(200);
    }
  });

  test('still gets the earlier answers: an apps/ key is refused as before, a SIWE for another site by the origin check', async () => {
    const apps = await sign({
      message: siweWith(THIRD_PARTY, { [urn('/apps/xyz.thirdparty/k')]: [`${E}decrypt`] }),
      requestOrigin: THIRD_PARTY,
    });
    expect(apps.status).toBe(403);
    await expect(apps.json()).resolves.toMatchObject({ code: 'app_key_grant_refused' });

    const other = await sign({ message: siweWith('https://tinycloud.chat', { [urn('')]: [`${E}decrypt`] }), requestOrigin: THIRD_PARTY });
    expect(other.status).toBe(403);
    await expect(other.json()).resolves.toMatchObject({ code: 'siwe_origin_refused', reason: 'domain-mismatch' });
    expect(unseal).not.toHaveBeenCalled();
  });
});

describe('a first-party origin', () => {
  const previews = FIRST_PARTY_PAGES_SUBDOMAINS.flatMap((name) => [`https://${name}.pages.dev`, `https://a1b2c3d4.${name}.pages.dev`, `https://feat-x.${name}.pages.dev`]);
  const origins = [...FIRST_PARTY_ENCRYPTION_ORIGINS, ...previews];

  test('the list is the one briefed: six production origins and our own Pages projects', () => {
    expect([...FIRST_PARTY_ENCRYPTION_ORIGINS].sort()).toEqual([
      'http://tauri.localhost',
      'https://lightning-node-1.gecko-snares.ts.net',
      'https://secrets.tinycloud.xyz',
      'https://share.tinycloud.xyz',
      'https://tinycloud.chat',
      'tauri://localhost',
    ]);
    expect([...FIRST_PARTY_PAGES_SUBDOMAINS].sort()).toEqual(['openkey-tinycloud-demo', 'share-2fz', 'tinychat-4jq', 'tinycloud-secrets']);
  });

  test.each(origins)('%s signs the SDK default sign-in (bare-network decrypt and network.create) and a folder grant', async (origin) => {
    for (const raw of [SHAPES[1]![1], SHAPES[4]![1]]) {
      unseal.mockClear();
      calls = [];
      const res = await sign({ message: siweWith(origin, raw), requestOrigin: origin });
      expect(res.status, await res.clone().text()).toBe(200);
      expect(unseal).toHaveBeenCalledTimes(1);
      expect(calls).toEqual(['sign']);
    }
  });

  test('signs the same message as 0x hex', async () => {
    const res = await sign({ message: hex(siweWith('https://tinycloud.chat', SHAPES[1]![1])), format: 'raw', requestOrigin: 'https://tinycloud.chat' });
    expect(res.status, await res.clone().text()).toBe(200);
  });
});

// Inbox (TC-2230, inbox #32): one sign-in with eight ReCap rows, the last of them `decrypt` and
// `network.create` on the owner's `inbox` encryption network. The rows are those of the renewal
// fixture in the Inbox repository (tests/fixtures/signin-renewal.json).
describe('the Inbox sign-in', () => {
  const INBOX_ORIGIN = 'https://lightning-node-1.gecko-snares.ts.net';
  const MESSAGES = `tinycloud:pkh:eip155:1:${address}:messages`;
  const PUBLIC = `tinycloud:pkh:eip155:1:${address}:public`;
  const KV = ['tinycloud.kv/del', 'tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/metadata', 'tinycloud.kv/put'];
  const SQL = ['tinycloud.sql/read', 'tinycloud.sql/schema', 'tinycloud.sql/write'];
  const CAPS = ['tinycloud.capabilities/read'];
  const INBOX_NETWORK = urn('').replace(':default', ':inbox');
  const messagesRows = {
    capabilities: { '': CAPS },
    kv: { 'xyz.tinycloud.inbox/media/': KV, 'xyz.tinycloud.inbox/sessions/': KV },
    sql: { 'xyz.tinycloud.inbox/data': SQL, 'xyz.tinycloud.inbox/triage': SQL },
  };
  const publicRows = { capabilities: { '': CAPS }, kv: { 'xyz.tinycloud.inbox/grants/': ['tinycloud.kv/put'] } };

  function inboxSiwe(domain: string): string {
    const now = new Date();
    return prepareSession({
      address,
      chainId: 1,
      domain,
      issuedAt: now.toISOString(),
      expirationTime: new Date(now.getTime() + 7 * 86_400_000).toISOString(),
      spaceId: MESSAGES,
      jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
      abilities: messagesRows as never,
      spaceAbilities: { [MESSAGES]: messagesRows, [PUBLIC]: publicRows } as never,
      rawAbilities: { [INBOX_NETWORK]: ['tinycloud.encryption/decrypt', 'tinycloud.encryption/network.create'] },
    }).siwe;
  }

  test('the request built here has the eight rows of the Inbox fixture', () => {
    const rows = extractRecapAttenuations(inboxSiwe('lightning-node-1.gecko-snares.ts.net'));
    expect(Object.keys(rows).sort()).toEqual([
      `${MESSAGES}/capabilities`,
      `${MESSAGES}/kv/xyz.tinycloud.inbox/media/`,
      `${MESSAGES}/kv/xyz.tinycloud.inbox/sessions/`,
      `${MESSAGES}/sql/xyz.tinycloud.inbox/data`,
      `${MESSAGES}/sql/xyz.tinycloud.inbox/triage`,
      `${PUBLIC}/capabilities`,
      `${PUBLIC}/kv/xyz.tinycloud.inbox/grants/`,
      INBOX_NETWORK,
    ].sort());
    expect(Object.keys(rows[INBOX_NETWORK]!).sort()).toEqual(['tinycloud.encryption/decrypt', 'tinycloud.encryption/network.create']);
  });

  test('signs from the Inbox origin, as text and as 0x hex', async () => {
    const siwe = inboxSiwe('lightning-node-1.gecko-snares.ts.net');
    for (const body of [{ message: siwe }, { message: hex(siwe), format: 'raw' }]) {
      unseal.mockClear();
      const res = await sign({ ...body, requestOrigin: INBOX_ORIGIN });
      expect(res.status, await res.clone().text()).toBe(200);
      expect(unseal).toHaveBeenCalledTimes(1);
    }
  });

  test.each([
    ['the retired port', 'https://lightning-node-1.gecko-snares.ts.net:8451'],
    ['plain http', 'http://lightning-node-1.gecko-snares.ts.net'],
    ['a longer host', 'https://lightning-node-1.gecko-snares.ts.net.evil.example'],
    ['a prefixed host', 'https://evil-lightning-node-1.gecko-snares.ts.net'],
    ['another node on the tailnet', 'https://lightning-node-2.gecko-snares.ts.net'],
    ['the tailnet name alone', 'https://gecko-snares.ts.net'],
  ])('is refused from %s', async (_name, origin) => {
    expect(isFirstPartyEncryptionOrigin(origin)).toBe(false);
    const res = await sign({ message: inboxSiwe(new URL(origin).host), requestOrigin: origin });
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toEqual(REFUSED);
    expect(unseal).not.toHaveBeenCalled();
  });

  test('is refused from an unrelated site', async () => {
    const res = await sign({ message: inboxSiwe('thirdparty.example'), requestOrigin: THIRD_PARTY });
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toEqual(REFUSED);
    expect(unseal).not.toHaveBeenCalled();
  });
});

describe('look-alikes of a first-party origin are not first-party', () => {
  const lookAlikes = [
    'https://tinycloud.chat.evil.example',
    'https://evil-tinycloud.chat',
    'https://tinycloud.chat:8443',
    'http://tinycloud.chat',
    'https://TINYCLOUD.CHAT',
    'https://listen.tinycloud.xyz',
    'https://demo.tinycloud.xyz',
    'https://tinychat-4jq.pages.dev.evil.example',
    'https://a.b.tinychat-4jq.pages.dev',
    'https://evil.pages.dev',
    'https://tinycloud-secrets.pages.dev:8443',
    'http://tinychat-4jq.pages.dev',
    'tauri://localhost:1420',
    'https://tauri.localhost',
    'http://localhost',
  ];

  test.each(lookAlikes)('%s is refused bare-network decrypt', async (origin) => {
    expect(isFirstPartyEncryptionOrigin(origin)).toBe(false);
    const domain = origin.startsWith('tauri:') ? 'localhost' : new URL(origin).host.toLowerCase();
    const siwe = siweWith(`https://${domain}`, SHAPES[1]![1]);
    const res = await sign({ message: siwe, requestOrigin: origin });
    // Either the new refusal, or the earlier origin check for a spelling it does not accept.
    expect(res.status).toBe(403);
    expect(unseal).not.toHaveBeenCalled();
  });

  test('an unusable origin value is not first-party', () => {
    for (const origin of [undefined, null, '', '*', 'null', 7, {}]) expect(isFirstPartyEncryptionOrigin(origin)).toBe(false);
  });
});

describe('encryptionOutsideAppsRefusal', () => {
  test('refuses a ReCap it cannot read, instead of passing it', () => {
    const siwe = siweWith(THIRD_PARTY).replace(/(- urn:recap:)\S*/, `$1${Buffer.from('{"att":{},"att":{}}').toString('base64url')}`);
    expect(encryptionOutsideAppsRefusal(siwe)).toEqual({ reason: 'recap_unreadable' });
    expect(encryptionOutsideAppsRefusalForMessage(hex(siwe))).toEqual({ reason: 'recap_unreadable' });
  });

  test('passes text that is not a sign-in, and a sign-in without encryption outside apps/', () => {
    expect(encryptionOutsideAppsRefusal('hello')).toBeNull();
    expect(encryptionOutsideAppsRefusalForMessage(hex('hello'))).toBeNull();
    expect(encryptionOutsideAppsRefusal(siweWith(THIRD_PARTY))).toBeNull();
    expect(encryptionOutsideAppsRefusal(siweWith(THIRD_PARTY, { [urn('/apps/xyz.thirdparty/')]: [`${E}decrypt`] }))).toBeNull();
  });

  test('names the resource shapes that need a first-party origin', () => {
    for (const [, raw] of SHAPES) {
      expect(encryptionOutsideAppsRefusal(siweWith(THIRD_PARTY, raw))).toEqual({ reason: 'apps_key' });
      expect(encryptionOutsideAppsRefusalForMessage(hex(siweWith(THIRD_PARTY, raw)))).toEqual({ reason: 'apps_key' });
    }
  });
});
