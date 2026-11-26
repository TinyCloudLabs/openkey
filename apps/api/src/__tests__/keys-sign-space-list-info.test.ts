// POST /api/keys/:id/sign from a site that is not first-party, for a message with a space `list` ability and a kv
// ability and no host ability (the sign-in of an app for an owner who has spaces): signed. A space ability that is
// not `host`, `list` or `info` is refused.

import { afterAll, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { generateHostSIWEMessage } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const user = { id: 'user_1', email: 'alice@example.test' };
const keyRecord = {
  id: 'key_1', userId: user.id, address: account.address, keyType: 'MANAGED' as const,
  archivedAt: null, sealedBlob: 'sealed-blob', sealingContext: null,
};
const spaceId = (name: string) => `tinycloud:pkh:eip155:1:${account.address}:${name}`;
const THIRD_PARTY = 'https://app.example.test';
const PEER = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

let row: { status: string } | null = null;
let signedMessages: string[] = [];
const unseal = mock(async () => privateKey);
const prisma = {
  ethereumKey: { findFirst: mock(async () => keyRecord) },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: { findUnique: mock(async () => row) },
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
      return { address: wallet.address, signMessage: async (args: { message: string }) => { signedMessages.push(args.message); return wallet.signMessage(args); } };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => account.address,
  }),
});

let keysRouter: typeof import('../routes/keys')['keysRouter'];
const savedEnv = { on: process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN, host: process.env.TINYCLOUD_BOOTSTRAP_HOST };
beforeAll(async () => {
  process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN = 'off';
  delete process.env.TINYCLOUD_BOOTSTRAP_HOST;
  ({ keysRouter } = await import('../routes/keys?keys-sign-space-list-info' as string));
});
afterAll(() => {
  for (const [name, value] of Object.entries({ TINYCLOUD_BOOTSTRAP_ON_SIGN: savedEnv.on, TINYCLOUD_BOOTSTRAP_HOST: savedEnv.host })) {
    if (value === undefined) delete process.env[name]; else process.env[name] = value;
  }
});
beforeEach(() => {
  row = null;
  signedMessages = [];
  unseal.mockClear();
});

const PRIMARY = `tinycloud:pkh:eip155:1:${account.address}:account`;
/** A message whose ReCap is `att` (the statement is rewritten to what the recap parser checks). */
function withRecap(att: Record<string, Record<string, unknown[]>>) {
  const base = generateHostSIWEMessage({
    address: account.address, chainId: 1, domain: 'app.example.test', issuedAt: new Date().toISOString(), spaceId: spaceId('public'), peerId: PEER,
  });
  const lines = Object.entries(att).sort(([a], [b]) => a.localeCompare(b)).flatMap(([resource, abilities]) => {
    const byService = new Map<string, string[]>();
    for (const ability of Object.keys(abilities).sort()) {
      const service = ability.slice(0, ability.indexOf('/'));
      byService.set(service, [...(byService.get(service) ?? []), ability.slice(ability.indexOf('/') + 1)]);
    }
    return [...byService].map(([service, names]) => `'${service}': ${names.map((name) => `'${name}'`).join(', ')} for '${resource}'`);
  });
  const statement = `I further authorize the stated URI to perform the following actions on my behalf: ${lines.map((line, i) => `(${i + 1}) ${line}.`).join(' ')}`;
  return base
    .replace(/I further authorize[^\n]*/, statement)
    .replace(/urn:recap:[A-Za-z0-9_-]+/, `urn:recap:${Buffer.from(JSON.stringify({ att, prf: [] })).toString('base64url')}`);
}
const listAndKv = (...spaceAbilities: string[]) => withRecap({
  [`${PRIMARY}/kv/`]: { 'tinycloud.kv/get': [{}] },
  [`${PRIMARY}/space`]: Object.fromEntries(spaceAbilities.map((ability) => [ability, [{}]])),
});

async function sign(message: string) {
  const response = await keysRouter.request('/key_1/sign', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'http://localhost:5173' },
    body: JSON.stringify({ message, requestOrigin: THIRD_PARTY }),
  });
  return { status: response.status, body: (await response.json()) as { signature?: string; code?: string } };
}

describe('POST /api/keys/:id/sign for a space `list` ability, from a site that is not first-party', () => {
  test('signs a list ability and a kv ability for an owner whose primary space has a complete row', async () => {
    row = { status: 'complete' };
    const message = listAndKv('tinycloud.space/list');
    const signed = await sign(message);

    expect(signed.status).toBe(200);
    expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
    expect(signedMessages).toEqual([message]);
  });

  test('signs a list ability and an info ability', async () => {
    row = { status: 'complete' };
    const signed = await sign(listAndKv('tinycloud.space/list', 'tinycloud.space/info'));

    expect(signed.status).toBe(200);
    expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
  });

  test('refuses a create ability and signs nothing', async () => {
    row = { status: 'complete' };
    const signed = await sign(listAndKv('tinycloud.space/list', 'tinycloud.space/create'));

    expect(signed.status).toBe(403);
    expect(signed.body.code).toBe('host_signing_first_party_only');
    expect(signed.body.signature).toBeUndefined();
    expect(unseal).not.toHaveBeenCalled();
    expect(signedMessages).toEqual([]);
  });
});
