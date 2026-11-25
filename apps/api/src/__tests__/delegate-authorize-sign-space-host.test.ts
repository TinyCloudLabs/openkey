// POST /api/delegate/authorize-sign-prepare and /authorize-sign (the versioned sign-in). The owner approves what the
// screen shows, and the server signs the app's SIWE as written. A message that hosts a space is the ability to create
// that space on the node, so the same rule as POST /api/keys/:id/sign applies to it, from the origin the server
// checked the SIWE against: TinyCloud's own apps are signed for; any other site only for its own non-primary spaces
// once the owner's primary space is hosted; an unattributed request is another site.

import { afterAll, beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { generateHostSIWEMessage } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import { mockModules, replaceModules } from './mock-module';
import { escapedHostSpellings, withRawRecap } from './space-host-recap';

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
  ({ delegateRouter: router } = await import('../routes/delegate?authorize-sign-space-host' as string));
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
const hostBoth = (first: string, second: string, origin = THIRD_PARTY) => {
  const att = { [`${spaceId(first)}/space`]: { 'tinycloud.space/host': [{}] }, [`${spaceId(second)}/space`]: { 'tinycloud.space/host': [{}] } };
  const lines = Object.keys(att).sort().map((resource, i) => `(${i + 1}) 'tinycloud.space': 'host' for '${resource}'.`);
  return hostSiwe(first, origin)
    .replace(/I further authorize[^\n]*/, `I further authorize the stated URI to perform the following actions on my behalf: ${lines.join(' ')}`)
    .replace(/urn:recap:[A-Za-z0-9_-]+/, `urn:recap:${Buffer.from(JSON.stringify({ att, prf: [] })).toString('base64url')}`);
};

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

function expectRefused(reply: Reply) {
  expect(reply.status).toBe(403);
  expect(reply.body.code).toBe('host_signing_first_party_only');
  expect(reply.body.signature).toBeUndefined();
  expect(signed).toEqual([]);
}

describe('a sign-in that hosts a space, from a site that is not TinyCloud\'s own', () => {
  test('is refused for the primary space, hosted or not, in every spelling', async () => {
    for (const hosted of [null, { status: 'complete' }]) {
      row = hosted;
      expectRefused(await signIn(hostSiwe('default'), THIRD_PARTY));
      for (const { label, json } of escapedHostSpellings(`${spaceId('default')}/space`)) {
        const reply = await signIn(withRawRecap(hostSiwe('default'), json, `${spaceId('default')}/space`), THIRD_PARTY);
        // A ReCap the strict reader cannot read is refused before the host rule, as a malformed request.
        if (label === 'an unrelated key beside att') {
          expect(reply.status).toBe(400);
          expect(reply.body.signature).toBeUndefined();
          expect(signed).toEqual([]);
        } else expectRefused(reply);
      }
    }
  });

  test('is refused when the request names no site', async () => {
    row = { status: 'complete' };
    const reply = await signIn(hostSiwe('default'), undefined);
    expect(reply.status).toBeGreaterThanOrEqual(400);
    expect(reply.body.signature).toBeUndefined();
    expect(signed).toEqual([]);
  });

  test('is refused for a non-primary space while the primary space is not known to be hosted', async () => {
    for (const unknown of [null, { status: 'pending' }, { status: 'in_progress' }, { status: 'failed' }]) {
      row = unknown;
      expectRefused(await signIn(hostSiwe('public'), THIRD_PARTY));
    }
  });

  test('is refused when the targets mix the primary space with another', async () => {
    row = { status: 'complete' };
    const reply = await signIn(hostBoth('public', 'default'), THIRD_PARTY);
    expect(reply.body.signature).toBeUndefined();
    expect(signed).toEqual([]);
  });

  test('is signed for a non-primary space once the primary space is hosted', async () => {
    row = { status: 'complete' };
    const message = hostSiwe('public');
    const reply = await signIn(message, THIRD_PARTY);

    expect(reply.status).toBe(200);
    expect(reply.body.signedMessage).toBe(message);
    expect(reply.body.signature).toMatch(/^0x[0-9a-f]+$/i);
    expect(signed).toEqual([message]);
  });
});

describe('a sign-in that hosts a space, from a TinyCloud app', () => {
  test('is signed whatever it names and whether or not the account is set up', async () => {
    for (const name of ['default', 'public']) {
      const message = hostSiwe(name, FIRST_PARTY);
      const reply = await signIn(message, FIRST_PARTY);

      expect(reply.status).toBe(200);
      expect(reply.body.signedMessage).toBe(message);
    }
  });
});
