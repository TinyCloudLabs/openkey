// POST /api/delegate/sign signs with no gesture, so a message that hosts a space needs a rule on every way in. These
// tests use the real signer-auth middleware and the real route: only the database, the TEE and the session are stand-ins.
//
//  - cookie session: admitted only from OpenKey's own browser origin; that origin is not first-party, so the
//    third-party rule of POST /api/keys/:id/sign applies (non-primary spaces of the owner, once the primary is hosted).
//  - OAuth tinycloud:manage-key token: the policy lets an `applications` host message through; the same rule applies
//    to the client, which is not TinyCloud's own.
//  - OAuth tinycloud:session token: the session policy signs only a kv ReCap, so a host message is refused there.

import { beforeEach, describe, expect, mock, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { generateHostSIWEMessage } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import { mockModules, replaceModules } from './mock-module';
import { escapedHostSpellings, withRawRecap } from './space-host-recap';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const user = { id: 'user_1', email: 'test@example.com' };
const PEER = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const OPENKEY_ORIGIN = 'http://localhost:5173';
const THIRD_PARTY = 'https://app.example.test';
const FIRST_PARTY = 'https://home.tinycloud.xyz';
const CLIENT_ID = 'third-party-client';
const rawBearer = 'opaque_OpenKey_token_123';
const spaceId = (name: string) => `tinycloud:pkh:eip155:1:${address}:${name}`;

const keyRecord = { id: 'key_1', userId: user.id, address, keyType: 'MANAGED', sealedBlob: 'sealed-private-key', archivedAt: null };
let row: { status: string } | null = null;
let signedMessages: string[] = [];
let token: Record<string, unknown>;
let client: Record<string, unknown>;

const prisma: Record<string, unknown> = {
  termsAcceptance: { findFirst: mock(async () => ({ id: 'terms_1' })) },
  oauthAccessToken: { findUnique: mock(async ({ where }: { where: { token: string } }) => (where.token === createHash('sha256').update(rawBearer).digest('base64url') ? token : null)) },
  oauthClient: { findUnique: mock(async () => client) },
  user: {
    findUnique: mock(async ({ select }: { select?: Record<string, boolean> }) => select?.autoSignEnabled
      ? { autoSignEnabled: true }
      : select?.tinyCloudManageKeyMode
        ? { tinyCloudManageKeyEnabled: true, tinyCloudManageKeyMode: 'APP_MANAGED', tinyCloudManageKeyPolicyEpoch: BigInt(0) }
        : { id: user.id, emailVerified: true }),
  },
  oauthConsent: { findFirst: mock(async () => ({ clientId: CLIENT_ID })) },
  tinyCloudManageKeyAppPreference: { findUnique: mock(async () => ({ enabled: true, status: 'ENABLED' })) },
  tinyCloudManageKeySigningDecision: { create: mock(async ({ data }: { data: unknown }) => data) },
  coordinationosSigningDecision: { create: mock(async ({ data }: { data: unknown }) => data) },
  ethereumKey: { findFirst: mock(async () => keyRecord), findUnique: mock(async () => keyRecord) },
  tinyCloudBootstrapState: { findUnique: mock(async () => row) },
  $queryRawUnsafe: mock(async () => []),
};
prisma.$transaction = mock(async (callback: (tx: unknown) => Promise<unknown>) => callback(prisma));

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
    unseal: mock(async () => privateKey),
    createWalletFromPrivateKey: (key: string) => {
      const wallet = privateKeyToAccount(key as `0x${string}`);
      return { ...wallet, signMessage: async (args: { message: string }) => { signedMessages.push(args.message); return wallet.signMessage(args); } };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost: mock(async () => ({ success: true })) }),
});

beforeEach(() => {
  row = null;
  signedMessages = [];
  token = {
    id: 'oauth_token_1', clientId: CLIENT_ID, userId: user.id, scopes: ['openid', 'keys', 'tinycloud:manage-key'],
    createdAt: new Date(), expiresAt: new Date(Date.now() + 240_000),
  };
  client = {
    clientId: CLIENT_ID, disabled: false, type: 'web', public: false, tokenEndpointAuthMethod: 'client_secret_basic',
    grantTypes: ['authorization_code'], responseTypes: ['code'], scopes: ['openid', 'keys', 'tinycloud:manage-key'],
    tinycloudSessionPolicy: null, tinycloudSessionOrigin: null,
  };
});

const hostSiwe = (name: string) => generateHostSIWEMessage({
  address, chainId: 1, domain: 'cli.tinycloud.xyz', issuedAt: new Date().toISOString(), spaceId: spaceId(name), peerId: PEER,
});
/** What a manage-key client sends: the policy also wants an expiry, which a host message may carry. */
const withExpiry = (message: string) => message.replace(/^(Issued At: .*)$/m, `$1\nExpiration Time: ${new Date(Date.now() + 600_000).toISOString()}`);
/** The same message naming both spaces (the statement is rewritten to what the recap parser checks). */
const hostBoth = (first: string, second: string) => {
  const att = { [`${spaceId(first)}/space`]: { 'tinycloud.space/host': [{}] }, [`${spaceId(second)}/space`]: { 'tinycloud.space/host': [{}] } };
  const lines = Object.keys(att).sort().map((resource, i) => `(${i + 1}) 'tinycloud.space': 'host' for '${resource}'.`);
  return hostSiwe(first)
    .replace(/I further authorize[^\n]*/, `I further authorize the stated URI to perform the following actions on my behalf: ${lines.join(' ')}`)
    .replace(/urn:recap:[A-Za-z0-9_-]+/, `urn:recap:${Buffer.from(JSON.stringify({ att, prf: [] })).toString('base64url')}`);
};
const asHex = (text: string) => `0x${Buffer.from(text, 'utf8').toString('hex')}`;

type SignBody = { approved?: boolean; signature?: string; code?: string; error?: string; reason?: string };
async function post(headers: Record<string, string>, body: Record<string, unknown>) {
  const { delegateRouter } = await import('../routes/delegate?delegate-sign-space-host' as string) as typeof import('../routes/delegate');
  const response = await delegateRouter.request('/sign', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: (await response.json()) as SignBody };
}
/** A cookie session from `origin`. */
const signAsSession = (message: string, origin: string) =>
  post({ origin }, { address, chainId: 1, message, type: 'siwe', keyId: keyRecord.id });
/** An OAuth bearer token (the manage-key one unless the test changed it). */
const signWithToken = (message: string) =>
  post({ authorization: `Bearer ${rawBearer}`, origin: THIRD_PARTY }, { address, chainId: 1, message, type: 'siwe', keyId: keyRecord.id });

function expectNoSignature(signed: { status: number; body: SignBody }) {
  // A refusal is a 4xx, or a 200 that asks for approval and carries no signature.
  expect(signed.status === 200 ? signed.body.approved : false).not.toBe(true);
  expect(signed.body.signature).toBeUndefined();
  expect(signedMessages).toEqual([]);
}
function expectRefusedByRule(signed: { status: number; body: SignBody }) {
  expect(signed.status).toBe(403);
  expect(signed.body).toMatchObject({ approved: false, code: 'host_signing_first_party_only' });
  expectNoSignature(signed);
}

describe('the cookie session, from OpenKey\'s own browser origin', () => {
  test('is signed for the primary space when it is hosted and refused when it is not, in every spelling and as hex', async () => {
    for (const hosted of [null, { status: 'complete' }]) {
      row = hosted;
      for (const { label, json } of escapedHostSpellings(`${spaceId('default')}/space`)) {
        signedMessages = [];
        const message = withRawRecap(hostSiwe('default'), json, `${spaceId('default')}/space`);
        if (hosted) {
          // The hex form is not signed on this route, so it gets no signature whichever way the host rule decides.
          expectNoSignature(await signAsSession(asHex(message), OPENKEY_ORIGIN));
          const plain = await signAsSession(message, OPENKEY_ORIGIN);
          expect([label, plain.status, plain.body.approved]).toEqual([label, 200, true]);
          expect(plain.body.signature).toMatch(/^0x[0-9a-f]+$/i);
          expect(signedMessages).toEqual([message]);
        } else {
          expectRefusedByRule(await signAsSession(message, OPENKEY_ORIGIN));
          expectNoSignature(await signAsSession(asHex(message), OPENKEY_ORIGIN));
        }
      }
    }
  });

  test('is refused for a non-primary space while the primary space is not known to be hosted', async () => {
    for (const unknown of [null, { status: 'pending' }, { status: 'in_progress' }, { status: 'failed' }]) {
      row = unknown;
      expectRefusedByRule(await signAsSession(hostSiwe('public'), OPENKEY_ORIGIN));
    }
  });

  test('is signed for a non-primary space once the primary space is hosted', async () => {
    row = { status: 'complete' };
    const message = hostSiwe('public');
    const signed = await signAsSession(message, OPENKEY_ORIGIN);

    expect(signed.status).toBe(200);
    expect(signed.body.approved).toBe(true);
    expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
    expect(signedMessages).toEqual([message]);
  });

  test('gets no signature when it names the primary space with another', async () => {
    row = { status: 'complete' };
    expectNoSignature(await signAsSession(hostBoth('public', 'default'), OPENKEY_ORIGIN));
  });
});

describe('the cookie session, from any other origin', () => {
  test('is refused by the signer middleware before the route reads the message, for a first-party origin too', async () => {
    row = { status: 'complete' };
    for (const origin of [THIRD_PARTY, FIRST_PARTY]) {
      const signed = await signAsSession(hostSiwe('public'), origin);

      expect(signed.status).toBe(403);
      expect(signed.body.error).toBe('Managed-key signing requires an OpenKey browser origin');
      expectNoSignature(signed);
    }
  });
});

describe('an OAuth tinycloud:manage-key token of a client that is not TinyCloud\'s own', () => {
  test('gets no signature for an `applications` host message while the primary space is not known to be hosted', async () => {
    for (const unknown of [null, { status: 'pending' }, { status: 'in_progress' }, { status: 'failed' }]) {
      row = unknown;
      const signed = await signWithToken(withExpiry(hostSiwe('applications')));

      expect(signed.status).toBe(403);
      expect(signed.body).toMatchObject({ approved: false, code: 'host_signing_first_party_only' });
      expectNoSignature(signed);
    }
  });

  test('is signed for an `applications` host message once the primary space is hosted', async () => {
    row = { status: 'complete' };
    const message = withExpiry(hostSiwe('applications'));
    const signed = await signWithToken(message);

    expect(signed.status).toBe(200);
    expect(signed.body.approved).toBe(true);
    expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
    expect(signedMessages).toEqual([message]);
  });

  test('gets no signature for an `applications` host message spelled with escapes while the primary space is not hosted', async () => {
    for (const { json } of escapedHostSpellings(`${spaceId('applications')}/space`)) {
      expectNoSignature(await signWithToken(withExpiry(withRawRecap(hostSiwe('applications'), json, `${spaceId('applications')}/space`))));
    }
  });

  test('is signed for the same escaped spellings once the primary space is hosted', async () => {
    row = { status: 'complete' };
    for (const { label, json } of escapedHostSpellings(`${spaceId('applications')}/space`)) {
      const signed = await signWithToken(withExpiry(withRawRecap(hostSiwe('applications'), json, `${spaceId('applications')}/space`)));
      expect([label, signed.status]).toEqual([label, 200]);
    }
  });

  test('gets no signature for the primary space, which its policy does not cover', async () => {
    row = { status: 'complete' };
    expectNoSignature(await signWithToken(withExpiry(hostSiwe('default'))));
  });

  test('gets no signature when the owner is another account', async () => {
    row = { status: 'complete' };
    const other = privateKeyToAccount('0x1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef').address;
    const message = withExpiry(hostSiwe('applications')).replaceAll(address, other);
    expectNoSignature(await signWithToken(message));
  });
});

describe('an OAuth tinycloud:session token (also a client that holds both scopes)', () => {
  test('gets no signature for a host message: the session policy signs only a kv ReCap', async () => {
    row = { status: 'complete' };
    token.scopes = ['openid', 'email', 'keys', 'tinycloud:session', 'tinycloud:manage-key'];
    client = { ...client, scopes: ['openid', 'email', 'keys', 'tinycloud:session', 'tinycloud:manage-key'], tinycloudSessionPolicy: 'coordinationos-kv-v1', tinycloudSessionOrigin: THIRD_PARTY };
    const signed = await post(
      { authorization: `Bearer ${rawBearer}`, origin: THIRD_PARTY },
      { address, chainId: 1, message: withExpiry(hostSiwe('applications')), type: 'siwe', purpose: 'sign-in', keyId: keyRecord.id },
    );
    expectNoSignature(signed);
  });
});
