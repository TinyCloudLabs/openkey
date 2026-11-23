// POST /api/delegate/sign (Auto-Sign) signs with no gesture, so a space host message needs the same rule as
// POST /api/keys/:id/sign: TinyCloud's own apps are signed for; any other site only for its own non-primary spaces,
// and only once the owner's primary space is known to be hosted (a stored bootstrap row that is complete).
//
// A cookie session reaches /sign only from OpenKey's own browser origin (`rejectNonOpenKeySignRequest`), so a site's
// Origin never gets this far; the tests below stand in for a signer-auth that lets the Origin through, to show the rule
// holds on its own. The one test with the real middleware shows the Origin check itself.

import { afterEach, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { generateHostSIWEMessage } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import { mockModules, replaceModules } from './mock-module';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const user = { id: 'user_1', email: 'test@example.com' };
const PEER = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const THIRD_PARTY = 'https://app.example.test';
const FIRST_PARTY = 'https://home.tinycloud.xyz';
const spaceId = (name: string) => `tinycloud:pkh:eip155:1:${address}:${name}`;

const keyRecord = { id: 'key_1', userId: user.id, address, keyType: 'MANAGED', sealedBlob: 'sealed-private-key', archivedAt: null };
let row: { status: string } | null = null;
let signedMessages: string[] = [];
const prisma = {
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  ethereumKey: { findFirst: mock(async () => keyRecord) },
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

async function delegateRoutes() {
  return await import('../routes/delegate?delegate-sign-space-host' as string) as typeof import('../routes/delegate');
}

/** A signer-auth that accepts the cookie session whatever the Origin is, as the route would if that check were absent. */
const sessionWhateverTheOrigin = createMiddleware(async (c, next) => {
  c.set('user', user);
  c.set('delegateSignerPrincipal', { kind: 'session', userId: user.id });
  c.set('delegateSignerOauthContext', null);
  c.set('delegateSignerAuthFailure', null);
  await next();
});

beforeEach(async () => {
  row = null;
  signedMessages = [];
  (await delegateRoutes()).setDelegateSignerAuthMiddlewareForTests(sessionWhateverTheOrigin);
});

afterEach(async () => {
  (await delegateRoutes()).setDelegateSignerAuthMiddlewareForTests();
});

const hostSiwe = (name: string) => generateHostSIWEMessage({
  address, chainId: 1, domain: 'cli.tinycloud.xyz', issuedAt: new Date().toISOString(), spaceId: spaceId(name), peerId: PEER,
});
/** The same message naming both spaces (the statement is rewritten to what the recap parser checks). */
const hostBoth = (first: string, second: string) => {
  const att = { [`${spaceId(first)}/space`]: { 'tinycloud.space/host': [{}] }, [`${spaceId(second)}/space`]: { 'tinycloud.space/host': [{}] } };
  const lines = Object.keys(att).sort().map((resource, i) => `(${i + 1}) 'tinycloud.space': 'host' for '${resource}'.`);
  return hostSiwe(first)
    .replace(/I further authorize[^\n]*/, `I further authorize the stated URI to perform the following actions on my behalf: ${lines.join(' ')}`)
    .replace(/urn:recap:[A-Za-z0-9_-]+/, `urn:recap:${Buffer.from(JSON.stringify({ att, prf: [] })).toString('base64url')}`);
};

async function sign(message: string, origin: string) {
  const { delegateRouter } = await delegateRoutes();
  const response = await delegateRouter.request('/sign', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin },
    body: JSON.stringify({ address, chainId: 1, message, type: 'siwe', keyId: keyRecord.id }),
  });
  return { status: response.status, body: (await response.json()) as { approved?: boolean; signature?: string; code?: string } };
}

describe('a space host message sent to Auto-Sign by an app of another site', () => {
  test('is refused for the primary space, whether or not it is hosted', async () => {
    for (const hosted of [null, { status: 'complete' }]) {
      row = hosted;
      const signed = await sign(hostSiwe('default'), THIRD_PARTY);

      expect(signed.status).toBe(403);
      expect(signed.body).toMatchObject({ approved: false, code: 'host_signing_first_party_only' });
      expect(signed.body.signature).toBeUndefined();
    }
    expect(signedMessages).toEqual([]);
  });

  test('is refused for a non-primary space while the primary space is not known to be hosted', async () => {
    for (const unknown of [null, { status: 'pending' }, { status: 'in_progress' }, { status: 'failed' }]) {
      row = unknown;
      const signed = await sign(hostSiwe('public'), THIRD_PARTY);

      expect(signed.status).toBe(403);
      expect(signed.body).toMatchObject({ approved: false, code: 'host_signing_first_party_only' });
    }
    expect(signedMessages).toEqual([]);
  });

  test('is signed for a non-primary space once the primary space is hosted', async () => {
    row = { status: 'complete' };
    const message = hostSiwe('public');
    const signed = await sign(message, THIRD_PARTY);

    expect(signed.status).toBe(200);
    expect(signed.body.approved).toBe(true);
    expect(signed.body.signature).toMatch(/^0x[0-9a-f]+$/i);
    expect(signedMessages).toEqual([message]);
  });

  test('gets no signature when it names the primary space with another', async () => {
    row = { status: 'complete' };
    const signed = await sign(hostBoth('public', 'default'), THIRD_PARTY);

    expect(signed.body.approved).not.toBe(true);
    expect(signed.body.signature).toBeUndefined();
    expect(signedMessages).toEqual([]);
  });

  test('is signed for a TinyCloud app, whatever it names and whether or not the account is set up', async () => {
    for (const name of ['default', 'public']) {
      const message = hostSiwe(name);
      const signed = await sign(message, FIRST_PARTY);

      expect(signed.status).toBe(200);
      expect(signed.body.approved).toBe(true);
      expect(signedMessages.at(-1)).toBe(message);
    }
  });
});

describe('the cookie session on /sign', () => {
  test('never reaches the signer from the Origin of another site', async () => {
    (await delegateRoutes()).setDelegateSignerAuthMiddlewareForTests();
    row = { status: 'complete' };
    const signed = await sign(hostSiwe('public'), THIRD_PARTY);

    expect(signed.status).toBe(403);
    expect(signed.body.signature).toBeUndefined();
    expect(signedMessages).toEqual([]);
  });
});
