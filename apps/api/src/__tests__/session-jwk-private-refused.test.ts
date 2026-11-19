// A session JWK that includes any private member is refused on every delegate
// route, before any lookup or storage, without repeating the key.

import './tc1777-test-env';
import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { mockModules, replaceModules } from './mock-module';
import type { delegateRouter, setPreparedHandoffServiceForTests } from '../routes/delegate';
import type { createPreparedHandoffRouter } from '../routes/prepared-handoffs';
import type * as AuthorizationSigning from '../services/authorization-signing';
import { MemoryPreparedHandoffStore, PreparedHandoffService } from '../services/prepared-handoff';

const walletKey = '0x1111111111111111111111111111111111111111111111111111111111111111';
const wallet = privateKeyToAccount(walletKey);
const address = wallet.address;
const user = { id: 'user_1', email: 'alice@example.test' };
const host = 'https://node.tinycloud.xyz';
const ORIGIN = 'https://listen.tinycloud.xyz';
const SPACE = `tinycloud:pkh:eip155:1:${address}:default`;

const exported = generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }) as Record<string, string>;
const publicMembers = { kty: 'OKP', crv: 'Ed25519', x: exported.x };
// What a WebCrypto export of the session's private key carries.
const sentJwk = { ...publicMembers, d: exported.d, ext: true, key_ops: ['sign'] };

const keyRecord = {
  id: 'key_1',
  userId: user.id,
  address,
  keyType: 'MANAGED',
  archivedAt: null,
  sealedBlob: 'sealed-blob',
  sealingContext: null,
};

const prisma = {
  ethereumKey: {
    findFirst: mock(async () => keyRecord),
    findMany: mock(async () => [keyRecord]),
    findUnique: mock(async () => keyRecord),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
  appSignInDay: {
    upsert: mock(async () => null),
    deleteMany: mock(async () => null),
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
    unseal: mock(async () => walletKey),
    createWalletFromPrivateKey: (key: string) => privateKeyToAccount(key as `0x${string}`),
    generatePrivateKey: () => walletKey,
    getAddressFromPrivateKey: () => address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost: mock(async () => ({ success: true })) }),
  '../services/manifest-origin-fetch': () => ({
    fetchAndBindWellKnownManifest: mock(async () => ({ ok: false, reason: 'not fetched in this test' })),
  }),
});

let router: typeof delegateRouter;
let setHandoffService: typeof setPreparedHandoffServiceForTests;
let handoffRouter: typeof createPreparedHandoffRouter;
let auth: typeof AuthorizationSigning;

beforeAll(async () => {
  // Loaded after the module mocks, under a file-specific query, per the API
  // test convention (CLAUDE.md, TC-928); a static import would load the real modules.
  ({ delegateRouter: router, setPreparedHandoffServiceForTests: setHandoffService } = await import(
    '../routes/delegate?session-jwk-private-refused' as string
  ));
  ({ createPreparedHandoffRouter: handoffRouter } = await import('../routes/prepared-handoffs?session-jwk-private-refused' as string));
  auth = await import('../services/authorization-signing');
});

beforeEach(() => auth._resetAuthorizationContextStoreForTests());

async function post(path: string, body: Record<string, unknown>) {
  const res = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, text, body: JSON.parse(text) as Record<string, any> };
}

function storedJwk(token: string): unknown {
  const peek = auth.peekAuthorizationContext(token);
  if (!peek.ok) throw new Error(peek.error);
  return peek.value.jwk;
}

function widgetSiwe(): string {
  const now = new Date();
  return prepareSession({
    address,
    chainId: 1,
    domain: 'listen.tinycloud.xyz',
    uri: ORIGIN,
    issuedAt: now.toISOString(),
    expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
    spaceId: SPACE,
    jwk: publicMembers,
    abilities: { kv: { [SPACE]: ['tinycloud.kv/get'] } } as never,
  } as never).siwe;
}

const PRIVATE_JWK_REFUSED = { error: 'jwk must contain only public key members', code: 'private_jwk_refused' };

describe('a session JWK with a private member', () => {
  const routes = ['/', '/prepare', '/complete', '/authorize-sign-prepare'];
  const members = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'];
  test.each(routes.flatMap((route) => members.map((member) => [route, member])))(
    '%s refuses one with `%s`, without repeating, logging, or storing it',
    async (route, member) => {
      const secret = `private-${member}-${exported.d}`;
      const written: string[] = [];
      const write = process.stdout.write;
      process.stdout.write = ((chunk: string | Uint8Array) => {
        written.push(String(chunk));
        return true;
      }) as typeof process.stdout.write;
      prisma.ethereumKey.findFirst.mockClear();
      const res = await post(route!, {
        keyId: keyRecord.id, siwe: widgetSiwe(), jwk: { ...publicMembers, [member!]: secret }, host,
        prepared: { siwe: 'x' }, signature: '0x', requestOrigin: ORIGIN,
      }).finally(() => {
        process.stdout.write = write;
      });
      expect(res.status).toBe(400);
      expect(res.body).toEqual(PRIVATE_JWK_REFUSED);
      expect(written.join('')).not.toContain(secret);
      expect(prisma.ethereumKey.findFirst).not.toHaveBeenCalled();
    },
  );
});

describe('a WebCrypto private-key export with an approvalRequestId', () => {
  test.each([
    ['/', null], ['/', false], ['/', ''], ['/', 'approval_1'],
    ['/prepare', null], ['/prepare', false], ['/prepare', ''], ['/prepare', 'approval_1'],
  ] as const)('%s refuses it with approvalRequestId %p', async (route, approvalRequestId) => {
    const res = await post(route, { keyId: keyRecord.id, jwk: sentJwk, host, approvalRequestId });
    expect(res.status).toBe(400);
    expect(res.body).toEqual(PRIVATE_JWK_REFUSED);
    expect(res.text).not.toContain(exported.d);
  });
});

describe('the public members of the same key', () => {
  test('are still accepted on /prepare and /complete', async () => {
    const prepared = await post('/prepare', { keyId: keyRecord.id, jwk: { ...publicMembers, ext: true, key_ops: ['verify'] }, host });
    expect(prepared.status, prepared.text).toBe(200);
    expect(prepared.body.jwk).toEqual(publicMembers);
    const completed = await post('/complete', {
      prepared: prepared.body.prepared,
      signature: await wallet.signMessage({ message: prepared.body.prepared.siwe }),
      host,
      jwk: publicMembers,
      authorizationContextToken: prepared.body.authorizationContext.token,
      selectedActionIds: prepared.body.selectedActionKeys,
    });
    expect(completed.status, completed.text).toBe(200);
    expect(completed.body.jwk).toEqual(publicMembers);
  });
});

describe('CLI prepared hand-off on /authorize-sign-prepare', () => {
  test('refuses the key with d without consuming the hand-off, then accepts the public key once', async () => {
    const service = new PreparedHandoffService(new MemoryPreparedHandoffStore());
    setHandoffService(service);
    const siwe = widgetSiwe();
    const ticket = Buffer.alloc(32, 70).toString('base64url');
    const claim = await handoffRouter(service).request('/claim', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        transportVersion: 2,
        request: { protocolVersion: 1, siwe, jwk: publicMembers, host, keyId: keyRecord.id, sessionDid: 'did:key:cli-session' },
        delivery: { handoffId: ticket, state: Buffer.alloc(32, 71).toString('base64url'), cancelSecret: Buffer.alloc(32, 72).toString('base64url') },
      }),
    });
    expect(claim.status, await claim.clone().text()).toBe(201);
    const prepare = (jwk: unknown) => post('/authorize-sign-prepare', { ticket, keyId: keyRecord.id, siwe, jwk, host });

    const withPrivate = await prepare(sentJwk);
    expect(withPrivate.status).toBe(400);
    expect(withPrivate.body).toEqual(PRIVATE_JWK_REFUSED);
    expect(withPrivate.text).not.toContain(exported.d);

    const accepted = await prepare(publicMembers);
    expect(accepted.status, accepted.text).toBe(200);
    expect(storedJwk(accepted.body.authorizationContextToken)).toEqual(publicMembers);
    expect((await prepare(publicMembers)).status).toBe(409);
  });
});
