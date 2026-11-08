// The session JWK a caller sends is used, stored, and returned with only its
// public members, whatever else the caller includes.

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
  // Loaded after the module mocks, the routes under a file-specific query, per
  // the API test convention; the context store is the instance the route uses.
  ({ delegateRouter: router, setPreparedHandoffServiceForTests: setHandoffService } = await import(
    '../routes/delegate?session-jwk-public-members' as string
  ));
  ({ createPreparedHandoffRouter: handoffRouter } = await import('../routes/prepared-handoffs?session-jwk-public-members' as string));
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

// Accepted keys and the public members kept from each.
const accepted = [
  ['private members', sentJwk, publicMembers],
  ['private members nested in an unknown member', { ...publicMembers, extra: { d: exported.d, list: [{ d: exported.d }] } }, publicMembers],
  ['extra junk and a string kid', { ...publicMembers, kid: 'session-1', use: 'sig', alg: 7, junk: [null, { k: 'x' }] }, { ...publicMembers, kid: 'session-1' }],
] as const;

describe.each(accepted)('a session JWK with %s', (_name, sent, kept) => {
  test('/authorize-sign-prepare accepts it and stores only the public members', async () => {
    const res = await post('/authorize-sign-prepare', {
      keyId: keyRecord.id, siwe: widgetSiwe(), jwk: sent, host, requestOrigin: ORIGIN, reportedOrigin: ORIGIN,
    });
    expect(res.status, res.text).toBe(200);
    expect(storedJwk(res.body.authorizationContextToken)).toEqual(kept);
    expect(res.text).not.toContain(exported.d);
  });

  test('/prepare and /complete accept it, and store and return only the public members', async () => {
    const prepared = await post('/prepare', { keyId: keyRecord.id, jwk: sent, host });
    expect(prepared.status, prepared.text).toBe(200);
    expect(prepared.text).not.toContain(exported.d);
    expect(prepared.body.jwk).toEqual(kept);
    expect(prepared.body.prepared.jwk).toEqual(kept);
    expect(storedJwk(prepared.body.authorizationContext.token)).toEqual(kept);

    const completed = await post('/complete', {
      prepared: prepared.body.prepared,
      signature: await wallet.signMessage({ message: prepared.body.prepared.siwe }),
      host,
      jwk: sent,
      authorizationContextToken: prepared.body.authorizationContext.token,
      selectedActionIds: prepared.body.selectedActionKeys,
    });
    expect(completed.status, completed.text).toBe(200);
    expect(completed.text).not.toContain(exported.d);
    expect(completed.body.jwk).toEqual(kept);
  });

  test('managed POST / accepts it and returns only the public members', async () => {
    const res = await post('/', { keyId: keyRecord.id, jwk: sent, host });
    expect(res.status, res.text).toBe(200);
    expect(res.text).not.toContain(exported.d);
    expect(res.body.jwk).toEqual(kept);
  });
});

describe('a malformed session JWK counts as missing', () => {
  const malformed = [
    ['an array', [sentJwk]],
    ['an object-valued kid', { ...publicMembers, kid: { d: exported.d } }],
    ['private members nested in a kept member', { ...publicMembers, x: { x: exported.x, d: exported.d } }],
    ['an unknown kty', { kty: 'oct', k: exported.d }],
  ] as const;
  const missing = {
    '/': { error: 'keyId, jwk, and host are required' },
    '/prepare': { error: 'keyId, jwk, and host are required' },
    '/complete': { error: 'prepared, signature, host, and jwk are required' },
    '/authorize-sign-prepare': { error: 'keyId, siwe, and jwk are required', code: 'missing_authorize_sign_prepare_fields' },
  };
  test.each(Object.keys(missing).flatMap((route) => malformed.map(([name, jwk]) => [route, name, jwk] as const)))(
    '%s refuses %s with its missing-key error',
    async (route, _name, jwk) => {
      const res = await post(route, {
        keyId: keyRecord.id, siwe: widgetSiwe(), jwk, host, requestOrigin: ORIGIN, prepared: { siwe: 'x' }, signature: '0x',
      });
      expect(res.status).toBe(400);
      expect(res.body).toEqual(missing[route as keyof typeof missing]);
      expect(res.text).not.toContain(exported.d);
    },
  );
});

describe('an empty or false approvalRequestId', () => {
  test.each([null, false, ''])('%p is refused on managed POST / and never returns the key', async (approvalRequestId) => {
    const res = await post('/', { keyId: keyRecord.id, jwk: sentJwk, host, approvalRequestId });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'Approval requests require the consent preview context' });
    expect(res.text).not.toContain(exported.d);
  });

  // "" is a string id, so /prepare looks it up in the approval store; null and
  // false are refused without one.
  test.each([null, false])('%p is refused on /prepare and never returns the key', async (approvalRequestId) => {
    const prepared = await post('/prepare', { keyId: keyRecord.id, jwk: sentJwk, host, approvalRequestId });
    expect(prepared.status).toBe(410);
    expect(prepared.body.code).toBe('expired_request');
    expect(prepared.text).not.toContain(exported.d);
  });

  test.each([null, false, ''])('%p is refused on /complete and never returns the key', async (approvalRequestId) => {
    const ordinary = await post('/prepare', { keyId: keyRecord.id, jwk: publicMembers, host });
    expect(ordinary.status, ordinary.text).toBe(200);
    const completed = await post('/complete', {
      prepared: ordinary.body.prepared,
      signature: await wallet.signMessage({ message: ordinary.body.prepared.siwe }),
      host,
      jwk: sentJwk,
      approvalRequestId,
    });
    expect(completed.status).toBe(400);
    expect(completed.body).toEqual({ error: 'Approval requests require the consent preview context' });
    expect(completed.text).not.toContain(exported.d);
  });
});

describe('CLI prepared hand-off on /authorize-sign-prepare', () => {
  test('refuses a different key or host, accepts the same key with d and stores it public-only, and refuses a repeat', async () => {
    const service = new PreparedHandoffService(new MemoryPreparedHandoffStore());
    setHandoffService(service);
    const siwe = widgetSiwe();
    const ticket = Buffer.alloc(32, 60).toString('base64url');
    const claim = await handoffRouter(service).request('/claim', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        transportVersion: 2,
        request: { protocolVersion: 1, siwe, jwk: publicMembers, host, keyId: keyRecord.id, sessionDid: 'did:key:cli-session' },
        delivery: { handoffId: ticket, state: Buffer.alloc(32, 61).toString('base64url'), cancelSecret: Buffer.alloc(32, 62).toString('base64url') },
      }),
    });
    expect(claim.status, await claim.clone().text()).toBe(201);
    const prepare = (jwk: unknown, sentHost = host) => post('/authorize-sign-prepare', { ticket, keyId: keyRecord.id, siwe, jwk, host: sentHost });

    const otherX = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }).x;
    expect((await prepare({ ...publicMembers, x: otherX })).status).toBe(403);
    expect((await prepare(sentJwk, 'https://other-node.tinycloud.xyz')).status).toBe(403);

    const accepted = await prepare(sentJwk);
    expect(accepted.status, accepted.text).toBe(200);
    expect(storedJwk(accepted.body.authorizationContextToken)).toEqual(publicMembers);

    expect((await prepare(sentJwk)).status).toBe(409);
  });
});

describe('session JWK adoption log line', () => {
  const routes = [
    ['/', '/api/delegate'],
    ['/prepare', '/api/delegate/prepare'],
    ['/complete', '/api/delegate/complete'],
    ['/authorize-sign-prepare', '/api/delegate/authorize-sign-prepare'],
  ] as const;
  test.each(routes.flatMap(([path, route]) => [[path, route, true], [path, route, false]] as const))(
    '%s logs route %s and private_members=%s, and nothing about the key, user or request',
    async (path, route, withPrivate) => {
      const written: string[] = [];
      const write = process.stdout.write;
      process.stdout.write = ((chunk: string | Uint8Array) => {
        written.push(String(chunk));
        return true;
      }) as typeof process.stdout.write;
      await post(path, {
        keyId: keyRecord.id, siwe: widgetSiwe(), jwk: withPrivate ? sentJwk : publicMembers, host, requestOrigin: ORIGIN,
      }).finally(() => {
        process.stdout.write = write;
      });
      const output = written.join('');
      const lines = output.split('\n').filter(Boolean).map((line) => JSON.parse(line) as Record<string, unknown>);
      expect(lines.filter((line) => line.event === 'delegate_session_jwk')).toEqual([{
        ts: expect.any(String), level: 'info', event: 'delegate_session_jwk', request_id: expect.any(String),
        route, private_members: withPrivate,
      }]);
      for (const value of [exported.d, exported.x, user.id, user.email, keyRecord.id, address, host]) {
        expect(output).not.toContain(value);
      }
    },
  );
});

describe('prepared handoff record', () => {
  function claimBody(jwk: Record<string, unknown>) {
    const now = new Date();
    const siwe = prepareSession({
      address, chainId: 1, domain: 'cli.tinycloud.xyz', issuedAt: now.toISOString(),
      expirationTime: new Date(now.getTime() + 3_600_000).toISOString(), spaceId: SPACE, jwk: publicMembers,
      abilities: { kv: { [SPACE]: ['tinycloud.kv/get'] } } as never,
    }).siwe;
    const secret = (seed: number) => Buffer.alloc(32, seed).toString('base64url');
    return {
      transportVersion: 2,
      request: { protocolVersion: 1, siwe, jwk, host, sessionDid: 'did:key:cli-session' },
      delivery: { handoffId: secret(1), state: secret(2), cancelSecret: secret(3) },
    };
  }

  test('persists only the public members, and nothing for a key with private members', async () => {
    const store = new MemoryPreparedHandoffStore();
    const created: unknown[] = [];
    const createLimited = store.createLimited.bind(store);
    store.createLimited = async (record, since, limit) => {
      created.push(record.request);
      return createLimited(record, since, limit);
    };
    const service = new PreparedHandoffService(store);

    await expect(service.claim(claimBody(sentJwk), 'owner')).rejects.toMatchObject({ status: 400 });
    expect(created).toEqual([]);

    await service.claim(claimBody(publicMembers), 'owner');
    expect(created).toEqual([expect.objectContaining({ jwk: publicMembers })]);
  });
});
