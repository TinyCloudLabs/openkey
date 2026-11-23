// A prepared command-line handoff that asks for ONE exact app key: claim,
// /authorize-sign-prepare (the app's own file is fetched there), preview and
// sign.

import './tc1777-test-env';
import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { mockModules, replaceModules } from './mock-module';
import { MemoryPreparedHandoffStore, PreparedHandoffService } from '../services/prepared-handoff';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const address = privateKeyToAccount(privateKey).address;
const user = { id: 'user_1', email: 'alice@example.test' };
const OWNER = `did:pkh:eip155:1:${address}`;
const SPACE = `tinycloud:pkh:eip155:1:${address}:default`;
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;

const APP_ID = 'xyz.tinycloud.share';
const HOST = 'share.tinycloud.xyz';
const KEY = 'xyz.tinycloud.tinyapps.contacts/seal-v1';
const RESOURCE = urn(`/apps/${APP_ID}/${KEY}`);
const ABILITIES = ['tinycloud.encryption/decrypt', 'tinycloud.encryption/key.create'];
const DAY = 24 * 60 * 60 * 1000;

const sessionJwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });

type FileResult = { ok: true; bytes: Uint8Array } | { ok: false; kind: 'missing' | 'invalid' | 'unavailable' | 'busy'; reason: string };
const file = (body: unknown): FileResult => ({ ok: true, bytes: new TextEncoder().encode(typeof body === 'string' ? body : JSON.stringify(body)) });
const listing = (over: Record<string, unknown> = {}) => ({
  type: 'openkey-app-keys',
  app_id: APP_ID,
  keys: [{ path: `apps/${APP_ID}/${KEY}`, abilities: ['decrypt', 'key.create'] }],
  ...over,
});

let fileResult: FileResult = file(listing());
const fetchAppKeysFile = mock(async (_host: string): Promise<FileResult> => fileResult);
const fetchAndBindWellKnownManifest = mock(async () => ({ ok: false, reason: 'not used' }));
let signed: string[] = [];

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
    findFirst: mock(async ({ where }: { where: Record<string, unknown> }) => {
      if (where.userId !== user.id) return null;
      if (where.id !== undefined && where.id !== keyRecord.id) return null;
      if (where.archivedAt !== null) return null;
      return keyRecord;
    }),
    findMany: mock(async () => [keyRecord]),
    findUnique: mock(async () => keyRecord),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
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
      return {
        ...wallet,
        signMessage: async (args: { message: string }) => {
          signed.push(args.message);
          return wallet.signMessage(args);
        },
      };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost: mock(async () => ({ success: true })) }),
  '../services/manifest-origin-fetch': () => ({ fetchAppKeysFile, fetchAndBindWellKnownManifest }),
});

let router: typeof import('../routes/delegate')['delegateRouter'];
let createPreparedHandoffRouter: typeof import('../routes/prepared-handoffs')['createPreparedHandoffRouter'];
let setService: typeof import('../routes/delegate')['setPreparedHandoffServiceForTests'];
let resetContexts: typeof import('../services/authorization-signing')['_resetAuthorizationContextStoreForTests'];
let service: PreparedHandoffService;

beforeAll(async () => {
  const delegate = await import('../routes/delegate?app-key-handoff-routes' as string);
  router = delegate.delegateRouter;
  ({ createPreparedHandoffRouter } = await import('../routes/prepared-handoffs?app-key-claim-route' as string));
  setService = delegate.setPreparedHandoffServiceForTests;
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?app-key-handoff-routes' as string
  ));
});

let nonce = 0;
beforeEach(() => {
  signed = [];
  fileResult = file(listing());
  fetchAppKeysFile.mockClear();
  resetContexts?.();
  service = new PreparedHandoffService(new MemoryPreparedHandoffStore());
  setService(service);
});

function siweFor(raw: Record<string, string[]> = { [RESOURCE]: ABILITIES }, lifetimeMs = 7 * DAY - 60_000): string {
  const now = new Date();
  return prepareSession({
    address,
    chainId: 1,
    domain: 'cli.tinycloud.xyz',
    issuedAt: now.toISOString(),
    expirationTime: new Date(now.getTime() + lifetimeMs).toISOString(),
    spaceId: SPACE,
    jwk: sessionJwk,
    abilities: {} as never,
    rawAbilities: raw,
  } as never).siwe;
}

function post(path: string, body: unknown) {
  return router.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
}

function claimPayload(siwe: string, appKey: unknown = { appId: APP_ID, key: KEY }, omitAppKey = false) {
  nonce += 1;
  const delivery = {
    handoffId: Buffer.alloc(32, nonce).toString('base64url'),
    state: Buffer.alloc(32, nonce + 100).toString('base64url'),
    cancelSecret: Buffer.alloc(32, nonce + 200).toString('base64url'),
  };
  const request = { protocolVersion: 1, siwe, jwk: sessionJwk, host: 'https://node.tinycloud.xyz', sessionDid: 'did:key:session-cli', ...(omitAppKey ? {} : { appKey }) };
  return { transportVersion: 2, request, delivery };
}

/** Claim a handoff as the CLI's page would; returns the ticket and the request it claimed. */
async function claim(siwe: string, appKey?: unknown, omitAppKey = false) {
  const payload = claimPayload(siwe, appKey, omitAppKey);
  await service.claim(payload, user.id);
  return { ticket: payload.delivery.handoffId, siwe };
}

async function prepare(handoff: { ticket: string; siwe: string }, over: Record<string, unknown> = {}) {
  const res = await post('/authorize-sign-prepare', {
    keyId: keyRecord.id,
    siwe: handoff.siwe,
    jwk: sessionJwk,
    host: 'https://node.tinycloud.xyz',
    ticket: handoff.ticket,
    appKey: { appId: APP_ID, key: KEY },
    ...over,
  });
  return { res, body: await res.json() as Record<string, any> };
}

const expirationOf = (siwe: string) => Date.parse(/^Expiration Time: (.+)$/m.exec(siwe)![1]!);
const recapResources = (siwe: string) => {
  const token = /urn:recap:(\S+)/.exec(siwe)![1]!;
  return Object.keys((JSON.parse(Buffer.from(token, 'base64url').toString('utf8')) as { att: Record<string, unknown> }).att);
};

describe('an admitted command-line app key', () => {
  test('prepare fetches the app file, preview defaults to one hour, sign signs the request bytes', async () => {
    const handoff = await claim(siweFor());
    const { res, body } = await prepare(handoff);
    expect(res.status).toBe(200);
    expect(fetchAppKeysFile).toHaveBeenCalledTimes(1);
    expect(fetchAppKeysFile).toHaveBeenCalledWith(HOST);
    expect(body.appKey).toMatchObject({
      appId: APP_ID, host: HOST, key: KEY, resource: RESOURCE, abilities: ['decrypt', 'key.create'],
      requestedExpiresAt: new Date(expirationOf(handoff.siwe)).toISOString(),
      maxExpiresAt: new Date(expirationOf(handoff.siwe)).toISOString(),
    });
    expect(Date.parse(body.appKey.defaultExpiresAt) - Date.now()).toBeLessThanOrEqual(3_600_000);
    expect(Date.parse(body.appKey.defaultExpiresAt) - Date.now()).toBeGreaterThan(3_590_000);
    expect(body.metadataTrust.status).toBe('unsigned');

    const selected = body.allowedActionIds as string[];
    expect(selected).toHaveLength(2);
    const preview = await post('/authorize-sign-preview', { authorizationContextToken: body.authorizationContextToken, selectedActionIds: selected, ticket: handoff.ticket });
    expect(preview.status).toBe(200);
    const previewBody = await preview.json() as { signedMessage: string; previewApprovalToken: string };
    expect(expirationOf(previewBody.signedMessage) - Date.now()).toBeLessThanOrEqual(3_600_000);
    expect(expirationOf(previewBody.signedMessage) - Date.now()).toBeGreaterThan(3_590_000);
    expect(recapResources(previewBody.signedMessage)).toEqual([RESOURCE]);

    const sign = await post('/authorize-sign', {
      authorizationContextToken: body.authorizationContextToken, previewApprovalToken: previewBody.previewApprovalToken,
      selectedActionIds: selected, protocolVersion: 1, ticket: handoff.ticket,
    });
    expect(sign.status).toBe(200);
    const signBody = await sign.json() as { signedMessage: string };
    expect(signBody.signedMessage).toBe(previewBody.signedMessage);
    expect(signed).toEqual([previewBody.signedMessage]);
  });

  test('the owner may pick any later time up to the one the CLI asked for, and no later', async () => {
    const handoff = await claim(siweFor());
    const { body } = await prepare(handoff);
    const selected = body.allowedActionIds as string[];
    const chosen = new Date(Date.now() + 2 * DAY).toISOString();
    const ok = await post('/authorize-sign-preview', { authorizationContextToken: body.authorizationContextToken, selectedActionIds: selected, ticket: handoff.ticket, expirationTime: chosen });
    expect(ok.status).toBe(200);
    expect(expirationOf((await ok.json() as { signedMessage: string }).signedMessage)).toBe(Date.parse(chosen));
    const later = new Date(expirationOf(handoff.siwe) + 60_000).toISOString();
    const refused = await post('/authorize-sign-preview', { authorizationContextToken: body.authorizationContextToken, selectedActionIds: selected, ticket: handoff.ticket, expirationTime: later });
    expect(refused.status).toBe(400);
    await expect(refused.json()).resolves.toMatchObject({ code: 'expiry_exceeds_handoff' });
  });

  test('preview accepts the exact default end shown at prepare', async () => {
    const handoff = await claim(siweFor());
    const { body } = await prepare(handoff);
    const shownEnd = body.appKey.defaultExpiresAt as string;
    const preview = await post('/authorize-sign-preview', {
      authorizationContextToken: body.authorizationContextToken, selectedActionIds: body.allowedActionIds,
      ticket: handoff.ticket, expirationTime: shownEnd,
    });
    expect(preview.status).toBe(200);
    expect(expirationOf((await preview.json() as { signedMessage: string }).signedMessage)).toBe(Date.parse(shownEnd));
  });

  test('a request for less than an hour keeps its time', async () => {
    const handoff = await claim(siweFor(undefined, 20 * 60_000));
    const { body } = await prepare(handoff);
    expect(body.appKey.defaultExpiresAt).toBe(body.appKey.requestedExpiresAt);
    const preview = await post('/authorize-sign-preview', { authorizationContextToken: body.authorizationContextToken, selectedActionIds: body.allowedActionIds, ticket: handoff.ticket });
    expect(expirationOf((await preview.json() as { signedMessage: string }).signedMessage)).toBe(expirationOf(handoff.siwe));
  });

  test('taking only one of the two abilities is refused', async () => {
    const handoff = await claim(siweFor());
    const { body } = await prepare(handoff);
    const preview = await post('/authorize-sign-preview', {
      authorizationContextToken: body.authorizationContextToken, selectedActionIds: [(body.allowedActionIds as string[])[0]], ticket: handoff.ticket,
    });
    expect(preview.status).toBe(400);
    expect(signed).toEqual([]);
  });
});

describe('the request is bound to the claimed handoff', () => {
  test.each([
    ['a different key', { appKey: { appId: APP_ID, key: 'other/key' } }],
    ['a different app', { appKey: { appId: 'xyz.tinycloud.listen', key: KEY } }],
    ['no appKey', { appKey: undefined }],
  ])('prepare with %s is refused before anything is fetched', async (_name, over) => {
    const handoff = await claim(siweFor());
    const { res, body } = await prepare(handoff, over);
    expect(res.status).toBe(403);
    expect(body.code).toBe('binding_mismatch');
    expect(fetchAppKeysFile).not.toHaveBeenCalled();
    expect(body.authorizationContextToken).toBeUndefined();
  });

  test('an appKey the claim did not carry is refused', async () => {
    const handoff = await claim(siweFor({ [urn('/secrets/x')]: ABILITIES.slice(0, 1) }), undefined, true);
    const { res, body } = await prepare(handoff);
    expect(res.status).toBe(403);
    expect(body.code).toBe('binding_mismatch');
  });

  test('a SIWE other than the claimed one is refused', async () => {
    const handoff = await claim(siweFor());
    const other = siweFor({ [urn(`/apps/${APP_ID}/another`)]: ABILITIES });
    const { res, body } = await prepare({ ticket: handoff.ticket, siwe: other });
    expect(res.status).toBe(403);
    expect(body.code).toBe('binding_mismatch');
  });

  test('without a ticket an appKey never gets this mode', async () => {
    const res = await post('/authorize-sign-prepare', {
      keyId: keyRecord.id, siwe: siweFor(), jwk: sessionJwk, host: 'https://node.tinycloud.xyz', appKey: { appId: APP_ID, key: KEY },
      requestOrigin: `https://${HOST}`, reportedOrigin: `https://${HOST}`,
    });
    expect(res.status).toBe(400);
    await expect(res.json()).resolves.toMatchObject({ code: 'app_key_request_invalid', reason: 'ticket_required' });
    expect(fetchAppKeysFile).not.toHaveBeenCalled();
  });

  test('a browser sign-in for the same key without appKey keeps its own rules', async () => {
    const res = await post('/authorize-sign-prepare', {
      keyId: keyRecord.id, siwe: siweFor(), jwk: sessionJwk, host: 'https://node.tinycloud.xyz',
      requestOrigin: 'https://cli.tinycloud.xyz', reportedOrigin: 'https://cli.tinycloud.xyz',
    });
    expect(res.status).not.toBe(200);
    expect(fetchAppKeysFile).not.toHaveBeenCalled();
  });
});

const WORDS: Record<string, string> = {
  file_missing: "OpenKey can't approve this request: share.tinycloud.xyz doesn't list keys that command-line tools can ask for. Nothing was approved.",
  file_unavailable: "OpenKey couldn't check share.tinycloud.xyz's list of keys for command-line tools. Nothing was approved. Try again.",
  file_invalid: "OpenKey can't approve this request: share.tinycloud.xyz's list of keys for command-line tools can't be read. Nothing was approved.",
  file_app_mismatch: "OpenKey can't approve this request: share.tinycloud.xyz's list of keys for command-line tools can't be read. Nothing was approved.",
  key_not_listed: "OpenKey can't approve this request: share.tinycloud.xyz doesn't let command-line tools ask for the key seal-v1. Nothing was approved.",
};

describe('refusals at prepare', () => {
  test.each([
    ['no file', { ok: false, kind: 'missing', reason: 'fetch returned status 404' } as FileResult, 'app_keys_file_missing', 'file_missing'],
    ['a fetch that failed', { ok: false, kind: 'unavailable', reason: 'fetch threw' } as FileResult, 'app_keys_file_unavailable', 'file_unavailable'],
    ['text that is not JSON', file('<html>'), 'app_keys_file_invalid', 'file_invalid'],
    ['a file with no keys', file({ type: 'openkey-app-keys', app_id: APP_ID }), 'app_keys_file_invalid', 'file_invalid'],
    ['an unreadable keys block', file(listing({ keys: [{ path: `apps/${APP_ID}/${KEY}`, abilities: ['decrypt', 'key.create'], extra: 1 }] })), 'app_keys_file_invalid', 'file_invalid'],
    ['another app id', file(listing({ app_id: 'xyz.tinycloud.listen' })), 'app_keys_file_invalid', 'file_app_mismatch'],
    ['no app id', file({ type: 'openkey-app-keys', keys: listing().keys }), 'app_keys_file_invalid', 'file_invalid'],
    ['another key', file(listing({ keys: [{ path: `apps/${APP_ID}/other`, abilities: ['decrypt', 'key.create'] }] })), 'app_key_not_listed', 'key_not_listed'],
    ['a prefix that covers the key', file(listing({ keys: [{ prefix: `apps/${APP_ID}/`, abilities: ['decrypt', 'key.create'] }] })), 'app_key_not_listed', 'key_not_listed'],
    ['decrypt only', file(listing({ keys: [{ path: `apps/${APP_ID}/${KEY}`, abilities: ['decrypt'] }] })), 'app_key_not_listed', 'key_not_listed'],
  ])('%s: no context is issued', async (_name, result, code, reason) => {
    fileResult = result;
    const handoff = await claim(siweFor());
    const { res, body } = await prepare(handoff);
    expect(res.status).toBe(403);
    expect(body).toMatchObject({ code, reason });
    expect(body.error).toBe(WORDS[reason]!);
    expect(body.authorizationContextToken).toBeUndefined();
  });

  test('a failed fetch can be retried on the same handoff, and the file is fetched again', async () => {
    fileResult = { ok: false, kind: 'unavailable', reason: 'fetch threw' };
    const handoff = await claim(siweFor());
    expect((await prepare(handoff)).res.status).toBe(403);
    fileResult = file(listing());
    expect((await prepare(handoff)).res.status).toBe(200);
    expect(fetchAppKeysFile).toHaveBeenCalledTimes(2);
  });
});

test('claim returns the app-key refusal reason and owner message', async () => {
  const app = createPreparedHandoffRouter(service);
  const res = await app.request('/claim', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(claimPayload(siweFor({ [RESOURCE]: ['tinycloud.encryption/decrypt'] }))),
  });
  expect(res.status).toBe(403);
  expect(await res.json()).toEqual({
    code: 'app_key_request_invalid',
    reason: 'recap',
    error: 'This request asks for more than the one app key it names. Nothing was approved.',
  });
});

test('prepare answers 429 with the process capacity reason and owner message', async () => {
  fileResult = { ok: false, kind: 'busy', reason: 'DNS lookup capacity reached' };
  const { res, body } = await prepare(await claim(siweFor()));
  expect(res.status).toBe(429);
  expect(body).toEqual({
    code: 'app_key_fetch_busy',
    reason: 'process_capacity',
    error: "OpenKey is busy and couldn't check share.tinycloud.xyz's list of keys for command-line tools. Nothing was approved. Try again in a minute.",
  });
});
