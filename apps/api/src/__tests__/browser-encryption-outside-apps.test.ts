// A website's sign-in (no prepared-handoff ticket) may name encryption
// `decrypt` or `key.create` only under its own `apps/<app id>/`. Anything
// else, the pathless whole-network URN included, is refused at
// /authorize-sign-prepare, /authorize-sign-preview and /authorize-sign before
// a context is issued, a preview is approved or a key is unsealed.
//
// A preview or a signature needs a context. Prepare refuses these requests, so
// the preview and sign tests lift the new check while the context is issued
// (`allowEncryption`), restore it, and call the route under test.
//
// A request that carries a ticket (the CLI's `--keys <folder>` flow) is not
// touched: the last describe block runs it end to end.

import './tc1777-test-env';
import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { verifyMessage } from 'ethers';
import { mockModules, replaceModules } from './mock-module';
import { parseManifestKeys } from '../services/app-key-gate';
import { MemoryPreparedHandoffStore, PreparedHandoffService } from '../services/prepared-handoff';
import type { setPreparedHandoffServiceForTests } from '../routes/delegate';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const ORIGIN = 'https://evil.example';
const OWNER = `did:pkh:eip155:1:${address}`;
const SPACE = `tinycloud:pkh:eip155:1:${address}:default`;
const HOST = 'https://node.tinycloud.xyz';
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;
const E = 'tinycloud.encryption/';
const APP_ID = 'xyz.tinycloud.listen';

let signed: string[] = [];
let allowEncryption = false;
let manifestBindResult: { ok: boolean; manifest?: Record<string, unknown>; fetchedDigest?: string; reason?: string } = {
  ok: false,
  reason: 'not configured',
};
const fetchAndBindWellKnownManifest = mock(async () => manifestBindResult);
const unsealMock = mock(async () => privateKey);

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
    unseal: unsealMock,
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
  '../services/manifest-origin-fetch': () => ({ fetchAndBindWellKnownManifest }),
  // The check under test is lifted only while a context is minted for the
  // preview and sign tests. Before the check exists this export is missing and
  // those tests fail on the route's answer, not on this wrapper.
  '../services/app-key-refusal': (actual) => ({
    encryptionGrantsOutsideApps: (...args: unknown[]) =>
      allowEncryption ? [] : (actual.encryptionGrantsOutsideApps as (...a: unknown[]) => unknown)(...args),
  }),
});

let router: typeof import('../routes/delegate')['delegateRouter'];
let resetContexts: typeof import('../services/authorization-signing')['_resetAuthorizationContextStoreForTests'];
let setHandoffService: typeof setPreparedHandoffServiceForTests;
let createHandoffRouter: typeof import('../routes/prepared-handoffs')['createPreparedHandoffRouter'];

beforeAll(async () => {
  ({ delegateRouter: router, setPreparedHandoffServiceForTests: setHandoffService } = await import(
    '../routes/delegate?browser-encryption-outside-apps' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?browser-encryption-outside-apps' as string
  ));
  ({ createPreparedHandoffRouter: createHandoffRouter } = await import(
    '../routes/prepared-handoffs?browser-encryption-outside-apps' as string
  ));
});

beforeEach(() => {
  signed = [];
  allowEncryption = false;
  manifestBindResult = { ok: false, reason: 'not configured' };
  unsealMock.mockClear();
  fetchAndBindWellKnownManifest.mockClear();
  resetContexts?.();
});

function siweWith(rawAbilities: Record<string, string[]> = {}, domain = new URL(ORIGIN).host): string {
  const now = new Date();
  return prepareSession({
    address,
    chainId: 1,
    domain,
    issuedAt: now.toISOString(),
    expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
    spaceId: SPACE,
    jwk,
    abilities: { kv: { [SPACE]: ['tinycloud.kv/get', 'tinycloud.kv/put'] } } as never,
    ...(Object.keys(rawAbilities).length > 0 ? { rawAbilities } : {}),
  }).siwe;
}

function post(path: string, body: unknown) {
  return router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function prepareBody(siwe: string, origin = ORIGIN) {
  return { keyId: keyRecord.id, siwe, jwk, host: HOST, requestOrigin: origin, reportedOrigin: origin };
}

const NOT_DECLARED = "This website doesn't list the key this app asked for, so OpenKey didn't approve it.";
const REFUSED = { error: NOT_DECLARED, code: 'app_key_grant_refused' };

// Each request is one a third-party site could send with a single consent click.
const OUTSIDE_APPS: Array<[string, Record<string, string[]>]> = [
  ['decrypt on the share/ prefix', { [urn('/share/')]: [`${E}decrypt`] }],
  ['decrypt and key.create on a folder', { [urn('/qa/')]: [`${E}key.create`, `${E}decrypt`] }],
  ['decrypt on an exact key outside apps/', { [urn('/secrets/x')]: [`${E}decrypt`] }],
  ['decrypt on the whole network (no path)', { [urn('')]: [`${E}decrypt`] }],
  ['decrypt and network.create on the whole network', { [urn('')]: [`${E}decrypt`, `${E}network.create`] }],
  ['key.create on the whole network', { [urn('')]: [`${E}key.create`] }],
  ['the decrypt ability under a short service name', { [urn('/qa/')]: ['encryption/decrypt'] }],
];

// A refused row beside an `apps/` row: the context could never be issued, so only prepare sees it.
const MIXED_WITH_APPS = { [urn('/qa/')]: [`${E}decrypt`], [urn(`/apps/${APP_ID}/`)]: [`${E}decrypt`] };

describe('POST /authorize-sign-prepare without a ticket', () => {
  test.each(OUTSIDE_APPS)('refuses %s, issues nothing and unseals nothing', async (_name, raw) => {
    const res = await post('/authorize-sign-prepare', prepareBody(siweWith(raw)));
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toEqual(REFUSED);
    expect(unsealMock).not.toHaveBeenCalled();
    expect(signed).toEqual([]);
  });

  test('refuses a refused row that sits beside an apps/ row, even from a site that is the app', async () => {
    const origin = 'https://listen.tinycloud.xyz';
    manifestBindResult = { ok: true, fetchedDigest: 'a'.repeat(64), manifest: { name: 'Listen', appId: APP_ID, prefix: APP_ID } };
    const res = await post('/authorize-sign-prepare', prepareBody(siweWith(MIXED_WITH_APPS, new URL(origin).host), origin));
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toEqual(REFUSED);
    expect(unsealMock).not.toHaveBeenCalled();
  });

  test('still issues a context for whole-network network.create alone and for a message with no encryption rows', async () => {
    for (const raw of [{}, { [urn('')]: [`${E}network.create`] }]) {
      const res = await post('/authorize-sign-prepare', prepareBody(siweWith(raw)));
      expect(res.status).toBe(200);
      await expect(res.json()).resolves.toMatchObject({ authorizationContextToken: expect.stringMatching(/^oks_/) });
    }
  });
});

describe('POST /authorize-sign-preview and /authorize-sign without a ticket', () => {
  async function contextFor(raw: Record<string, string[]>) {
    allowEncryption = true;
    const prepared = await post('/authorize-sign-prepare', prepareBody(siweWith(raw)));
    expect(prepared.status).toBe(200);
    const { authorizationContextToken, allowedActionIds } = await prepared.json() as {
      authorizationContextToken: string;
      allowedActionIds: string[];
    };
    return { token: authorizationContextToken, allowed: allowedActionIds };
  }

  test.each(OUTSIDE_APPS)('preview refuses %s', async (_name, raw) => {
    const { token, allowed } = await contextFor(raw);
    allowEncryption = false;
    const res = await post('/authorize-sign-preview', { authorizationContextToken: token, selectedActionIds: allowed });
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toEqual(REFUSED);
    expect(unsealMock).not.toHaveBeenCalled();
  });

  test.each(OUTSIDE_APPS)('sign refuses %s before the context is used and before the key is unsealed', async (_name, raw) => {
    const { token, allowed } = await contextFor(raw);
    // The preview approval is obtained while the check is lifted.
    const preview = await post('/authorize-sign-preview', { authorizationContextToken: token, selectedActionIds: allowed });
    expect(preview.status).toBe(200);
    const { previewApprovalToken } = await preview.json() as { previewApprovalToken: string };

    allowEncryption = false;
    const body = { authorizationContextToken: token, previewApprovalToken, selectedActionIds: allowed, protocolVersion: 1 };
    const res = await post('/authorize-sign', body);
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toEqual(REFUSED);
    expect(unsealMock).not.toHaveBeenCalled();
    expect(signed).toEqual([]);

    // The refusal came before the context was consumed: with the check lifted
    // the same request signs.
    allowEncryption = true;
    const again = await post('/authorize-sign', body);
    expect(again.status).toBe(200);
    expect(signed.length).toBe(1);
  });
});

describe('a website under its own apps/<app id>/ prefix', () => {
  test('is still admitted, previewed and signed', async () => {
    const origin = 'https://listen.tinycloud.xyz';
    manifestBindResult = {
      ok: true,
      fetchedDigest: 'a'.repeat(64),
      manifest: {
        name: 'Listen',
        appId: APP_ID,
        prefix: APP_ID,
        declaredAppId: APP_ID,
        declaredKeys: parseManifestKeys(APP_ID, [{ prefix: `apps/${APP_ID}/`, abilities: ['key.create', 'decrypt'] }]),
      },
    };
    const siwe = siweWith({ [urn(`/apps/${APP_ID}/`)]: [`${E}key.create`, `${E}decrypt`] }, new URL(origin).host);
    const prepared = await post('/authorize-sign-prepare', {
      ...prepareBody(siwe, origin),
      presentation: { manifestDigest: 'a'.repeat(64), displayName: 'Listen' },
    });
    expect(prepared.status, await prepared.clone().text()).toBe(200);
    const { authorizationContextToken, allowedActionIds } = await prepared.json() as {
      authorizationContextToken: string;
      allowedActionIds: string[];
    };
    const preview = await post('/authorize-sign-preview', { authorizationContextToken, selectedActionIds: allowedActionIds });
    expect(preview.status, await preview.clone().text()).toBe(200);
    const { previewApprovalToken } = await preview.json() as { previewApprovalToken: string };
    const res = await post('/authorize-sign', {
      authorizationContextToken, previewApprovalToken, selectedActionIds: allowedActionIds, protocolVersion: 1,
    });
    expect(res.status, await res.clone().text()).toBe(200);
    expect(signed.length).toBe(1);
  });
});

describe('a prepared-handoff ticket (CLI --keys <folder>) is unchanged', () => {
  const bare = urn('');
  const folder = urn('/qa/');
  const rawAbilities = {
    [bare]: [`${E}decrypt`, `${E}network.create`],
    [folder]: [`${E}key.create`, `${E}decrypt`],
  };

  async function claim(siwe: string, seed: number): Promise<string> {
    const service = new PreparedHandoffService(new MemoryPreparedHandoffStore());
    setHandoffService(service);
    const ticket = Buffer.alloc(32, seed).toString('base64url');
    const res = await createHandoffRouter(service).request('/claim', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        transportVersion: 2,
        request: { protocolVersion: 1, siwe, jwk, host: HOST, keyId: keyRecord.id, sessionDid: 'did:key:cli-session' },
        delivery: {
          handoffId: ticket,
          state: Buffer.alloc(32, seed + 1).toString('base64url'),
          cancelSecret: Buffer.alloc(32, seed + 2).toString('base64url'),
        },
      }),
    });
    expect(res.status, await res.clone().text()).toBe(201);
    return ticket;
  }

  test.each([
    ['the default whole-network pair plus the folder row', rawAbilities],
    ['whole-network decrypt alone', { [bare]: [`${E}decrypt`] }],
    ['the folder row alone', { [folder]: [`${E}key.create`, `${E}decrypt`] }],
  ])('prepares, previews and signs %s', async (_name, raw) => {
    const siwe = siweWith(raw, 'cli.tinycloud.xyz');
    const ticket = await claim(siwe, 20);
    const prepared = await post('/authorize-sign-prepare', { ticket, keyId: keyRecord.id, siwe, jwk, host: HOST });
    expect(prepared.status, await prepared.clone().text()).toBe(200);
    const { authorizationContextToken, allowedActionIds } = await prepared.json() as {
      authorizationContextToken: string;
      allowedActionIds: string[];
    };
    const preview = await post('/authorize-sign-preview', { ticket, authorizationContextToken, selectedActionIds: allowedActionIds });
    expect(preview.status, await preview.clone().text()).toBe(200);
    const { previewApprovalToken } = await preview.json() as { previewApprovalToken: string };
    const res = await post('/authorize-sign', {
      ticket, authorizationContextToken, previewApprovalToken, selectedActionIds: allowedActionIds, protocolVersion: 1,
    });
    expect(res.status, await res.clone().text()).toBe(200);
    const result = await res.json() as { signedMessage: string; signature: string };
    expect(verifyMessage(result.signedMessage, result.signature)).toBe(address);
    expect(signed.length).toBe(1);
  });
});
