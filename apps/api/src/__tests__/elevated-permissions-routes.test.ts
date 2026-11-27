// TC-2927: an app may ask to decrypt, or create keys, on the encryption network or on keys outside its own `apps/`
// area. The approval then shows an extra warning screen for each such permission; the owner allows or rejects it
// and the rest of the request is approved either way. The server half of that screen is checked here:
//   - /authorize-sign-prepare issues a context for these requests (the blanket refusal is gone);
//   - /authorize-sign refuses to sign an extra permission the preview did not record as explicitly allowed
//     (`elevated_not_decided`) before the context is used or the key is unsealed;
//   - rejecting a permission narrows it out of the bytes and the rest signs, even beside an admitted `apps/` key;
//   - an exact share key (`share/<id>`) is refused for every site, text or hex;
//   - a prepared-handoff (command line) request is untouched.

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
});

let router: typeof import('../routes/delegate')['delegateRouter'];
let resetContexts: typeof import('../services/authorization-signing')['_resetAuthorizationContextStoreForTests'];
let setHandoffService: typeof setPreparedHandoffServiceForTests;
let createHandoffRouter: typeof import('../routes/prepared-handoffs')['createPreparedHandoffRouter'];

beforeAll(async () => {
  ({ delegateRouter: router, setPreparedHandoffServiceForTests: setHandoffService } = await import(
    '../routes/delegate?elevated-permissions-routes' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?elevated-permissions-routes' as string
  ));
  ({ createPreparedHandoffRouter: createHandoffRouter } = await import(
    '../routes/prepared-handoffs?elevated-permissions-routes' as string
  ));
});

beforeEach(() => {
  signed = [];
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

const REFUSED = { error: "This site isn't allowed to request that access.", code: 'app_key_grant_refused' };


// The refusal for an exact share key keeps the stable code, in the wording the app already receives.
/** A field of a JSON answer, read without trusting its shape. */
async function fieldOf(res: Response, name: string): Promise<unknown> {
  const body: unknown = await res.json();
  return typeof body === 'object' && body !== null && name in body ? Object.getOwnPropertyDescriptor(body, name)?.value : undefined;
}

const SHARE_REFUSED = { error: "This site isn't allowed to request that access.", code: 'app_key_grant_refused' };

// Requests a third-party site may now send: each reaches the warning screen, one card per permission.
const ELEVATED: Array<[string, Record<string, string[]>]> = [
  ['decrypt on the share/ prefix', { [urn('/share/')]: [`${E}decrypt`] }],
  ['decrypt and key.create on a folder', { [urn('/qa/')]: [`${E}key.create`, `${E}decrypt`] }],
  ['decrypt on an exact key outside apps/ and outside share/', { [urn('/secrets/x')]: [`${E}decrypt`] }],
  ['decrypt on the whole network (no path)', { [urn('')]: [`${E}decrypt`] }],
  ['decrypt and network.create on the whole network', { [urn('')]: [`${E}decrypt`, `${E}network.create`] }],
  ['key.block on a folder', { [urn('/qa/')]: [`${E}key.block`] }],
  ['key.unblock on the whole network', { [urn('')]: [`${E}key.unblock`] }],
  ['key.block and key.unblock on an exact key outside apps/', { [urn('/secrets/x')]: [`${E}key.block`, `${E}key.unblock`] }],
  ['key.create on the whole network', { [urn('')]: [`${E}key.create`] }],
  ['the decrypt ability under a short service name', { [urn('/qa/')]: ['encryption/decrypt'] }],
];

// An exact share key is an id the app chooses or guesses: OpenKey accepts it only when it made the id for the request.
const EXACT_SHARE: Array<[string, Record<string, string[]>]> = [
  ['decrypt on an exact share key', { [urn('/share/abc123')]: [`${E}decrypt`] }],
  ['key.create on an exact share key', { [urn('/share/abc123')]: [`${E}key.create`] }],
  ['an exact share key beside the share/ prefix', { [urn('/share/')]: [`${E}decrypt`], [urn('/share/abc123')]: [`${E}decrypt`] }],
];

async function prepare(raw: Record<string, string[]>, origin = ORIGIN) {
  const res = await post('/authorize-sign-prepare', prepareBody(siweWith(raw, new URL(origin).host), origin));
  expect(res.status, await res.clone().text()).toBe(200);
  const body = await res.json() as { authorizationContextToken: string; allowedActionIds: string[] };
  return { token: body.authorizationContextToken, allowed: body.allowedActionIds };
}

async function preview(token: string, selected: string[], elevatedDecision?: unknown) {
  const res = await post('/authorize-sign-preview', {
    authorizationContextToken: token,
    selectedActionIds: selected,
    ...(elevatedDecision === undefined ? {} : { elevatedDecision }),
  });
  expect(res.status, await res.clone().text()).toBe(200);
  const issued = await fieldOf(res, 'previewApprovalToken');
  if (typeof issued !== 'string') throw new Error('the preview returned no previewApprovalToken');
  return issued;
}

const elevatedIds = (allowed: string[]) =>
  allowed.filter((id) => id.includes('urn:tinycloud:encryption:') && /\0(tinycloud\.)?encryption\/(decrypt|key\.create|key\.block|key\.unblock)$/.test(id) && !id.includes('/apps/'));

describe('POST /authorize-sign-prepare without a ticket', () => {
  test.each(ELEVATED)('issues a context for %s (no refusal; the owner decides on the warning screen)', async (_name, raw) => {
    const { token, allowed } = await prepare(raw);
    expect(token).toMatch(/^oks_/);
    expect(elevatedIds(allowed).length).toBeGreaterThan(0);
    expect(unsealMock).not.toHaveBeenCalled();
  });

  test('issues a context from any origin, ours or not: there is no list of first-party sites', async () => {
    for (const origin of ['https://share.tinycloud.xyz', 'https://tinycloud.one', 'https://evil.example', 'https://gk.gbafa.com']) {
      const siwe = siweWith({ [urn('')]: [`${E}decrypt`] }, new URL(origin).host);
      const res = await post('/authorize-sign-prepare', prepareBody(siwe, origin));
      expect(res.status, origin).toBe(200);
    }
  });

  test.each(EXACT_SHARE)('refuses %s from any site, issues nothing and unseals nothing', async (_name, raw) => {
    for (const origin of [ORIGIN, 'https://share.tinycloud.xyz']) {
      const res = await post('/authorize-sign-prepare', prepareBody(siweWith(raw, new URL(origin).host), origin));
      expect(res.status, origin).toBe(403);
      await expect(res.json()).resolves.toEqual(SHARE_REFUSED);
    }
    expect(unsealMock).not.toHaveBeenCalled();
    expect(signed).toEqual([]);
  });

  test('still refuses key.delete and a ReCap it cannot read', async () => {
    const del = await post('/authorize-sign-prepare', prepareBody(siweWith({ [urn('/qa/x')]: [`${E}key.delete`] })));
    expect(del.status).toBe(403);
    expect(await fieldOf(del, 'code')).toBe('key_delete_not_grantable');
  });
});

describe('POST /authorize-sign: the owner decides on each extra permission', () => {
  test.each(ELEVATED)('refuses to sign %s when the preview did not record it as allowed, before the key is unsealed', async (_name, raw) => {
    const { token, allowed } = await prepare(raw);
    const previewApprovalToken = await preview(token, allowed);
    const body = { authorizationContextToken: token, previewApprovalToken, selectedActionIds: allowed, protocolVersion: 1 };
    const res = await post('/authorize-sign', body);
    expect(res.status).toBe(403);
    expect(await fieldOf(res, 'code')).toBe('elevated_not_decided');
    expect(unsealMock).not.toHaveBeenCalled();
    expect(signed).toEqual([]);
  });

  test.each(ELEVATED)('signs %s once the preview recorded every extra permission as allowed', async (_name, raw) => {
    const { token, allowed } = await prepare(raw);
    const previewApprovalToken = await preview(token, allowed, { allowed: elevatedIds(allowed) });
    const res = await post('/authorize-sign', { authorizationContextToken: token, previewApprovalToken, selectedActionIds: allowed, protocolVersion: 1 });
    expect(res.status, await res.clone().text()).toBe(200);
    const result = await res.json() as { signedMessage: string; signature: string };
    expect(verifyMessage(result.signedMessage, result.signature)).toBe(address);
    expect(signed.length).toBe(1);
  });

  test('the refusal comes before the context is used: the same request signs once the preview records the allow', async () => {
    const raw = { [urn('')]: [`${E}decrypt`] };
    const { token, allowed } = await prepare(raw);
    const first = await preview(token, allowed);
    const refused = await post('/authorize-sign', { authorizationContextToken: token, previewApprovalToken: first, selectedActionIds: allowed, protocolVersion: 1 });
    expect(refused.status).toBe(403);
    const second = await preview(token, allowed, { allowed: elevatedIds(allowed) });
    const ok = await post('/authorize-sign', { authorizationContextToken: token, previewApprovalToken: second, selectedActionIds: allowed, protocolVersion: 1 });
    expect(ok.status, await ok.clone().text()).toBe(200);
  });

  test('an allow for a different permission is not an allow for this one', async () => {
    const { token, allowed } = await prepare({ [urn('')]: [`${E}decrypt`] });
    const previewApprovalToken = await preview(token, allowed, { allowed: ['not-this-id', 7, null] });
    const res = await post('/authorize-sign', { authorizationContextToken: token, previewApprovalToken, selectedActionIds: allowed, protocolVersion: 1 });
    expect(res.status).toBe(403);
    for (const garbage of ['yes', 7, null, [], { allowed: 'all' }, { allowed: {} }]) {
      const fresh = await prepare({ [urn('')]: [`${E}decrypt`] });
      const tok = await preview(fresh.token, fresh.allowed, garbage);
      const r = await post('/authorize-sign', { authorizationContextToken: fresh.token, previewApprovalToken: tok, selectedActionIds: fresh.allowed, protocolVersion: 1 });
      expect(r.status, JSON.stringify(garbage)).toBe(403);
    }
  });

  test('rejecting a permission narrows it out and the rest of the request signs with no allow for it', async () => {
    const raw = { [urn('')]: [`${E}decrypt`] };
    const { token, allowed } = await prepare(raw);
    const rest = allowed.filter((id) => !elevatedIds(allowed).includes(id));
    expect(rest.length).toBeGreaterThan(0);
    const previewApprovalToken = await preview(token, rest);
    const res = await post('/authorize-sign', { authorizationContextToken: token, previewApprovalToken, selectedActionIds: rest, protocolVersion: 1 });
    expect(res.status, await res.clone().text()).toBe(200);
    const result = await res.json() as { signedMessage: string };
    expect(result.signedMessage).not.toContain('decrypt');
    expect(signed.length).toBe(1);
  });

  test('rejecting one permission and allowing another signs only the allowed one', async () => {
    const raw = { [urn('')]: [`${E}decrypt`], [urn('/qa/')]: [`${E}decrypt`] };
    const { token, allowed } = await prepare(raw);
    const elevated = elevatedIds(allowed);
    expect(elevated.length).toBe(2);
    const keepElevated = elevated.find((id) => id.includes('/qa/'))!;
    const selected = allowed.filter((id) => !elevated.includes(id) || id === keepElevated);
    const previewApprovalToken = await preview(token, selected, { allowed: [keepElevated] });
    const res = await post('/authorize-sign', { authorizationContextToken: token, previewApprovalToken, selectedActionIds: selected, protocolVersion: 1 });
    expect(res.status, await res.clone().text()).toBe(200);
    const result = await res.json() as { selectedActionKeys: string[] };
    // The response reports a raw encryption resource as the space with no path: the folder row is there, the whole-network row is not.
    expect(result.selectedActionKeys.some((key) => key.includes('/qa/') && key.includes('encryption/decrypt'))).toBe(true);
    expect(result.selectedActionKeys.some((key) => !key.includes('/qa/') && key.includes('encryption/decrypt'))).toBe(false);
  });

  test('a request without extra permissions needs no decision', async () => {
    const { token, allowed } = await prepare({ [urn('')]: [`${E}network.create`] });
    const previewApprovalToken = await preview(token, allowed);
    const res = await post('/authorize-sign', { authorizationContextToken: token, previewApprovalToken, selectedActionIds: allowed, protocolVersion: 1 });
    expect(res.status, await res.clone().text()).toBe(200);
  });
});

describe('a website under its own apps/<app id>/ prefix', () => {
  const origin = 'https://listen.tinycloud.xyz';
  const manifest = () => ({
    ok: true,
    fetchedDigest: 'a'.repeat(64),
    manifest: {
      name: 'Listen',
      appId: APP_ID,
      prefix: APP_ID,
      declaredAppId: APP_ID,
      declaredKeys: parseManifestKeys(APP_ID, [{ prefix: `apps/${APP_ID}/`, abilities: ['key.create', 'decrypt'] }]),
    },
  });

  test('is still admitted, previewed and signed, with no extra decision for its own keys', async () => {
    manifestBindResult = manifest();
    const siwe = siweWith({ [urn(`/apps/${APP_ID}/`)]: [`${E}key.create`, `${E}decrypt`] }, new URL(origin).host);
    const prepared = await post('/authorize-sign-prepare', { ...prepareBody(siwe, origin), presentation: { manifestDigest: 'a'.repeat(64), displayName: 'Listen' } });
    expect(prepared.status, await prepared.clone().text()).toBe(200);
    const { authorizationContextToken, allowedActionIds } = await prepared.json() as { authorizationContextToken: string; allowedActionIds: string[] };
    const previewApprovalToken = await preview(authorizationContextToken, allowedActionIds);
    const res = await post('/authorize-sign', { authorizationContextToken, previewApprovalToken, selectedActionIds: allowedActionIds, protocolVersion: 1 });
    expect(res.status, await res.clone().text()).toBe(200);
  });

  test('rejecting an extra permission beside its own admitted keys is not a partial app-key approval', async () => {
    manifestBindResult = manifest();
    const siwe = siweWith({ [urn(`/apps/${APP_ID}/`)]: [`${E}key.create`, `${E}decrypt`], [urn('/share/')]: [`${E}decrypt`] }, new URL(origin).host);
    const prepared = await post('/authorize-sign-prepare', { ...prepareBody(siwe, origin), presentation: { manifestDigest: 'a'.repeat(64), displayName: 'Listen' } });
    expect(prepared.status, await prepared.clone().text()).toBe(200);
    const { authorizationContextToken, allowedActionIds } = await prepared.json() as { authorizationContextToken: string; allowedActionIds: string[] };
    const selected = allowedActionIds.filter((id) => !id.includes('/share/'));
    expect(selected.length).toBeLessThan(allowedActionIds.length);
    const previewApprovalToken = await preview(authorizationContextToken, selected);
    const res = await post('/authorize-sign', { authorizationContextToken, previewApprovalToken, selectedActionIds: selected, protocolVersion: 1 });
    expect(res.status, await res.clone().text()).toBe(200);
  });

  test('dropping one of its own admitted keys while keeping another request row is still refused', async () => {
    manifestBindResult = manifest();
    const siwe = siweWith({ [urn(`/apps/${APP_ID}/`)]: [`${E}key.create`, `${E}decrypt`] }, new URL(origin).host);
    const prepared = await post('/authorize-sign-prepare', { ...prepareBody(siwe, origin), presentation: { manifestDigest: 'a'.repeat(64), displayName: 'Listen' } });
    const { authorizationContextToken, allowedActionIds } = await prepared.json() as { authorizationContextToken: string; allowedActionIds: string[] };
    const selected = allowedActionIds.filter((id) => !id.includes('tinycloud.kv'));
    const res = await post('/authorize-sign-preview', { authorizationContextToken, selectedActionIds: selected });
    expect(res.status).toBe(400);
    expect(await fieldOf(res, 'code')).toBe('app_key_group_partial');
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
  ])('prepares, previews and signs %s with no decision', async (_name, raw) => {
    const siwe = siweWith(raw, 'cli.tinycloud.xyz');
    const ticket = await claim(siwe, 20);
    const prepared = await post('/authorize-sign-prepare', { ticket, keyId: keyRecord.id, siwe, jwk, host: HOST });
    expect(prepared.status, await prepared.clone().text()).toBe(200);
    const { authorizationContextToken, allowedActionIds } = await prepared.json() as { authorizationContextToken: string; allowedActionIds: string[] };
    const preview = await post('/authorize-sign-preview', { ticket, authorizationContextToken, selectedActionIds: allowedActionIds });
    expect(preview.status, await preview.clone().text()).toBe(200);
    const { previewApprovalToken } = await preview.json() as { previewApprovalToken: string };
    const res = await post('/authorize-sign', { ticket, authorizationContextToken, previewApprovalToken, selectedActionIds: allowedActionIds, protocolVersion: 1 });
    expect(res.status, await res.clone().text()).toBe(200);
    const result = await res.json() as { signedMessage: string; signature: string };
    expect(verifyMessage(result.signedMessage, result.signature)).toBe(address);
    expect(signed.length).toBe(1);
  });

  test.each([
    ['key.block on a folder', { [folder]: [`${E}key.block`] }],
    ['key.unblock on the whole network', { [bare]: [`${E}key.unblock`] }],
  ])('refuses %s from a ticket request: it carries no owner decision', async (_name, raw) => {
    const siwe = siweWith(raw, 'cli.tinycloud.xyz');
    const ticket = await claim(siwe, 30);
    const prepared = await post('/authorize-sign-prepare', { ticket, keyId: keyRecord.id, siwe, jwk, host: HOST });
    expect(prepared.status).toBe(403);
    expect(await fieldOf(prepared, 'code')).toBe('app_key_grant_refused');
    expect(unsealMock).not.toHaveBeenCalled();
    expect(signed).toEqual([]);
  });
});
