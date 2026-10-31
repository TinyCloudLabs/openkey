import { beforeAll, beforeEach, describe, expect, mock, setSystemTime, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { verifyMessage } from 'ethers';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import * as signing from '../services/authorization-signing';
import * as realNarrowing from '../services/siwe-narrow';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import { mockModules, replaceModules } from './mock-module';

const account = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
const otherSigner = privateKeyToAccount('0x2222222222222222222222222222222222222222222222222222222222222222');
const user = { id: 'user_1', email: 'alice@example.test' };
const otherUser = { id: 'user_2', email: 'bob@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const host = 'https://node.tinycloud.xyz';
const space = `tinycloud:pkh:eip155:1:${account.address}:default`;
// Two database rows may hold the same wallet under different address casing:
// key linking checks the submitted spelling, while signer lookup normalizes it.
const otherExternal = {
  id: 'external_other', userId: otherUser.id, address: account.address.toLowerCase() as typeof account.address,
  keyType: 'EXTERNAL', archivedAt: null, sealedBlob: null, sealingContext: null,
};
const managed = {
  id: 'managed_1', userId: user.id, address: account.address, keyType: 'MANAGED',
  archivedAt: null, sealedBlob: 'sealed-blob', sealingContext: null,
};
const external = { ...managed, id: 'external_1', keyType: 'EXTERNAL', sealedBlob: null };
let currentUser = user;
let currentKey: typeof managed | typeof external = managed;
let narrowingFault: 'failure' | 'immutable-drift' | null = null;

const findMany = mock(async () => [currentKey]);
const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: { id: string; userId: string } }) =>
      where.id === currentKey.id && where.userId === currentUser.id ? currentKey : null),
    findMany,
    findUnique: mock(async () => currentKey),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
};
// Captured before mocking: bun rewrites the imported namespace in place.
const narrow = realNarrowing.narrowSiwePreservingImmutable;
const unseal = mock(async () => '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
const signManagedMessage = mock(async (message: string) => account.signMessage({ message }));
replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', currentUser);
      c.set('session', { id: 'session_test', userId: currentUser.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({ deriveKey: mock(async () => new Uint8Array(32)), getQuote: mock(async () => 'quote'), isInTee: () => false }),
    unseal,
    createWalletFromPrivateKey: () => ({ signMessage: ({ message }: { message: string }) => signManagedMessage(message) }),
    generatePrivateKey: () => '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    getAddressFromPrivateKey: () => account.address,
  }),
  // Fault injection at the SIWE regenerator, NOT at the authorization service:
  // valid prepared inputs cannot naturally produce a corrupt regenerated result.
  '../services/siwe-narrow': () => ({
    narrowSiwePreservingImmutable: (input: Parameters<typeof narrow>[0]) => {
      if (narrowingFault === 'failure') return narrow({ ...input, originalSiwe: '' });
      const result = narrow(input);
      if (narrowingFault === 'immutable-drift' && result.ok) {
        return { ...result, siwe: result.siwe.replace(/^(Nonce: .+)$/m, '$1x') };
      }
      return result;
    },
  }),
});

let router: typeof delegateRouter;
// Load the router after mock.module registrations; a static import would bind
// real Prisma/TEE dependencies before this isolated HTTP test installs fakes.
beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?approval-expiry-routes-isolated' as string
  ));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', currentUser);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: currentUser.id });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
});

beforeEach(() => {
  signing._resetAuthorizationContextStoreForTests();
  currentUser = user;
  currentKey = managed;
  narrowingFault = null;
  findMany.mockImplementation(async () => [currentKey]);
  unseal.mockClear();
  signManagedMessage.mockClear();
});

async function post(path: string, body: Record<string, unknown>) {
  const response = await router.request(path, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() as Record<string, unknown> };
}

function stringField(value: unknown): string {
  expect(typeof value).toBe('string');
  if (typeof value !== 'string') throw new Error('Expected string response field');
  return value;
}

function stringArray(value: unknown): string[] {
  expect(Array.isArray(value) && value.every((item: unknown) => typeof item === 'string')).toBe(true);
  if (!Array.isArray(value) || !value.every((item: unknown): item is string => typeof item === 'string')) {
    throw new Error('Expected string array response field');
  }
  return value;
}

function originalSiwe() {
  const now = Date.now();
  return prepareSession({
    address: account.address,
    chainId: 1,
    domain: 'openkey.so',
    issuedAt: new Date(now).toISOString(),
    expirationTime: new Date(now + 7 * 86_400_000).toISOString(),
    spaceId: space,
    jwk,
    abilities: {
      kv: { [space]: ['tinycloud.kv/get', 'tinycloud.kv/put'] },
      capabilities: { [space]: ['tinycloud.capabilities/read'] },
    } as unknown as Parameters<typeof prepareSession>[0]['abilities'],
  }).siwe;
}

const expiryLine = (siwe: string) => siwe.match(/^Expiration Time: (.+)$/m)?.[1];
const withoutExpiry = (siwe: string) => siwe.replace(/^Expiration Time: .+$/m, '');
const inDays = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString();

async function prepare() {
  const siwe = originalSiwe();
  const prepared = await post('/authorize-sign-prepare', { keyId: currentKey.id, siwe, jwk, host, requestOrigin: 'https://openkey.so' });
  expect(prepared.status).toBe(200);
  const allowed = stringArray(prepared.body.allowedActionIds);
  return { siwe, allowed, contextToken: stringField(prepared.body.authorizationContextToken) };
}

async function preview(p: Awaited<ReturnType<typeof prepare>>, selected: string[], expirationTime?: string) {
  return post('/authorize-sign-preview', {
    authorizationContextToken: p.contextToken, selectedActionIds: selected,
    ...(expirationTime === undefined ? {} : { expirationTime }),
  });
}

function signBody(p: Awaited<ReturnType<typeof prepare>>, selected: string[], previewToken: string) {
  return { authorizationContextToken: p.contextToken, previewApprovalToken: previewToken, selectedActionIds: selected, protocolVersion: 1 };
}

beforeEach(() => setSystemTime());

describe('the chosen approval expiry is what gets signed', () => {
  for (const selection of ['exact', 'narrowed'] as const) {
    test(`${selection} selection: preview and signature carry the chosen expiry and nothing else changes`, async () => {
      const p = await prepare();
      const selected = selection === 'narrowed' ? p.allowed.filter((id) => !id.includes('kv/put')) : p.allowed;
      const chosen = inDays(30);
      const unchanged = await preview(p, selected);
      expect(unchanged.status).toBe(200);
      const changed = await preview(p, selected, chosen);
      expect(changed.status).toBe(200);
      const bytes = stringField(changed.body.signedMessage);
      expect(expiryLine(bytes)).toBe(chosen);
      expect(withoutExpiry(bytes)).toBe(withoutExpiry(stringField(unchanged.body.signedMessage)));
      expect(expiryLine(stringField(unchanged.body.signedMessage))).toBe(expiryLine(p.siwe));

      const signed = await post('/authorize-sign', signBody(p, selected, stringField(changed.body.previewApprovalToken)));
      expect(signed.status).toBe(200);
      expect(signed.body.signedMessage).toBe(bytes);
      expect(expiryLine(stringField(signed.body.signedMessage))).toBe(chosen);
      expect(signManagedMessage).toHaveBeenCalledWith(bytes);
      expect(verifyMessage(bytes, stringField(signed.body.signature)).toLowerCase()).toBe(account.address.toLowerCase());
    });
  }

  test('a longer expiry than requested is signed as chosen, with no upper cap', async () => {
    const p = await prepare();
    const farAway = '9999-12-31T23:59:59.000Z';
    const result = await preview(p, p.allowed, farAway);
    expect(result.status).toBe(200);
    const signed = await post('/authorize-sign', signBody(p, p.allowed, stringField(result.body.previewApprovalToken)));
    expect(signed.status).toBe(200);
    expect(expiryLine(stringField(signed.body.signedMessage))).toBe(farAway);
  });

  test('an external signer signs the previewed bytes and /authorize-sign needs no expiry field', async () => {
    currentKey = external;
    const p = await prepare();
    const chosen = inDays(1);
    const result = await preview(p, p.allowed, chosen);
    const bytes = stringField(result.body.signedMessage);
    expect(expiryLine(bytes)).toBe(chosen);
    const signed = await post('/authorize-sign', {
      ...signBody(p, p.allowed, stringField(result.body.previewApprovalToken)),
      externalSignature: await account.signMessage({ message: bytes }),
    });
    expect(signed.status).toBe(200);
    expect(signed.body.signedMessage).toBe(bytes);
  });

  test('without a chosen expiry the original bytes are signed verbatim', async () => {
    const p = await prepare();
    const result = await preview(p, p.allowed);
    expect(result.body.signedMessage).toBe(p.siwe);
    const signed = await post('/authorize-sign', signBody(p, p.allowed, stringField(result.body.previewApprovalToken)));
    expect(signed.body.signedMessage).toBe(p.siwe);
  });

  test('re-previewing with another expiry seals the new bytes, and the old preview no longer signs', async () => {
    const p = await prepare();
    const first = await preview(p, p.allowed, inDays(1));
    const second = await preview(p, p.allowed, inDays(2));
    const signed = await post('/authorize-sign', signBody(p, p.allowed, stringField(second.body.previewApprovalToken)));
    expect(signed.status).toBe(200);
    expect(expiryLine(stringField(signed.body.signedMessage))).toBe(expiryLine(stringField(second.body.signedMessage)));
    // The first preview's token is bound to its own bytes and context, which the signature just used up.
    const stale = await post('/authorize-sign', signBody(p, p.allowed, stringField(first.body.previewApprovalToken)));
    expect(stale.status).toBe(400);
  });
});

describe('an expiry the server will not sign', () => {
  const cases: Array<[string, () => string | number | null]> = [
    ['not a time', () => 'soon'],
    ['a number', () => 12345],
    ['a date without the exact ISO form', () => '2030-01-01'],
    ['already past', () => new Date(Date.now() - 60_000).toISOString()],
    ['before the request was issued', () => new Date(Date.now() - 86_400_000).toISOString()],
    ['equal to the issue time', () => originalSiwe().match(/^Issued At: (.+)$/m)![1]!],
    ['null', () => null],
  ];
  for (const [name, value] of cases) {
    test(`${name} is refused and nothing is consumed`, async () => {
      const p = await prepare();
      const refused = await post('/authorize-sign-preview', {
        authorizationContextToken: p.contextToken, selectedActionIds: p.allowed, expirationTime: value(),
      });
      expect(refused.status).toBe(400);
      expect(refused.body.code).toBe('invalid_expiration_time');
      const ok = await preview(p, p.allowed, inDays(3));
      expect(ok.status).toBe(200);
      expect(signManagedMessage).not.toHaveBeenCalled();
    });
  }
});

describe('the one-minute floor', () => {
  test('a preview under a minute is refused, a minute and a bit is previewed', async () => {
    const p = await prepare();
    const refused = await preview(p, p.allowed, new Date(Date.now() + 30_000).toISOString());
    expect(refused.status).toBe(400);
    expect(refused.body.code).toBe('invalid_expiration_time');
    const ok = await preview(p, p.allowed, new Date(Date.now() + 90_000).toISOString());
    expect(ok.status).toBe(200);
  });
});
