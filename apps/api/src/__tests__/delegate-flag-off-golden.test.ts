// TC-1781: with `DECRYPT_LIFETIME_ENFORCE_NON_DEVICE` unset, `/prepare`, `/`,
// and `/complete` must answer exactly as they did before the flag existed.
// The golden table in `fixtures/delegate-flag-off-golden.json` was recorded by
// running this same request table against origin/main `3cdfa5a`. Values that
// vary per run are normalised (nonces, signatures, UUIDs, tokens, CIDs, the
// auth header). The clock is fixed by `setSystemTime`, so timestamps are raw.

import { beforeAll, beforeEach, describe, expect, mock, setSystemTime, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import type { delegateRouter, setDelegateSignerAuthMiddlewareForTests } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';
import { mockModules, replaceModules } from './mock-module';
import golden from './fixtures/delegate-flag-off-golden.json';

const walletKey = '0x1111111111111111111111111111111111111111111111111111111111111111';
const wallet = privateKeyToAccount(walletKey);
const foreignAddress = privateKeyToAccount('0x2222222222222222222222222222222222222222222222222222222222222222').address;
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const host = 'https://node.tinycloud.xyz';
const keyBase = { userId: user.id, address: wallet.address, archivedAt: null, sealingContext: null };
const managedKey = { ...keyBase, id: 'key_managed', keyType: 'MANAGED', sealedBlob: 'sealed-blob' };
const externalKey = { ...keyBase, id: 'key_ext', keyType: 'EXTERNAL', sealedBlob: null };
const keys = [managedKey, externalKey];

const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: { id?: string } }) => keys.find((key) => key.id === where.id) ?? null),
    findMany: mock(async () => keys),
    findUnique: mock(async () => managedKey),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
};
const activateSessionWithHost = mock(async () => ({ success: true }));

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
    createTeeClient: () => ({
      deriveKey: mock(async () => new Uint8Array(32)),
      getQuote: mock(async () => 'quote'),
      isInTee: () => false,
    }),
    unseal: mock(async () => walletKey),
    createWalletFromPrivateKey: (key: string) => privateKeyToAccount(key as `0x${string}`),
    generatePrivateKey: () => walletKey,
    getAddressFromPrivateKey: () => wallet.address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost }),
});

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;

beforeAll(async () => {
  let setSignerAuth: typeof setDelegateSignerAuthMiddlewareForTests;
  ({ delegateRouter: router, setDelegateSignerAuthMiddlewareForTests: setSignerAuth } = await import(
    '../routes/delegate?flag-off-golden-isolated' as string
  ));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?flag-off-golden-isolated' as string
  ));
  setSignerAuth(createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('delegateSignerPrincipal', { kind: 'session', userId: user.id });
    c.set('delegateSignerOauthContext', null);
    c.set('delegateSignerAuthFailure', null);
    await next();
  }));
  setSystemTime(new Date('2030-01-01T00:00:00.000Z'));
});

beforeEach(() => {
  resetContexts?.();
  activateSessionWithHost.mockClear();
});

const space = `tinycloud:pkh:eip155:1:${wallet.address}:secrets`;
const ownNetwork = `urn:tinycloud:encryption:did:pkh:eip155:1:${wallet.address}:default`;
const foreignNetwork = `urn:tinycloud:encryption:did:pkh:eip155:1:${foreignAddress}:default`;
const namedKeyNetwork = `urn:tinycloud:encryption:did:pkh:eip155:1:${wallet.address}:mykey`;
const DECRYPT = 'tinycloud.encryption/decrypt';
const kvGet = { service: 'tinycloud.kv', space, path: 'vault/secrets/TC_FWD_TOKEN', actions: ['tinycloud.kv/get'] };
const capabilitiesRead = { service: 'tinycloud.capabilities', space, path: '', actions: ['tinycloud.capabilities/read'] };
const deviceDefaultDecrypt = { service: 'tinycloud.encryption', space: 'default', path: '', actions: [DECRYPT] };
const rawOwnDecrypt = { service: 'tinycloud.encryption', space: 'encryption', path: ownNetwork, actions: [DECRYPT] };
const rawForeignDecrypt = { service: 'tinycloud.encryption', space: 'encryption', path: foreignNetwork, actions: [DECRYPT] };
const rawNamedKeyDecrypt = { service: 'tinycloud.encryption', space: 'encryption', path: namedKeyNetwork, actions: [DECRYPT] };
const request = [kvGet, rawOwnDecrypt, capabilitiesRead];

type Result = { status: number; body: unknown };

type PreparedBody = {
  prepared: Record<string, unknown>;
  edited: unknown;
  selectedActionKeys: unknown;
  authorizationContext: { token: string };
};

async function post(path: string, body: Record<string, unknown>): Promise<Result> {
  const res = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

function prepareBody(permissions: unknown[], expiry?: string, keyId = externalKey.id) {
  return { keyId, jwk, host, permissions, ...(expiry === undefined ? {} : { expiry }) };
}

async function completeWith(prepared: PreparedBody, siwe: string, permissions: unknown[] = request): Promise<Result> {
  return post('/complete', {
    prepared: { ...prepared.prepared, siwe },
    signature: await wallet.signMessage({ message: siwe }),
    host,
    jwk,
    edited: prepared.edited,
    permissions,
    authorizationContextToken: prepared.authorizationContext.token,
    selectedActionIds: prepared.selectedActionKeys,
  });
}

const cases: Record<string, () => Promise<Result>> = {
  'prepare lone device-shaped default decrypt, 3600s': () => post('/prepare', prepareBody([deviceDefaultDecrypt], '3600s')),
  'prepare lone device-shaped default decrypt, 3601s': () => post('/prepare', prepareBody([deviceDefaultDecrypt], '3601s')),
  'prepare lone device-shaped default decrypt, no expiry': () => post('/prepare', prepareBody([deviceDefaultDecrypt])),
  'prepare lone own-network raw decrypt, 3600s': () => post('/prepare', prepareBody([rawOwnDecrypt], '3600s')),
  'prepare lone own-network raw decrypt, 3601s': () => post('/prepare', prepareBody([rawOwnDecrypt], '3601s')),
  'prepare lone own-network raw decrypt, no expiry': () => post('/prepare', prepareBody([rawOwnDecrypt])),
  'prepare lone foreign-network raw decrypt, 3600s': () => post('/prepare', prepareBody([rawForeignDecrypt], '3600s')),
  'prepare lone named-key raw decrypt, 3600s': () => post('/prepare', prepareBody([rawNamedKeyDecrypt], '3600s')),
  'prepare two decrypt entries (device default + own raw), 3600s': () =>
    post('/prepare', prepareBody([deviceDefaultDecrypt, rawOwnDecrypt], '3600s')),
  'prepare kv + raw decrypt, default expiry': () => post('/prepare', prepareBody(request)),
  'prepare kv + raw decrypt, 3601s': () => post('/prepare', prepareBody(request, '3601s')),
  'prepare kv only, default expiry': () => post('/prepare', prepareBody([kvGet, capabilitiesRead])),
  'managed approval lone own-network raw decrypt, 3600s': () =>
    post('/', prepareBody([rawOwnDecrypt], '3600s', managedKey.id)),
  'managed approval lone device-shaped default decrypt, 3600s': () =>
    post('/', prepareBody([deviceDefaultDecrypt], '3600s', managedKey.id)),
  'managed approval kv + raw decrypt, default expiry': () => post('/', prepareBody(request, undefined, managedKey.id)),
  'complete with siwe containing urn:recap: that does not parse': async () => {
    const prepared = await post('/prepare', prepareBody(request));
    return completeWith(prepared.body as PreparedBody, 'urn:recap: not a parseable siwe message');
  },
  'complete with plain text siwe that does not parse': async () => {
    const prepared = await post('/prepare', prepareBody(request));
    return completeWith(prepared.body as PreparedBody, 'plain text, not a siwe message');
  },
};

const NONCE = /Nonce: \S+/g;
const SIG = /0x[0-9a-fA-F]{130}/g;
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g;
const TOKEN = /oks_[0-9a-f]+/g;
const CID = /bafk[a-z2-7]+/g;

/** Strip per-run values (nonce, signature, UUID, token, CID, auth header) so runs compare equal. */
function normalise(value: unknown, key = ''): unknown {
  if (typeof value === 'string') {
    if (key === 'Authorization') return '<authorization>';
    return value
      .replace(NONCE, 'Nonce: <nonce>')
      .replace(SIG, '<sig>')
      .replace(UUID, '<uuid>')
      .replace(TOKEN, 'oks_<token>')
      .replace(CID, '<cid>');
  }
  if (Array.isArray(value)) return value.map((item) => normalise(item));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, inner]) => [key, normalise(inner, key)]));
  }
  return value;
}

describe('flag OFF: golden behaviour', () => {
  test('every recorded request answers as origin/main 3cdfa5a did', async () => {
    const savedEnforce = process.env.DECRYPT_LIFETIME_ENFORCE_NON_DEVICE;
    const savedAdmit = process.env.DECRYPT_STEPUP_ADMIT;
    delete process.env.DECRYPT_LIFETIME_ENFORCE_NON_DEVICE;
    delete process.env.DECRYPT_STEPUP_ADMIT;
    try {
      const actual: Record<string, unknown> = {};
      for (const [name, run] of Object.entries(cases)) {
        resetContexts?.();
        const result = await run();
        actual[name] = normalise(result);
      }
      // Serialised comparison: key order and undefined-valued keys count, unlike toEqual.
      expect(JSON.stringify(actual)).toBe(JSON.stringify(golden));
    } finally {
      if (savedEnforce !== undefined) process.env.DECRYPT_LIFETIME_ENFORCE_NON_DEVICE = savedEnforce;
      if (savedAdmit !== undefined) process.env.DECRYPT_STEPUP_ADMIT = savedAdmit;
      setSystemTime();
    }
  });
});
