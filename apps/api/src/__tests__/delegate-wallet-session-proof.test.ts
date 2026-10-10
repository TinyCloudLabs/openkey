// TC-675: an external-wallet `/api/delegate/complete` hands the CLI the same
// session proof as the managed `/api/delegate` approval, and that proof passes
// the CLI's own verification. A `signature` that is not a string is refused at
// the request boundary, before the single-use context is consumed and before
// host activation.

import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import type { delegateRouter } from '../routes/delegate';
import type { _resetAuthorizationContextStoreForTests } from '../services/authorization-signing';

interface SessionKeyManager {
  createSessionKey(keyId?: string | null): string;
  jwk(keyId?: string | null): string | undefined;
  getDID(keyId?: string | null): string;
}
interface VerifiedSessionProof {
  verifiedRecap?: { service: string }[];
  expiresAt?: string;
}
interface CliVerifierWasm {
  TCWSessionManager: new () => SessionKeyManager;
  validatePersistedSession(proof: unknown): VerifiedSessionProof;
}
interface PreparedResponse {
  prepared: { siwe: string } & Record<string, unknown>;
  authorizationContext: { token: string };
  selectedActionKeys: string[];
  edited: boolean;
}

// The TinyCloud CLI (@tinycloud/cli 1.1.0) verifies sessions with
// node-sdk-wasm 1.7.7, the first build that exports validatePersistedSession.
// The API keeps building sessions with its own pinned 1.7.4. The verifier is
// resolved from packages/sdk-capacitor, which declares @tinycloud/web-sdk
// 3.1.0 (-> node-sdk 3.1.0 -> node-sdk-wasm 1.7.7), as its
// verify-production test does.
const CLI_VERIFIER_VERSION = '1.7.7';
const capacitorRequire = createRequire(join(import.meta.dir, '../../../../packages/sdk-capacitor/package.json'));
const verifierRequire = createRequire(
  createRequire(capacitorRequire.resolve('@tinycloud/web-sdk')).resolve('@tinycloud/node-sdk'),
);
const verifierVersion: string = verifierRequire('@tinycloud/node-sdk-wasm/package.json').version;
const cliWasm: CliVerifierWasm = verifierRequire('@tinycloud/node-sdk-wasm');
const builderVersion: string = createRequire(join(import.meta.dir, '../../package.json'))(
  '@tinycloud/node-sdk-wasm/package.json',
).version;

// The CLI's session key: OpenKey only ever sees the public half.
const sessionKeys = new cliWasm.TCWSessionManager();
const sessionKeyId = sessionKeys.createSessionKey('cli');
const sessionKey: { kty: string; crv: string; x: string; d: string } = JSON.parse(sessionKeys.jwk(sessionKeyId) ?? 'null');
const sessionDid = sessionKeys.getDID(sessionKeyId);
const jwk = { kty: sessionKey.kty, crv: sessionKey.crv, x: sessionKey.x };

const managedPrivateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const managedAccount = privateKeyToAccount(managedPrivateKey);
const wallet = privateKeyToAccount('0x1111111111111111111111111111111111111111111111111111111111111111');
const user = { id: 'user_1', email: 'alice@example.test' };
const host = 'https://node.tinycloud.xyz';
const managedKey = {
  id: 'key_managed', userId: user.id, address: managedAccount.address, keyType: 'MANAGED',
  isCanonicalTinyCloud: true, archivedAt: null, sealedBlob: 'sealed-managed', sealingContext: null,
};
// Stored as the wallet reported it (lowercase); the SIWE carries EIP-55.
const externalKey = {
  id: 'key_external', userId: user.id, address: wallet.address.toLowerCase(), keyType: 'EXTERNAL',
  isCanonicalTinyCloud: false, archivedAt: null, sealedBlob: null, sealingContext: null,
};
const keys = [managedKey, externalKey];

type Where = { id?: string; userId?: string; archivedAt?: null; address?: { equals: string; mode: string } };
const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: Where }) => keys.find((key) =>
      key.userId === where.userId &&
      key.archivedAt === null &&
      (where.id === undefined || key.id === where.id) &&
      (where.address === undefined || key.address.toLowerCase() === where.address.equals.toLowerCase()),
    ) ?? null),
    findMany: mock(async () => keys),
    findUnique: mock(async () => null),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
};
const activateSessionWithHost = mock(async () => ({ success: true }));

mock.module('@openkey/db', () => ({ createPrismaClient: () => prisma }));
mock.module('@openkey/tee', () => ({
  createTeeClient: () => ({
    deriveKey: mock(async () => new Uint8Array(32)),
    getQuote: mock(async () => 'quote'),
    isInTee: () => false,
  }),
  unseal: mock(async () => managedPrivateKey),
  createWalletFromPrivateKey: (key: string) => privateKeyToAccount(key as `0x${string}`),
  generatePrivateKey: () => managedPrivateKey,
  getAddressFromPrivateKey: () => managedAccount.address,
}));
mock.module('@tinycloud/sdk-core', () => ({ activateSessionWithHost }));
mock.module('../middleware/session', () => ({
  requireSession: createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('session', { id: 'session_1', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
    await next();
  }),
}));

let router: typeof delegateRouter;
let resetContexts: typeof _resetAuthorizationContextStoreForTests;

beforeAll(async () => {
  // Imported after mock.module (and with an isolating query) so the route
  // binds the mocked database, TEE, and host activation.
  ({ delegateRouter: router } = await import('../routes/delegate?wallet-session-proof-isolated' as string));
  ({ _resetAuthorizationContextStoreForTests: resetContexts } = await import(
    '../services/authorization-signing?wallet-session-proof-isolated' as string
  ));
});

beforeEach(() => {
  resetContexts?.();
  activateSessionWithHost.mockClear();
});

async function post(path: string, body: Record<string, unknown>) {
  const res = await router.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

/** A scoped secrets read as the CLI requests it, with the TC-598 raw decrypt grant. */
function scopedRequest(address: string) {
  const space = `tinycloud:pkh:eip155:1:${address}:secrets`;
  return [
    { service: 'tinycloud.kv', space, path: 'vault/secrets/OPENAI_API_KEY', actions: ['tinycloud.kv/get'] },
    {
      service: 'tinycloud.encryption', space: 'encryption',
      path: `urn:tinycloud:encryption:did:pkh:eip155:1:${address}:default`, actions: ['tinycloud.encryption/decrypt'],
    },
    { service: 'tinycloud.capabilities', space, path: '', actions: ['tinycloud.capabilities/read'] },
  ];
}

async function prepare(keyId: string, address: string): Promise<PreparedResponse> {
  const res = await post('/prepare', { keyId, jwk, host, permissions: scopedRequest(address) });
  expect(res.status).toBe(200);
  // The route's own response, checked above; only these fields are read.
  return res.body as unknown as PreparedResponse;
}

/** The versioned body the web's external-wallet path sends (+page.svelte doExternalDelegate). */
function webCompletion(prepared: PreparedResponse, signature: unknown) {
  return {
    prepared: prepared.prepared, signature, host, jwk, edited: prepared.edited,
    permissions: scopedRequest(wallet.address),
    authorizationContextToken: prepared.authorizationContext.token,
    selectedActionIds: prepared.selectedActionKeys,
  };
}

/** A token-less legacy completion. */
function legacyCompletion(prepared: PreparedResponse, signature: unknown) {
  return { prepared: prepared.prepared, signature, host, jwk, permissions: scopedRequest(wallet.address) };
}

/** The recovery byte as some hardware wallets return it: 0/1 instead of 27/28. */
function withRecoveryBit(signature: string): string {
  return signature.slice(0, -2) + (parseInt(signature.slice(-2), 16) - 27).toString(16).padStart(2, '0');
}

/**
 * Mirrors the CLI's field gate and cryptographic proof verification in js-sdk origin/master
 * (44d7d06b) packages/cli/src/auth/scoped-login.ts:358-410
 * (`verifySignedSession`, last changed in 2c703fc9). WASM validation uses the
 * CLI's own private session JWK. No key material is taken from the response;
 * its `verificationMethod` is only compared with the CLI's session DID.
 */
function verifyLikeCli(data: Record<string, unknown>): VerifiedSessionProof {
  const { siwe, signature, address, chainId, spaceId, delegationCid, delegationHeader, verificationMethod } = data;
  if (
    typeof siwe !== 'string' || typeof signature !== 'string' || typeof address !== 'string' ||
    !Number.isSafeInteger(chainId) || typeof spaceId !== 'string' || typeof delegationCid !== 'string' ||
    !delegationHeader || typeof delegationHeader !== 'object' ||
    typeof verificationMethod !== 'string' || verificationMethod.split('#')[0] !== sessionDid.split('#')[0]
  ) {
    throw new Error('OpenKey returned an incomplete session proof');
  }
  const proof = cliWasm.validatePersistedSession({
    delegationHeader, delegationCid, spaceId, jwk: sessionKey, address, chainId, siwe, signature,
  });
  if (!proof.verifiedRecap?.length || !proof.expiresAt || !Number.isFinite(Date.parse(proof.expiresAt))) {
    throw new Error('OpenKey returned an unverifiable session proof');
  }
  return proof;
}

function verifiedServices(data: Record<string, unknown>): string[] {
  return (verifyLikeCli(data).verifiedRecap ?? []).map((entry) => entry.service).sort();
}

describe(`session proofs (API node-sdk-wasm ${builderVersion}, CLI verifier node-sdk-wasm ${verifierVersion})`, () => {
  test('verifies with the WASM build the CLI ships', () => {
    expect(verifierVersion).toBe(CLI_VERIFIER_VERSION);
  });

  const walletCompletions = [
    { name: 'the web completion', body: webCompletion, sign: (signature: string) => signature },
    { name: 'the web completion, hardware-wallet recovery byte', body: webCompletion, sign: withRecoveryBit },
    { name: 'a token-less legacy completion', body: legacyCompletion, sign: (signature: string) => signature },
  ];
  for (const completion of walletCompletions) {
    test(`an external-wallet approval returns a proof the CLI verifies: ${completion.name}`, async () => {
      const prepared = await prepare(externalKey.id, wallet.address);
      const signature = completion.sign(await wallet.signMessage({ message: prepared.prepared.siwe }));
      const res = await post('/complete', completion.body(prepared, signature));
      expect(res.status).toBe(200);
      expect(res.body.signature).toBe(signature);
      expect(verifiedServices(res.body)).toEqual(['capabilities', 'encryption', 'kv']);
    });
  }

  test('the managed approval returns a proof the same check accepts', async () => {
    const prepared = await prepare(managedKey.id, managedAccount.address);
    const res = await post('/', {
      keyId: managedKey.id, jwk, host, prefix: 'default', permissions: scopedRequest(managedAccount.address),
      prepared: prepared.prepared,
      authorizationContextToken: prepared.authorizationContext.token,
      selectedActionIds: prepared.selectedActionKeys,
      protocolVersion: 1,
    });
    expect(res.status).toBe(200);
    expect(verifiedServices(res.body)).toEqual(['capabilities', 'encryption', 'kv']);
  });
});

describe('a signature that is not a string', () => {
  const malformed: { name: string; value: (signature: string) => unknown }[] = [
    { name: 'an object whose toString is null', value: () => ({ toString: null }) },
    { name: 'the valid signature wrapped in an array', value: (signature) => [signature] },
  ];
  for (const input of malformed) {
    test(`is refused after required-field validation and before the context is consumed: ${input.name}`, async () => {
      const prepared = await prepare(externalKey.id, wallet.address);
      const signature = await wallet.signMessage({ message: prepared.prepared.siwe });
      const refused = await post('/complete', webCompletion(prepared, input.value(signature)));
      expect(refused.status).toBe(400);
      expect(refused.body.error).toBe('signature must be a string');
      expect(refused.body.delegationHeader).toBeUndefined();
      expect(activateSessionWithHost).not.toHaveBeenCalled();

      // The pending approval is still usable.
      const ok = await post('/complete', webCompletion(prepared, signature));
      expect(ok.status).toBe(200);
      expect(activateSessionWithHost).toHaveBeenCalledTimes(1);
    });
  }

  test('is refused after required-field validation on a token-less legacy completion before session setup', async () => {
    const prepared = await prepare(externalKey.id, wallet.address);
    const signature = await wallet.signMessage({ message: prepared.prepared.siwe });
    const refused = await post('/complete', legacyCompletion(prepared, [signature]));
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe('signature must be a string');
    expect(activateSessionWithHost).not.toHaveBeenCalled();
  });
});
