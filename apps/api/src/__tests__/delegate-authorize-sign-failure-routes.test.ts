// TC-2382 over HTTP: /authorize-sign on a prepared CLI handoff. A signing that fails does not burn the
// handoff, and one that is in progress is reported as such, never as "already signed".
import { beforeAll, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { verifyMessage } from 'ethers';
import { mockModules, replaceModules } from './mock-module';
import { PreparedHandoffService, MemoryPreparedHandoffStore } from '../services/prepared-handoff';
import type { setPreparedHandoffServiceForTests } from '../routes/delegate';
// The route reads the shared module, not a query-suffixed copy, so its token store is the one reset and peeked here.
import { _resetAuthorizationContextStoreForTests as resetContexts, peekAuthorizationContext as peekContext } from '../services/authorization-signing';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const user = { id: 'user_1', email: 'alice@example.test' };
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const keyRecord = { id: 'key_1', userId: user.id, address, keyType: 'MANAGED', archivedAt: null, sealedBlob: 'sealed-blob', sealingContext: null };

const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: Record<string, unknown> }) => {
      if (where.userId !== user.id || (where.id !== undefined && where.id !== keyRecord.id) || where.archivedAt !== null) return null;
      return keyRecord;
    }),
    findMany: mock(async () => [keyRecord]),
    findUnique: mock(async () => keyRecord),
  },
  user: { findUnique: mock(async () => ({ autoSignEnabled: true })) },
  tinyCloudBootstrapState: {},
};

// What unsealing the managed key does for the next signing: succeeds, fails, or waits to be released.
let unseal: () => Promise<string> = async () => privateKey;

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
    unseal: mock(async () => unseal()),
    createWalletFromPrivateKey: (key: string) => {
      const wallet = privateKeyToAccount(key as `0x${string}`);
      return { ...wallet, signMessage: async (input: { message: string }) => wallet.signMessage(input) };
    },
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => address,
  }),
  '@tinycloud/sdk-core': () => ({ activateSessionWithHost: mock(async () => ({ success: true })) }),
});

let router: typeof import('../routes/delegate')['delegateRouter'];
let setHandoffService: typeof setPreparedHandoffServiceForTests;
beforeAll(async () => {
  ({ delegateRouter: router, setPreparedHandoffServiceForTests: setHandoffService } = await import('../routes/delegate?authorize-sign-failure-isolated' as string));
});
beforeEach(() => {
  resetContexts();
  unseal = async () => privateKey;
});

const state = Buffer.alloc(32, 1).toString('base64url');
const cancelSecret = Buffer.alloc(32, 2).toString('base64url');
const post = (target: Pick<typeof router, 'request'>, path: string, body: unknown) =>
  target.request(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

/** Claim, prepare and preview one handoff; the returned `sign` posts the approval. */
async function approvedHandoff() {
  const service = new PreparedHandoffService(new MemoryPreparedHandoffStore());
  setHandoffService(service);
  // Imported after the route replacements; a static import would load the real session middleware.
  const { createPreparedHandoffRouter } = await import('../routes/prepared-handoffs?authorize-sign-failure-isolated' as string);
  const handoffs = createPreparedHandoffRouter(service);
  const space = `tinycloud:pkh:eip155:1:${address}:default`;
  const now = new Date();
  const siwe = prepareSession({
    address, chainId: 1, domain: 'cli.tinycloud.xyz', spaceId: space, jwk,
    issuedAt: now.toISOString(), expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
    abilities: { kv: { [space]: ['tinycloud.kv/get', 'tinycloud.kv/put'] }, capabilities: { [space]: ['tinycloud.capabilities/read'] } } as never,
  }).siwe;
  const ticket = Buffer.alloc(32, 3).toString('base64url');
  const claimed = await post(handoffs, '/claim', {
    transportVersion: 2,
    request: { protocolVersion: 1, siwe, jwk, host: 'https://node.tinycloud.xyz', keyId: keyRecord.id, sessionDid: 'did:key:cli-session' },
    delivery: { handoffId: ticket, state, cancelSecret },
  });
  expect(claimed.status).toBe(201);
  const prepared = await (await post(router, '/authorize-sign-prepare', { ticket, keyId: keyRecord.id, siwe, jwk, host: 'https://node.tinycloud.xyz' })).json() as { authorizationContextToken: string; allowedActionIds: string[] };
  const selectedActionIds = prepared.allowedActionIds;
  const preview = await (await post(router, '/authorize-sign-preview', { ticket, authorizationContextToken: prepared.authorizationContextToken, selectedActionIds })).json() as { signedMessage: string; previewApprovalToken: string };
  const signBody = { ticket, authorizationContextToken: prepared.authorizationContextToken, previewApprovalToken: preview.previewApprovalToken, selectedActionIds, protocolVersion: 1 };
  return {
    ticket, handoffs, signedMessage: preview.signedMessage, contextToken: prepared.authorizationContextToken,
    sign: () => post(router, '/authorize-sign', signBody),
    cancelAsOwner: () => post(handoffs, '/cancel-claimed', { ticket }),
    cancelAsCli: () => post(handoffs, '/cancel', { ticket, cancelSecret }),
  };
}

describe('prepared handoff signing that fails', () => {
  test('a failed signing answers 500 and leaves the handoff usable: the same approval signs on retry', async () => {
    const handoff = await approvedHandoff();
    unseal = async () => { throw new Error('TEE unavailable'); };
    const failed = await handoff.sign();
    expect(failed.status).toBe(500);
    expect(await failed.json()).toMatchObject({ code: 'sign_failed' });
    unseal = async () => privateKey;
    const retry = await handoff.sign();
    expect(retry.status).toBe(200);
    const result = await retry.json() as { signature: string; signedMessage: string; deliveryState: string };
    expect(result.signedMessage).toBe(handoff.signedMessage);
    expect(result.deliveryState).toBe(state);
    expect(verifyMessage(result.signedMessage, result.signature)).toBe(address);
  });

  test('a failed signing delivers nothing and can still be cancelled by the owner and by the CLI', async () => {
    const owner = await approvedHandoff();
    unseal = async () => { throw new Error('TEE unavailable'); };
    const failed = await owner.sign();
    expect(JSON.stringify(await failed.json())).not.toContain(state);
    const cancelled = await owner.cancelAsOwner();
    expect(cancelled.status).toBe(200);
    expect(await cancelled.json()).toEqual({ cancelled: true });
    expect((await owner.sign()).status).toBeGreaterThanOrEqual(400);

    resetContexts();
    const cli = await approvedHandoff();
    expect((await cli.sign()).status).toBe(500);
    expect((await cli.cancelAsCli()).status).toBe(200);
  });

  test('a signing that succeeds spends the handoff: replay and cancel say it was signed', async () => {
    const handoff = await approvedHandoff();
    expect((await handoff.sign()).status).toBe(200);
    const cancelled = await handoff.cancelAsOwner();
    expect(cancelled.status).toBe(409);
    expect(await cancelled.json()).toMatchObject({ code: 'handoff_consumed' });
    expect((await handoff.sign()).status).toBeGreaterThanOrEqual(400);
  });

  test('the context and preview tokens are spent exactly once: gone after a successful sign, still there after a failed one', async () => {
    const handoff = await approvedHandoff();
    unseal = async () => { throw new Error('TEE unavailable'); };
    expect((await handoff.sign()).status).toBe(500);
    expect(peekContext(handoff.contextToken).ok).toBe(true);
    unseal = async () => privateKey;
    expect((await handoff.sign()).status).toBe(200);
    expect(peekContext(handoff.contextToken).ok).toBe(false);
  });
});

describe('prepared handoff signing in progress', () => {
  test('a second approval and a cancel are told it is being signed, and the first signing still delivers', async () => {
    const handoff = await approvedHandoff();
    const reachedTee = Promise.withResolvers<void>();
    const teeAnswer = Promise.withResolvers<string>();
    unseal = () => { reachedTee.resolve(); return teeAnswer.promise; };
    const first = handoff.sign();
    await reachedTee.promise;
    const second = await handoff.sign();
    expect(second.status).toBe(409);
    expect(await second.json()).toMatchObject({ code: 'handoff_signing' });
    const cancelled = await handoff.cancelAsOwner();
    expect(cancelled.status).toBe(409);
    expect(await cancelled.json()).toMatchObject({ code: 'handoff_signing' });
    const cliCancel = await handoff.cancelAsCli();
    expect(cliCancel.status).toBe(409);
    expect(await cliCancel.json()).toMatchObject({ code: 'handoff_signing' });
    teeAnswer.resolve(privateKey);
    const delivered = await first;
    expect(delivered.status).toBe(200);
    expect(await delivered.json()).toMatchObject({ deliveryState: state });
  });

  test('when the tokens cannot be spent after the key has signed, the handoff stays SIGNING and no signature is delivered (fails closed)', async () => {
    const handoff = await approvedHandoff();
    const reachedTee = Promise.withResolvers<void>();
    const teeAnswer = Promise.withResolvers<string>();
    unseal = () => { reachedTee.resolve(); return teeAnswer.promise; };
    const first = handoff.sign();
    await reachedTee.promise;
    // The context is gone while the key is signing (expired or evicted), so the tokens cannot be spent.
    resetContexts();
    teeAnswer.resolve(privateKey);
    const refused = await first;
    expect(refused.status).toBe(400);
    const body = JSON.stringify(await refused.json());
    expect(body).not.toContain(state);
    expect(body).not.toContain('signature');
    // A signature exists for this handoff, so it is not released: it stays SIGNING until it expires.
    const cancelled = await handoff.cancelAsOwner();
    expect(cancelled.status).toBe(409);
    expect(await cancelled.json()).toMatchObject({ code: 'handoff_signing' });
    const cliCancel = await handoff.cancelAsCli();
    expect(cliCancel.status).toBe(409);
    expect(await cliCancel.json()).toMatchObject({ code: 'handoff_signing' });
  });
});
