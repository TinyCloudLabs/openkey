import { beforeEach, describe, expect, mock, spyOn, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import type { TinyCloudBootstrapOutcome } from '../services/tinycloud-bootstrap';

// Keep the bootstrap sync budget short so the pending-path test is fast.
// Must be set before the routes/keys module is first imported.
process.env.TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS = '75';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const user = { id: 'user_1', email: 'test@example.com' };

let calls: string[] = [];
let keyRecord: {
  id: string;
  userId: string;
  address: string;
  keyType: 'MANAGED' | 'EXTERNAL';
  keyPurpose: 'PERSONAL' | 'MANAGED_ACCOUNT';
  sealedBlob: string | null;
  archivedAt: null;
};

const unseal = mock(async () => privateKey);
const ensureTinyCloudBootstrapForApprovedSign = mock(async (): Promise<TinyCloudBootstrapOutcome> => {
  calls.push('bootstrap');
  return { status: 'complete' as const };
});

const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: Record<string, unknown> }) => {
      if (where.userId !== keyRecord.userId) return null;
      if (where.id !== keyRecord.id) return null;
      if (where.keyPurpose !== keyRecord.keyPurpose) return null;
      if (where.archivedAt !== null) return null;
      return keyRecord;
    }),
  },
};

const tee = {
  deriveKey: mock(async () => new Uint8Array(32)),
  getQuote: mock(async () => 'quote'),
  isInTee: () => false,
};

mock.module('@openkey/db', () => ({
  createPrismaClient: () => prisma,
}));

mock.module('@openkey/tee', () => ({
  createTeeClient: () => tee,
  seal: mock(async () => 'sealed-private-key'),
  unseal,
  createWalletFromPrivateKey: (key: string) => {
    const wallet = privateKeyToAccount(key as `0x${string}`);
    return {
      ...wallet,
      signMessage: async (args: { message: string | { raw: `0x${string}` } }) => {
        calls.push('sign');
        return wallet.signMessage(args as { message: string });
      },
    };
  },
  generatePrivateKey: () => privateKey,
  getAddressFromPrivateKey: () => address,
}));

mock.module('../services/tinycloud-bootstrap', () => ({
  ensureTinyCloudBootstrapForApprovedSign,
}));

mock.module('../middleware/session', () => ({
  requireSession: createMiddleware(async (c, next) => {
    c.set('user', user);
    c.set('session', {
      id: 'session_1',
      userId: user.id,
      expiresAt: new Date(Date.now() + 60_000),
    });
    await next();
  }),
}));

beforeEach(() => {
  calls = [];
  keyRecord = {
    id: 'key_1',
    userId: user.id,
    address,
    keyType: 'MANAGED',
    keyPurpose: 'PERSONAL',
    sealedBlob: 'sealed-private-key',
    archivedAt: null,
  };
  unseal.mockClear();
  ensureTinyCloudBootstrapForApprovedSign.mockClear();
  prisma.ethereumKey.findFirst.mockClear();
  tee.deriveKey.mockClear();
});

async function keysRouter() {
  return (await import('../routes/keys')).keysRouter;
}

describe('keysRouter managed signing', () => {
  test('POST /:keyId/sign runs TinyCloud bootstrap before signing the approved message', async () => {
    const router = await keysRouter();
    const message = 'listen.tinycloud.xyz wants you to sign in with your Ethereum account';

    const response = await router.request('/key_1/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message }),
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      signature: expect.stringMatching(/^0x[0-9a-f]+$/i),
      address,
      format: 'personal_sign',
    });
    expect(calls).toEqual(['bootstrap', 'sign']);
    expect(ensureTinyCloudBootstrapForApprovedSign).toHaveBeenCalledWith(expect.objectContaining({
      userId: user.id,
      key: keyRecord,
      privateKey,
      message,
      format: 'personal_sign',
    }));
    expect(tee.deriveKey).toHaveBeenCalledWith(`openkey/user/${user.id}/keys`);
  });

  test('personal signing routes cannot select a tenant-managed key for the same user', async () => {
    keyRecord = { ...keyRecord, keyPurpose: 'MANAGED_ACCOUNT' };
    const router = await keysRouter();

    const response = await router.request('/key_1/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'must not sign' }),
    });

    expect(response.status).toBe(404);
    expect(unseal).not.toHaveBeenCalled();
    expect(ensureTinyCloudBootstrapForApprovedSign).not.toHaveBeenCalled();
  });

  test('POST /:keyId/sign rejects external keys before unsealing', async () => {
    keyRecord = { ...keyRecord, keyType: 'EXTERNAL', sealedBlob: null };
    const router = await keysRouter();

    const response = await router.request('/key_1/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'hello' }),
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: 'External keys must be signed client-side',
    });
    expect(unseal).not.toHaveBeenCalled();
    expect(ensureTinyCloudBootstrapForApprovedSign).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  test('POST /:keyId/sign returns 404 for a missing key before unsealing', async () => {
    keyRecord = { ...keyRecord, id: 'other_key' };
    const router = await keysRouter();

    const response = await router.request('/key_1/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'hello' }),
    });

    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toEqual({ error: 'Key not found' });
    expect(unseal).not.toHaveBeenCalled();
    expect(ensureTinyCloudBootstrapForApprovedSign).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  test('POST /:keyId/sign includes tinycloudBootstrap:complete in response on success', async () => {
    const router = await keysRouter();
    const message = 'listen.tinycloud.xyz wants you to sign in with your Ethereum account';

    const response = await router.request('/key_1/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message }),
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      signature: expect.stringMatching(/^0x[0-9a-f]+$/i),
      address,
      format: 'personal_sign',
      tinycloudBootstrap: { status: 'complete' },
    });
  });

  test('POST /:keyId/sign still signs when bootstrap returns failed and includes status in response', async () => {
    ensureTinyCloudBootstrapForApprovedSign.mockImplementationOnce(async () => {
      calls.push('bootstrap');
      return {
        status: 'failed' as const,
        errorCode: 'tinycloud_bootstrap_failed',
        errorMessage: 'node unreachable',
      };
    });
    const consoleSpy = spyOn(console, 'error').mockImplementation(() => {});
    const router = await keysRouter();

    const response = await router.request('/key_1/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'hello' }),
    });

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toMatchObject({
      signature: expect.stringMatching(/^0x[0-9a-f]+$/i),
      address,
      format: 'personal_sign',
      tinycloudBootstrap: { status: 'failed', errorCode: 'tinycloud_bootstrap_failed' },
    });
    expect(calls).toEqual(['bootstrap', 'sign']);
    expect(consoleSpy).toHaveBeenCalledWith(
      '[Keys] TinyCloud bootstrap failed',
      expect.objectContaining({
        keyId: keyRecord.id,
        errorCode: 'tinycloud_bootstrap_failed',
        errorMessage: 'node unreachable',
      }),
    );
    consoleSpy.mockRestore();
  });

  test('POST /:keyId/sign includes tinycloudBootstrap:skipped when bootstrap is not applicable', async () => {
    ensureTinyCloudBootstrapForApprovedSign.mockImplementationOnce(async () => {
      calls.push('bootstrap');
      return { status: 'skipped' as const };
    });
    const router = await keysRouter();

    const response = await router.request('/key_1/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'hello' }),
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      tinycloudBootstrap: { status: 'skipped' },
    });
    expect(calls).toEqual(['bootstrap', 'sign']);
  });

  test('POST /:keyId/sign does not wait for a slow bootstrap — returns pending within the budget', async () => {
    let resolveBootstrap!: (outcome: { status: 'complete' }) => void;
    ensureTinyCloudBootstrapForApprovedSign.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveBootstrap = resolve;
        }),
    );
    const router = await keysRouter();

    const startedAt = Date.now();
    const response = await router.request('/key_1/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'hello' }),
    });
    const elapsed = Date.now() - startedAt;

    expect(response.status).toBe(200);
    const body = (await response.json()) as { signature?: string; tinycloudBootstrap?: unknown };
    expect(body.signature).toBeTruthy();
    expect(body.tinycloudBootstrap).toEqual({ status: 'pending' });
    // Budget is 75ms in this suite; the signature must not wait on bootstrap.
    expect(elapsed).toBeLessThan(1000);

    // Let the background bootstrap settle so the test leaves no dangling work.
    resolveBootstrap({ status: 'complete' });
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
});
