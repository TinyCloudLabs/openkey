import { beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const user = { id: 'user_1', email: 'test@example.com' };

class MockTinyCloudBootstrapError extends Error {
  constructor(
    message: string,
    public readonly code = 'tinycloud_bootstrap_failed',
    public readonly retryable = true,
  ) {
    super(message);
  }
}

let calls: string[] = [];
let keyRecord: {
  id: string;
  userId: string;
  address: string;
  keyType: 'MANAGED' | 'EXTERNAL';
  sealedBlob: string | null;
  archivedAt: null;
};

const unseal = mock(async () => privateKey);
const ensureTinyCloudBootstrapForApprovedSign = mock(async () => {
  calls.push('bootstrap');
});

const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: Record<string, unknown> }) => {
      if (where.userId !== keyRecord.userId) return null;
      if (where.id !== keyRecord.id) return null;
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
  TinyCloudBootstrapError: MockTinyCloudBootstrapError,
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

  test('POST /:keyId/sign still signs the approved message when bootstrap fails', async () => {
    ensureTinyCloudBootstrapForApprovedSign.mockImplementationOnce(async () => {
      calls.push('bootstrap');
      throw new MockTinyCloudBootstrapError('bootstrap failed', 'tinycloud_bootstrap_failed', true);
    });
    const router = await keysRouter();

    const response = await router.request('/key_1/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'hello' }),
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toMatchObject({
      signature: expect.stringMatching(/^0x[0-9a-f]+$/i),
      address,
      format: 'personal_sign',
    });
    expect(calls).toEqual(['bootstrap', 'sign']);
  });
});
