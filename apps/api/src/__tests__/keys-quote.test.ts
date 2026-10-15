import { afterEach, beforeEach, describe, expect, mock, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import type { TeeQuote } from '@openkey/tee';
import { mockModules, replaceModules } from './mock-module';

const user = { id: 'user_1', email: 'test@example.com' };
const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const address = privateKeyToAccount(privateKey).address;
const otherPrivateKey = `0x${'22'.repeat(32)}`;

type KeyRecord = {
  id: string;
  userId: string;
  address: string;
  keyType: 'MANAGED' | 'EXTERNAL';
  sealedBlob: string | null;
  sealingContext: string | null;
  archivedAt: null;
};
let keyRecord: KeyRecord;

const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: Record<string, unknown> }) =>
      where.id === keyRecord.id && where.userId === keyRecord.userId && where.archivedAt === null ? keyRecord : null),
  },
};

// Stands in for the production client, whose dstack contract is covered by
// packages/tee/tests/dstack-quote.test.ts.
const tee = {
  deriveKey: mock(async () => new Uint8Array(32)),
  getQuote: mock(async (binding: string): Promise<TeeQuote> => ({
    quote: 'ab'.repeat(64),
    eventLog: '[{"imr":3}]',
    reportDataSha256: createHash('sha256').update(binding, 'utf8').digest('hex'),
  })),
  isInTee: () => true,
};
const unseal = mock(async (): Promise<string> => privateKey);

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
    createTeeClient: () => tee,
    seal: mock(async () => 'sealed'),
    unseal,
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: (key: `0x${string}`) => privateKeyToAccount(key).address,
  }),
});

const originalStdoutWrite = process.stdout.write;
beforeEach(() => {
  keyRecord = {
    id: 'key_1',
    userId: user.id,
    address,
    keyType: 'MANAGED',
    sealedBlob: 'sealed-private-key',
    sealingContext: null,
    archivedAt: null,
  };
  tee.getQuote.mockClear();
  unseal.mockClear();
  process.stdout.write = (() => true) as typeof process.stdout.write;
});
afterEach(() => { process.stdout.write = originalStdoutWrite; });

// Dynamic with a file-specific query so the route loads after mockModules (TC-928).
async function keysRouter() {
  return (await import('../routes/keys?keys-quote' as string)).keysRouter;
}

const nonce = 'a1'.repeat(16);

describe('GET /:keyId/quote (TC-1193)', () => {
  test('quotes the binding digest and returns the preimage for verifiers', async () => {
    const router = await keysRouter();
    const before = Date.now();

    const response = await router.request(`/key_1/quote?nonce=${nonce}`);

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(tee.getQuote).toHaveBeenCalledTimes(1);
    expect(tee.getQuote).toHaveBeenCalledWith(body.binding);
    // A verifier recomputes the digest from the exact preimage bytes.
    expect(body.bindingSha256).toBe(createHash('sha256').update(body.binding, 'utf8').digest('hex'));
    const binding = JSON.parse(body.binding);
    expect(Object.keys(binding)).toEqual(['type', 'version', 'nonce', 'address', 'timestamp']);
    expect(binding).toEqual({
      type: 'openkey.key-quote',
      version: 1,
      nonce,
      address,
      timestamp: expect.any(Number),
    });
    expect(binding.timestamp).toBeGreaterThanOrEqual(before);
    expect(body).toMatchObject({ quote: 'ab'.repeat(64), eventLog: '[{"imr":3}]', address, inTee: true });
  });

  test('binds a null nonce when the caller sends none', async () => {
    const router = await keysRouter();

    const response = await router.request('/key_1/quote');

    expect(response.status).toBe(200);
    expect(JSON.parse((await response.json()).binding).nonce).toBeNull();
  });

  test('refuses a nonce that is not 16-64 bytes of lowercase hex', async () => {
    const router = await keysRouter();
    for (const bad of ['a1'.repeat(15), 'a1'.repeat(65), 'A1'.repeat(16), `${'a1'.repeat(15)}zz`, '']) {
      const response = await router.request(`/key_1/quote?nonce=${bad}`);
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ error: 'invalid_nonce' });
    }
    expect(tee.getQuote).not.toHaveBeenCalled();
  });

  test('refuses to quote an external key, which the TEE does not hold', async () => {
    keyRecord = { ...keyRecord, keyType: 'EXTERNAL', sealedBlob: null };
    const router = await keysRouter();

    const response = await router.request('/key_1/quote');

    expect(response.status).toBe(400);
    expect(tee.getQuote).not.toHaveBeenCalled();
    expect(unseal).not.toHaveBeenCalled();
  });

  test('answers 503 without quoting when the sealed key is not the recorded address', async () => {
    unseal.mockImplementationOnce(async () => otherPrivateKey);
    const router = await keysRouter();

    const response = await router.request('/key_1/quote');

    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: 'quote_unavailable' });
    expect(tee.getQuote).not.toHaveBeenCalled();
  });

  test('answers 503 without a quote or inTee when quoting fails', async () => {
    tee.getQuote.mockImplementationOnce(async () => {
      throw new Error('Report data is too large, it should be less than 64 bytes.');
    });
    const router = await keysRouter();

    const response = await router.request('/key_1/quote');

    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: 'quote_unavailable' });
  });
});
