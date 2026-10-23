import { afterAll, afterEach, beforeEach, describe, expect, mock, spyOn, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { verifyMessage } from 'viem';
import { SiweMessage } from 'siwe';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import type { TinyCloudBootstrapOutcome } from '../services/tinycloud-bootstrap';
import { mockModules, replaceModules } from './mock-module';

// Keep the bootstrap sync budget short so the pending-path test is fast.
// The shared helper reads this per request. Restored afterwards: other files
// in the same `bun test` run read it.
const originalSyncBudget = process.env.TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS;
process.env.TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS = '75';
afterAll(() => {
  if (originalSyncBudget === undefined) delete process.env.TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS;
  else process.env.TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS = originalSyncBudget;
});

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const user = { id: 'user_1', email: 'test@example.com' };

const logOutput: string[] = [];
const originalStdoutWrite = process.stdout.write;
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
const ensureTinyCloudBootstrapForApprovedSign = mock(async (): Promise<TinyCloudBootstrapOutcome> => {
  calls.push('bootstrap');
  return { status: 'complete' as const };
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

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', user);
      c.set('session', {
        id: 'session_1',
        userId: user.id,
        expiresAt: new Date(Date.now() + 60_000),
      });
      await next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({
    createPrismaClient: () => prisma,
  }),
  '@openkey/tee': () => ({
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
  }),
  '../services/tinycloud-bootstrap': () => ({
    ensureTinyCloudBootstrapForApprovedSign,
  }),
});

beforeEach(() => {
  logOutput.length = 0;
  process.stdout.write = ((chunk: string | Uint8Array) => { logOutput.push(String(chunk)); return true; }) as typeof process.stdout.write;
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

afterEach(() => { process.stdout.write = originalStdoutWrite; });

async function keysRouter() {
  return (await import('../routes/keys?keys-sign' as string)).keysRouter;
}

function delegationSiwe(path: string, action: string): string {
  const now = new Date();
  return prepareSession({
    address,
    chainId: 1,
    domain: 'cli.tinycloud.xyz',
    issuedAt: now.toISOString(),
    expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
    spaceId: `tinycloud:pkh:eip155:1:${address}:default`,
    jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
    abilities: { delegation: { [path]: [action] } },
  }).siwe;
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

  test.each([
    ['revoke', 'tinycloud.delegation/revoke'],
    ['wildcard', 'tinycloud.delegation/*'],
  ])('POST /:keyId/sign refuses space-root %s authority before unsealing', async (_name, action) => {
    const router = await keysRouter();
    const response = await router.request('/key_1/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: delegationSiwe('', action) }),
    });
    expect(response.status).toBe(400);
    expect((await response.json() as { code?: string }).code).toBe('REVOKE_GRANT_DISABLED');
    expect(unseal).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  test.each([
    ['hex raw', (siwe: string) => ({ message: `0x${Buffer.from(siwe, 'utf8').toString('hex')}`, format: 'raw' })],
    ['raw object', (siwe: string) => ({ message: { raw: `0x${Buffer.from(siwe, 'utf8').toString('hex')}` } })],
  ])('POST /:keyId/sign cannot sign root authority via %s', async (_name, request) => {
    const router = await keysRouter();
    const response = await router.request('/key_1/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(request(delegationSiwe('', 'tinycloud.delegation/revoke'))),
    });
    expect(response.status).toBe(400);
    expect(unseal).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  test('POST /:keyId/sign still signs ordinary raw bytes', async () => {
    const router = await keysRouter();
    const response = await router.request('/key_1/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: '0x68656c6c6f', format: 'raw' }),
    });
    expect(response.status).toBe(200);
    const body = await response.json() as { signature: string };
    expect(body.signature).toBe(await account.signMessage({ message: { raw: '0x68656c6c6f' } }));
    expect(calls).toEqual(['bootstrap', 'sign']);
  });

  test('POST /:keyId/sign still signs a resource-scoped revocation request', async () => {
    const router = await keysRouter();
    const response = await router.request('/key_1/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: delegationSiwe('grants/specific-grant', 'tinycloud.delegation/revoke') }),
    });
    expect(response.status).toBe(200);
    expect(calls).toEqual(['bootstrap', 'sign']);
  });

  test('POST /:keyId/sign signs an owner revocation bound to one CID', async () => {
    const now = new Date();
    const message = new SiweMessage({
      domain: 'account.tinycloud.xyz',
      address,
      uri: 'ucan:bafkreicidexample',
      version: '1',
      chainId: 1,
      nonce: 'abcdefgh',
      issuedAt: now.toISOString(),
      expirationTime: new Date(now.getTime() + 60_000).toISOString(),
    }).prepareMessage();
    const router = await keysRouter();
    const response = await router.request('/key_1/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message }),
    });
    expect(response.status).toBe(200);
    const body = await response.json() as { signature: `0x${string}` };
    expect(await verifyMessage({ address, message, signature: body.signature })).toBe(true);
    expect(calls).toEqual(['bootstrap', 'sign']);
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

  test('POST /:keyId/sign refuses a deviceTransactionId it cannot enforce, before unsealing', async () => {
    const router = await keysRouter();

    const response = await router.request('/key_1/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'hello', deviceTransactionId: 'unknown-transaction' }),
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({ code: 'device_transaction_unsupported' });
    expect(unseal).not.toHaveBeenCalled();
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
    const line = JSON.parse(logOutput[0]!);
    expect(line).toMatchObject({ level: 'error', event: 'tinycloud_bootstrap_failed', error_code: 'tinycloud_bootstrap_failed', request_id: 'startup' });
    expect(Object.keys(line).sort()).toEqual(['error_code', 'event', 'level', 'request_id', 'ts']);
  });

  test('POST /:keyId/sign still signs when bootstrap rejects before the budget', async () => {
    ensureTinyCloudBootstrapForApprovedSign.mockImplementationOnce(async () => {
      calls.push('bootstrap');
      throw new Error('database unavailable');
    });
    const router = await keysRouter();
    const response = await router.request('/key_1/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'hello' }),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      signature: expect.stringMatching(/^0x[0-9a-f]+$/i),
      address,
      format: 'personal_sign',
      tinycloudBootstrap: { status: 'failed', errorCode: 'tinycloud_bootstrap_crashed' },
    });
    expect(calls).toEqual(['bootstrap', 'sign']);
    const line = JSON.parse(logOutput[0]!);
    expect(line).toMatchObject({ level: 'error', event: 'tinycloud_bootstrap_failed', error_code: 'tinycloud_bootstrap_crashed', request_id: 'startup' });
    expect(Object.keys(line).sort()).toEqual(['error_code', 'event', 'level', 'request_id', 'ts']);
  });
  test('POST /:keyId/sign emits only allowlisted fields on background rejection', async () => {
    let resolveBootstrap!: (outcome: TinyCloudBootstrapOutcome) => void;
    let rejectBootstrap!: (error: Error) => void;
    const bootstrap = new Promise<TinyCloudBootstrapOutcome>((resolve, reject) => {
      resolveBootstrap = resolve;
      rejectBootstrap = reject;
    });
    ensureTinyCloudBootstrapForApprovedSign.mockImplementationOnce(() => bootstrap);
    const unhandled = mock(() => {});
    process.on('unhandledRejection', unhandled);
    try {
      const router = await keysRouter();
      const response = await router.request('/key_1/sign', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ message: 'hello' }),
      });
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({
        signature: expect.stringMatching(/^0x[0-9a-f]+$/i),
        tinycloudBootstrap: { status: 'pending' },
      });
      rejectBootstrap(new Error('background database failure'));
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(unhandled).not.toHaveBeenCalled();
      expect(logOutput).toHaveLength(1);
      const line = JSON.parse(logOutput[0]!);
      expect(line).toMatchObject({ level: 'error', event: 'tinycloud_bootstrap_background_failed', error_code: 'tinycloud_bootstrap_crashed', request_id: 'startup' });
      expect(Object.keys(line).sort()).toEqual(['attempt', 'duration_ms', 'error_code', 'event', 'level', 'request_id', 'ts']);
      expect(logOutput.join('\n')).not.toContain('privateKey');
      expect(logOutput.join('\n')).not.toContain(privateKey);
      expect(logOutput.join('\n')).not.toContain(keyRecord.sealedBlob!);
    } finally {
      resolveBootstrap({ status: 'complete' });
      await new Promise((resolve) => setTimeout(resolve, 0));
      process.off('unhandledRejection', unhandled);
    }
  });

  for (const [configured, expectedMs] of [['125', 125], [undefined, 2500]] as const) {
    test(`POST /:keyId/sign schedules the ${configured === undefined ? 'default' : 'configured'} ${expectedMs} ms bootstrap budget`, async () => {
      const savedBudget = process.env.TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS;
      if (configured === undefined) delete process.env.TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS;
      else process.env.TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS = configured;
      const router = await keysRouter();
      let resolveBootstrap!: (outcome: TinyCloudBootstrapOutcome) => void;
      const bootstrap = new Promise<TinyCloudBootstrapOutcome>((resolve) => { resolveBootstrap = resolve; });
      ensureTinyCloudBootstrapForApprovedSign.mockImplementationOnce(() => bootstrap);
      const timer = spyOn(globalThis, 'setTimeout');
      const request = router.request('/key_1/sign', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ message: 'hello' }),
      });
      try {
        // An asynchronous bootstrap should complete before either budget, but not a forced 0 ms budget.
        await new Promise((resolve) => setTimeout(resolve, 20));
        resolveBootstrap({ status: 'complete' });
        const response = await request;
        expect(response.status).toBe(200);
        expect(await response.json()).toMatchObject({ tinycloudBootstrap: { status: 'complete' } });
        expect(timer).toHaveBeenCalledWith(expect.any(Function), expectedMs);
      } finally {
        resolveBootstrap({ status: 'complete' });
        await request;
        await new Promise((resolve) => setTimeout(resolve, 0));
        timer.mockRestore();
        if (savedBudget === undefined) delete process.env.TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS;
        else process.env.TINYCLOUD_BOOTSTRAP_SYNC_BUDGET_MS = savedBudget;
      }
    });
  }

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
  describe('TC-1486 SIWE origin guard', () => {
    const siwe = (domain: string, uri: string) => [
      `${domain} wants you to sign in with your Ethereum account:`,
      address,
      '',
      'Sign in',
      '',
      `URI: ${uri}`,
      'Version: 1',
      'Chain ID: 1',
      'Nonce: abcdef12345678',
      'Issued At: 2026-10-19T00:00:00.000Z',
    ].join('\n');
    const internal = 'https://internal.tinycloud.xyz';
    const hex = (text: string) => `0x${Buffer.from(text, 'utf8').toString('hex')}`;

    async function sign(body: Record<string, unknown>) {
      const router = await keysRouter();
      return router.request('/key_1/sign', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
    }

    function expectNothingSigned() {
      expect(calls).toEqual([]);
      expect(unseal).not.toHaveBeenCalled();
      expect(ensureTinyCloudBootstrapForApprovedSign).not.toHaveBeenCalled();
    }

    test('a SIWE naming the requesting origin signs', async () => {
      const response = await sign({ message: siwe('internal.tinycloud.xyz', internal), requestOrigin: internal });
      expect(response.status).toBe(200);
      expect(calls).toEqual(['bootstrap', 'sign']);
    });

    test('a mismatched domain is refused before the key is unsealed', async () => {
      const response = await sign({ message: siwe('internal.tinycloud.xyz', internal), requestOrigin: 'https://evil.example' });
      expect(response.status).toBe(403);
      await expect(response.json()).resolves.toMatchObject({ code: 'siwe_origin_refused', reason: 'domain-mismatch' });
      expectNothingSigned();
    });

    test('a mismatched URI with a matching domain is refused', async () => {
      const response = await sign({ message: siwe('internal.tinycloud.xyz', 'https://evil.example'), requestOrigin: internal });
      expect(response.status).toBe(403);
      await expect(response.json()).resolves.toMatchObject({ reason: 'uri-mismatch' });
      expectNothingSigned();
    });

    test('a SIWE with no verified origin is refused', async () => {
      for (const requestOrigin of [undefined, '*', '']) {
        const response = await sign({ message: siwe('internal.tinycloud.xyz', internal), requestOrigin });
        expect(response.status).toBe(403);
        await expect(response.json()).resolves.toMatchObject({ reason: 'unattributed-origin' });
      }
      expectNothingSigned();
    });

    test('SIWE text hidden in a hex message is refused for both formats', async () => {
      const message = hex(siwe('internal.tinycloud.xyz', internal));
      for (const format of ['raw', 'personal_sign']) {
        const response = await sign({ message, format, requestOrigin: 'https://evil.example' });
        expect(response.status).toBe(403);
      }
      expectNothingSigned();
    });

    test('a non-string message is rejected with 400 before anything is unsealed', async () => {
      for (const message of [[104, 105], { raw: hex(siwe('internal.tinycloud.xyz', internal)) }, 5, null]) {
        for (const format of ['raw', 'personal_sign']) {
          const response = await sign({ message, format, requestOrigin: internal });
          expect(response.status).toBe(400);
        }
      }
      expectNothingSigned();
    });

    test('raw input that is not even-length 0x hex is rejected with 400', async () => {
      for (const message of ['hello', '0xabc', '0xzz']) {
        const response = await sign({ message, format: 'raw' });
        expect(response.status).toBe(400);
      }
      expectNothingSigned();
    });

    test('valid 0x hex of a foreign-domain SIWE is refused as raw', async () => {
      const response = await sign({ message: hex(siwe('internal.tinycloud.xyz', internal)), format: 'raw', requestOrigin: 'https://evil.example' });
      expect(response.status).toBe(403);
      expectNothingSigned();
    });

    test('a ucan: URI SIWE signs when the domain matches and is refused when it does not', async () => {
      const message = siwe('account.tinycloud.xyz', 'ucan:bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgzz7nazxe');
      const ok = await sign({ message, requestOrigin: 'https://account.tinycloud.xyz' });
      expect(ok.status).toBe(200);
      calls.length = 0;
      const refused = await sign({ message, requestOrigin: 'https://evil.example' });
      expect(refused.status).toBe(403);
      await expect(refused.json()).resolves.toMatchObject({ reason: 'domain-mismatch' });
    });

    test('a web origin cannot claim openkey.so', async () => {
      const message = siwe('openkey.so', 'did:key:z6Mk');
      const response = await sign({ message, requestOrigin: 'https://attacker.example' });
      expect(response.status).toBe(403);
      await expect(response.json()).resolves.toMatchObject({ reason: 'domain-mismatch' });
      expectNothingSigned();
    });

    test('a non-SIWE message signs without any origin', async () => {
      const response = await sign({ message: 'just a plain message' });
      expect(response.status).toBe(200);
      expect(calls).toEqual(['bootstrap', 'sign']);
    });
  });

  describe('POST /:keyId/sign-typed-data', () => {
    const typedData = (valueType: string) => ({
      domain: { name: 'Test', version: '1', chainId: 1 },
      types: { Transfer: [{ name: 'amount', type: valueType }] },
      primaryType: 'Transfer',
      message: { amount: '1' },
    });
    const signTyped = async (body: unknown) => (await keysRouter()).request('/key_1/sign-typed-data', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });

    test('signs a canonical uint256 type', async () => {
      const response = await signTyped(typedData('uint256'));
      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toMatchObject({ signature: expect.stringMatching(/^0x[0-9a-f]+$/i), address });
    });

    test('returns 400, before unsealing, for a uint alias viem rejects', async () => {
      const response = await signTyped(typedData('uint'));
      expect(response.status).toBe(400);
      await expect(response.json()).resolves.toMatchObject({ error: expect.stringContaining('Invalid typed data') });
      expect(unseal).not.toHaveBeenCalled();
    });
  });
});
