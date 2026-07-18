import { afterEach, beforeEach, describe, expect, mock, test } from 'bun:test';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import type { TinyCloudBootstrapOutcome } from '../services/tinycloud-bootstrap';

const address = '0x31d40B62C395B9418C4198363619B11c65cD406F';
const chainId = 1;
const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const key = { id: 'key_1', address, keyType: 'MANAGED', keyPurpose: 'PERSONAL' as const };
const userId = 'user_1';
const tinycloudHost = 'https://tee.node.tinycloud.xyz';
const defaultTinycloudHost = 'https://node.tinycloud.xyz';
const originalNodeEnv = process.env.NODE_ENV;
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'test' };

let autoSignEnabled = true;
let state: {
  id: string;
  status: string;
  attemptId?: string | null;
  lockExpiresAt?: Date | null;
} | null = null;

const executor = mock(async () => undefined);
const probe = mock(async () => undefined);
type BootstrapHook = (input: {
  address: string;
  chainId: number;
  privateKey: string;
  tinycloudHost: string;
}) => Promise<void>;

let TINYCLOUD_BOOTSTRAP_VERSION: string;
let TinyCloudBootstrapError: new (...args: any[]) => Error;
let ensureTinyCloudBootstrapForApprovedSign: (input: any) => Promise<TinyCloudBootstrapOutcome>;
let setTinyCloudBootstrapExecutorForTests: (executor?: BootstrapHook) => void;
let setTinyCloudBootstrapProbeForTests: (probe?: BootstrapHook) => void;
let trustedTinyCloudBootstrapHost: () => string;

const prisma = {
  user: {
    findUnique: mock(async () => ({ autoSignEnabled })),
  },
  tinyCloudBootstrapState: {
    findUnique: mock(async () => state),
    create: mock(async ({ data }: { data: typeof state }) => {
      state = { ...data!, id: 'state_1' };
      return state;
    }),
    update: mock(async () => {
      throw new Error('update should not be called');
    }),
    updateMany: mock(async ({ where, data }: { where: Record<string, unknown>; data: Partial<NonNullable<typeof state>> }) => {
      if (!state || where.keyId !== key.id || where.chainId !== chainId || where.tinycloudHost !== tinycloudHost) {
        return { count: 0 };
      }
      if (where.bootstrapVersion !== TINYCLOUD_BOOTSTRAP_VERSION) {
        return { count: 0 };
      }
      if (where.attemptId && where.attemptId !== state.attemptId) {
        return { count: 0 };
      }
      state = { ...state, ...data };
      return { count: 1 };
    }),
  },
};

beforeEach(async () => {
  ({
    TINYCLOUD_BOOTSTRAP_VERSION,
    TinyCloudBootstrapError,
    ensureTinyCloudBootstrapForApprovedSign,
    setTinyCloudBootstrapExecutorForTests,
    setTinyCloudBootstrapProbeForTests,
    trustedTinyCloudBootstrapHost,
  } = await import('../services/tinycloud-bootstrap.ts?actual' as string));
  autoSignEnabled = true;
  state = null;
  process.env.NODE_ENV = originalNodeEnv;
  process.env.TINYCLOUD_BOOTSTRAP_HOST = tinycloudHost;
  executor.mockClear();
  probe.mockClear();
  prisma.user.findUnique.mockClear();
  prisma.tinyCloudBootstrapState.findUnique.mockClear();
  prisma.tinyCloudBootstrapState.create.mockClear();
  prisma.tinyCloudBootstrapState.update.mockClear();
  prisma.tinyCloudBootstrapState.updateMany.mockClear();
  setTinyCloudBootstrapExecutorForTests(executor);
  setTinyCloudBootstrapProbeForTests(probe);
});

afterEach(() => {
  delete process.env.TINYCLOUD_BOOTSTRAP_HOST;
  process.env.NODE_ENV = originalNodeEnv;
  setTinyCloudBootstrapExecutorForTests();
  setTinyCloudBootstrapProbeForTests();
});

function approvedTinyCloudSiwe() {
  return tinyCloudSiwe({ chainId, expirationTime: new Date(Date.now() + 60 * 60 * 1000).toISOString() });
}

function tinyCloudSiwe(options: {
  chainId: number;
  expirationTime: string;
  spaceName?: string;
  abilities?: Record<string, Record<string, string[]>>;
}) {
  const spaceName = options.spaceName ?? 'account';
  return prepareSession({
    address,
    chainId: options.chainId,
    domain: 'listen.tinycloud.xyz',
    issuedAt: new Date().toISOString(),
    expirationTime: options.expirationTime,
    spaceId: `tinycloud:pkh:eip155:${options.chainId}:${address}:${spaceName}`,
    jwk,
    abilities: options.abilities ?? {
      capabilities: {
        'capabilities': ['tinycloud.capabilities/read'],
      },
    },
  }).siwe;
}

function ensureInput(message = approvedTinyCloudSiwe(), format: 'raw' | 'personal_sign' = 'personal_sign') {
  return {
    prisma,
    userId,
    key,
    privateKey,
    message,
    format,
  };
}

describe('ensureTinyCloudBootstrapForApprovedSign', () => {
  test('defaults to the public TinyCloud node host', () => {
    delete process.env.TINYCLOUD_BOOTSTRAP_HOST;

    expect(trustedTinyCloudBootstrapHost()).toBe(defaultTinycloudHost);
  });

  test('trusts the direct TinyCloud TEE host in production', () => {
    process.env.NODE_ENV = 'production';
    process.env.TINYCLOUD_BOOTSTRAP_HOST = tinycloudHost;

    expect(trustedTinyCloudBootstrapHost()).toBe(tinycloudHost);
  });

  test('only trusts the production TinyCloud host in production', () => {
    process.env.NODE_ENV = 'production';
    process.env.TINYCLOUD_BOOTSTRAP_HOST = 'https://evil.example';

    expect(() => trustedTinyCloudBootstrapHost()).toThrow(TinyCloudBootstrapError);
  });

  test('rejects malformed bootstrap host configuration with a structured error', () => {
    process.env.NODE_ENV = 'production';
    process.env.TINYCLOUD_BOOTSTRAP_HOST = 'not a url';

    expect(() => trustedTinyCloudBootstrapHost()).toThrow(TinyCloudBootstrapError);
  });

  test('allows localhost bootstrap hosts outside production for local node validation', () => {
    process.env.NODE_ENV = 'test';
    process.env.TINYCLOUD_BOOTSTRAP_HOST = 'http://127.0.0.1:49152/';

    expect(trustedTinyCloudBootstrapHost()).toBe('http://127.0.0.1:49152');
  });

  test('does not bootstrap raw ETH signatures', async () => {
    await ensureTinyCloudBootstrapForApprovedSign(ensureInput(approvedTinyCloudSiwe(), 'raw'));

    expect(executor).not.toHaveBeenCalled();
    expect(probe).not.toHaveBeenCalled();
    expect(prisma.user.findUnique).not.toHaveBeenCalled();
    expect(prisma.tinyCloudBootstrapState.findUnique).not.toHaveBeenCalled();
  });

  test('kill-switch TINYCLOUD_BOOTSTRAP_ON_SIGN=off skips the hook entirely', async () => {
    process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN = 'off';
    try {
      const outcome = await ensureTinyCloudBootstrapForApprovedSign(
        ensureInput(approvedTinyCloudSiwe()),
      );

      expect(outcome).toEqual({ status: 'skipped' });
      expect(executor).not.toHaveBeenCalled();
      expect(prisma.user.findUnique).not.toHaveBeenCalled();
    } finally {
      delete process.env.TINYCLOUD_BOOTSTRAP_ON_SIGN;
    }
  });

  test('does not apply bootstrap expiry rejection when auto-sign is disabled', async () => {
    autoSignEnabled = false;
    const expiredMessage = tinyCloudSiwe({
      chainId,
      expirationTime: new Date(Date.now() - 60_000).toISOString(),
    });

    await ensureTinyCloudBootstrapForApprovedSign(ensureInput(expiredMessage));

    expect(executor).not.toHaveBeenCalled();
    expect(probe).not.toHaveBeenCalled();
    expect(prisma.tinyCloudBootstrapState.findUnique).not.toHaveBeenCalled();
  });

  test('does not bootstrap unsupported TinyCloud chains', async () => {
    const unsupportedChainMessage = tinyCloudSiwe({
      chainId: 11155111,
      expirationTime: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    });

    await ensureTinyCloudBootstrapForApprovedSign(ensureInput(unsupportedChainMessage));

    expect(prisma.user.findUnique).not.toHaveBeenCalled();
    expect(executor).not.toHaveBeenCalled();
    expect(probe).not.toHaveBeenCalled();
    expect(prisma.tinyCloudBootstrapState.findUnique).not.toHaveBeenCalled();
  });

  test('does not bootstrap arbitrary signer-owned TinyCloud app resources', async () => {
    const appMessage = tinyCloudSiwe({
      chainId,
      expirationTime: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      spaceName: 'randomapp',
      abilities: {
        kv: {
          'data/': ['tinycloud.kv/get'],
        },
      },
    });

    await ensureTinyCloudBootstrapForApprovedSign(ensureInput(appMessage));

    expect(prisma.user.findUnique).not.toHaveBeenCalled();
    expect(executor).not.toHaveBeenCalled();
    expect(probe).not.toHaveBeenCalled();
    expect(prisma.tinyCloudBootstrapState.findUnique).not.toHaveBeenCalled();
  });

  test('does not bootstrap when auto-sign is disabled', async () => {
    autoSignEnabled = false;

    await ensureTinyCloudBootstrapForApprovedSign(ensureInput());

    expect(executor).not.toHaveBeenCalled();
    expect(probe).not.toHaveBeenCalled();
    expect(prisma.tinyCloudBootstrapState.findUnique).not.toHaveBeenCalled();
  });

  test('uses the complete cache without running bootstrap again', async () => {
    state = { id: 'state_1', status: 'complete' };

    const outcome = await ensureTinyCloudBootstrapForApprovedSign(ensureInput());

    expect(outcome).toEqual({ status: 'complete' });
    expect(executor).not.toHaveBeenCalled();
    expect(probe).not.toHaveBeenCalled();
    expect(prisma.tinyCloudBootstrapState.create).not.toHaveBeenCalled();
    expect(prisma.tinyCloudBootstrapState.updateMany).not.toHaveBeenCalled();
  });

  test('creates a cache row, bootstraps, and marks the key complete', async () => {
    const outcome = await ensureTinyCloudBootstrapForApprovedSign(ensureInput());

    expect(outcome).toEqual({ status: 'complete' });
    expect(prisma.tinyCloudBootstrapState.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        keyId: key.id,
        chainId,
        tinycloudHost,
        bootstrapVersion: TINYCLOUD_BOOTSTRAP_VERSION,
        userId,
        address,
        status: 'in_progress',
      }),
    });
    expect(probe).toHaveBeenCalledWith({
      address,
      chainId,
      privateKey,
      tinycloudHost,
    });
    expect(executor).toHaveBeenCalledWith({
      address,
      chainId,
      privateKey,
      tinycloudHost,
    });
    expect(state).toMatchObject({
      status: 'complete',
      attemptId: null,
      lockExpiresAt: null,
      failureCode: null,
      failureReason: null,
    });
  });

  test('returns a failed outcome when another bootstrap attempt owns the fresh lock', async () => {
    state = {
      id: 'state_1',
      status: 'in_progress',
      attemptId: 'attempt_1',
      lockExpiresAt: new Date(Date.now() + 60_000),
    };

    const outcome = await ensureTinyCloudBootstrapForApprovedSign(ensureInput());

    expect(outcome).toEqual({
      status: 'failed',
      errorCode: 'tinycloud_bootstrap_in_progress',
      errorMessage: 'TinyCloud account bootstrap is already in progress for this key.',
    });
    expect(executor).not.toHaveBeenCalled();
    expect(probe).not.toHaveBeenCalled();
    expect(prisma.tinyCloudBootstrapState.updateMany).not.toHaveBeenCalled();
  });

  test('returns a failed outcome when the bootstrap executor throws', async () => {
    executor.mockImplementationOnce(async () => {
      throw new Error('node unreachable');
    });

    const outcome = await ensureTinyCloudBootstrapForApprovedSign(ensureInput());

    expect(outcome).toEqual({
      status: 'failed',
      errorCode: 'tinycloud_bootstrap_failed',
      errorMessage: 'node unreachable',
    });
    expect(state).toMatchObject({ status: 'failed', failureCode: 'tinycloud_bootstrap_failed' });
  });

  test('returns a skipped outcome when auto-sign is disabled', async () => {
    autoSignEnabled = false;

    const outcome = await ensureTinyCloudBootstrapForApprovedSign(ensureInput());

    expect(outcome).toEqual({ status: 'skipped' });
    expect(executor).not.toHaveBeenCalled();
    expect(probe).not.toHaveBeenCalled();
  });
});
