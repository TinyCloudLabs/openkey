// TC-4082: the bootstrap's `onFreshlyComplete` hook is the affirmative hosted signal for the owner-location publish.
// It fires only when this run moved the row to `complete` (probe and bootstrap both succeeded), and only past the
// Auto-Sign check. A `complete` row that was already there, a failed run and an Auto-Sign-off account never fire it.

import { afterEach, beforeEach, describe, expect, mock, test } from 'bun:test';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import type { TinyCloudBootstrapOutcome } from '../services/tinycloud-bootstrap';

const address = '0x31d40B62C395B9418C4198363619B11c65cD406F';
const chainId = 1;
const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const key = { id: 'key_1', address, keyType: 'MANAGED' };
const defaultHost = 'https://node.tinycloud.xyz';
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'test' };

interface Row {
  id: string;
  status: string;
  attemptId?: string | null;
  lockExpiresAt?: Date | null;
  failureReason?: string | null;
  checkedAt?: Date;
}
let state: Row | null = null;
let autoSignEnabled = true;
let TINYCLOUD_BOOTSTRAP_VERSION: string;

const executor = mock(async () => undefined);
const probe = mock(async () => undefined);
type Hook = (input: { address: string; chainId: number; privateKey: string; tinycloudHost: string }) => Promise<void>;
let ensureTinyCloudBootstrapForApprovedSign: (input: Record<string, unknown>) => Promise<TinyCloudBootstrapOutcome>;
let setExecutor: (executor?: Hook) => void;
let setProbe: (probe?: Hook) => void;

const prisma = {
  user: { findUnique: mock(async () => ({ autoSignEnabled })) },
  tinyCloudBootstrapState: {
    findUnique: mock(async () => state),
    create: mock(async ({ data }: { data: Row }) => {
      if (state) throw Object.assign(new Error('Unique constraint failed'), { code: 'P2002' });
      state = { ...data, id: 'state_1' };
      return state;
    }),
    updateMany: mock(async ({ where, data }: { where: Record<string, unknown>; data: Partial<Row> }) => {
      if (!state || where.bootstrapVersion !== TINYCLOUD_BOOTSTRAP_VERSION) return { count: 0 };
      if (where.attemptId && where.attemptId !== state.attemptId) return { count: 0 };
      state = { ...state, ...data };
      return { count: 1 };
    }),
  },
};

beforeEach(async () => {
  ({
    TINYCLOUD_BOOTSTRAP_VERSION,
    ensureTinyCloudBootstrapForApprovedSign,
    setTinyCloudBootstrapExecutorForTests: setExecutor,
    setTinyCloudBootstrapProbeForTests: setProbe,
  } = await import('../services/tinycloud-bootstrap.ts?owner-location-hook' as string));
  autoSignEnabled = true;
  state = null;
  process.env.TINYCLOUD_BOOTSTRAP_HOST = defaultHost;
  executor.mockClear();
  probe.mockClear();
  setExecutor(executor);
  setProbe(probe);
});

afterEach(() => {
  delete process.env.TINYCLOUD_BOOTSTRAP_HOST;
  setExecutor();
  setProbe();
});

function siwe(): string {
  return prepareSession({
    address,
    chainId,
    domain: 'home.tinycloud.xyz',
    issuedAt: new Date().toISOString(),
    expirationTime: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    spaceId: `tinycloud:pkh:eip155:${chainId}:${address}:account`,
    jwk,
    abilities: { capabilities: { capabilities: ['tinycloud.capabilities/read'] } },
  }).siwe;
}

const run = (onFreshlyComplete: unknown) =>
  ensureTinyCloudBootstrapForApprovedSign({
    prisma, userId: 'user_1', key, privateKey, message: siwe(), format: 'personal_sign', onFreshlyComplete,
  });

describe('onFreshlyComplete', () => {
  test('fires once when this run completes the setup, after the row is complete and the probe and bootstrap ran', async () => {
    const seen: Array<{ event: unknown; status: string | undefined }> = [];
    const outcome = await run((event: unknown) => seen.push({ event, status: state?.status }));

    expect(outcome).toEqual({ status: 'complete' });
    expect(probe).toHaveBeenCalledTimes(1);
    expect(executor).toHaveBeenCalledTimes(1);
    expect(seen).toEqual([{ event: { host: defaultHost, chainId }, status: 'complete' }]);
  });

  test('reports the host the run used, so a run on any other host is not mistaken for the default node', async () => {
    process.env.TINYCLOUD_BOOTSTRAP_HOST = 'https://tee.node.tinycloud.xyz';
    state = null;
    const hook = mock(() => undefined);
    await run(hook);

    expect(hook).toHaveBeenCalledTimes(1);
    expect(hook).toHaveBeenCalledWith({ host: 'https://tee.node.tinycloud.xyz', chainId });
  });

  test('does not fire for a complete row that was already there', async () => {
    state = { id: 'state_1', status: 'complete', attemptId: null, lockExpiresAt: null, checkedAt: new Date() };
    const hook = mock(() => undefined);

    expect(await run(hook)).toEqual({ status: 'complete' });
    expect(hook).not.toHaveBeenCalled();
    expect(probe).not.toHaveBeenCalled();
  });

  test('does not fire when Auto-Sign is off', async () => {
    autoSignEnabled = false;
    const hook = mock(() => undefined);

    expect(await run(hook)).toEqual({ status: 'skipped' });
    expect(hook).not.toHaveBeenCalled();
    expect(state).toBeNull();
  });

  test('does not fire when the probe or the bootstrap fails', async () => {
    const hook = mock(() => undefined);
    probe.mockImplementationOnce(async () => { throw new Error('node unreachable'); });
    expect((await run(hook)).status).toBe('failed');

    state = null;
    executor.mockImplementationOnce(async () => { throw new Error('host refused'); });
    expect((await run(hook)).status).toBe('failed');
    expect(hook).not.toHaveBeenCalled();
  });

  test('a hook that throws does not fail the completed setup', async () => {
    const outcome = await run(() => { throw new Error('hook failed'); });

    expect(outcome).toEqual({ status: 'complete' });
    expect(state?.status).toBe('complete');
  });
});
