// TC-4082: an account whose bootstrap row is already `complete`. The row is only a hint. The publish reads the registry
// without the key, asks the node for a fresh 2xx on the account space (the real probe, stubbed node), and only then
// signs the canonical v1 record and PUTs it, once.

import { afterEach, beforeEach, describe, expect, mock, test } from 'bun:test';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { verifyLocationRecord } from '@tinycloud/sdk-core';
import { privateKeyToAccount } from 'viem/accounts';
import {
  OWNER_LOCATION_MEMO_MS,
  ensureOwnerLocationRecord,
  resetOwnerLocationMemoForTests,
} from '../services/owner-location-record';
import type { TinyCloudBootstrapOutcome } from '../services/tinycloud-bootstrap';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const account = privateKeyToAccount(privateKey);
const address = account.address;
const ACCOUNT_SPACE = `tinycloud:pkh:eip155:1:${address}:account`;
const DEFAULT_NODE = 'https://node.tinycloud.xyz';
const TEE_NODE = 'https://tee.node.tinycloud.xyz';
const NOT_FOUND = '{"error":"location record not found"}';
const V2_URL = `https://registry.tinycloud.xyz/v2/locations/${address}`;
const V1_URL = `https://registry.tinycloud.xyz/v1/locations/${encodeURIComponent(`did:pkh:eip155:1:${address}`)}`;

let probeAccountSpaceHosted: (input: {
  address: string;
  chainId: number;
  tinycloudHost: string;
  signMessage: (message: string) => Promise<string>;
}) => Promise<boolean>;
let ensureTinyCloudBootstrapForApprovedSign: (input: Record<string, unknown>) => Promise<TinyCloudBootstrapOutcome>;
let setExecutor: (executor?: () => Promise<void>) => void;
let setProbe: (probe?: () => Promise<void>) => void;
let TINYCLOUD_BOOTSTRAP_VERSION: string;

type Reply = Response | Error;
interface World {
  v2?: () => Reply;
  v1?: () => Reply;
  put?: () => Reply;
  delegate?: () => Reply;
  invoke?: () => Reply;
}
let events: string[] = [];
const originalFetch = globalThis.fetch;
const absent = () => new Response(NOT_FOUND, { status: 404 });
const created = () => new Response('{}', { status: 201 });
const delegated = () => new Response(JSON.stringify({ activated: [ACCOUNT_SPACE], skipped: [] }), { status: 200 });
const listed = () => new Response('[]', { status: 200 });
const HOSTED: World = { v2: absent, v1: absent, put: created, delegate: delegated, invoke: listed };

function stubWorld(world: World) {
  globalThis.fetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = String(input);
    const method = init.method ?? 'GET';
    const label = url === V2_URL ? 'GET v2' : url === V1_URL ? `${method} v1` : `${method} ${new URL(url).pathname}`;
    events.push(label);
    const make = {
      'GET v2': world.v2, 'GET v1': world.v1, 'PUT v1': world.put, 'POST /delegate': world.delegate, 'POST /invoke': world.invoke,
    }[label];
    if (!make) throw new Error(`unexpected request ${label}`);
    const reply = make();
    if (reply instanceof Error) throw reply;
    return reply;
  }) as typeof fetch;
}

const signMessage = async (message: string) => {
  events.push(message.startsWith('{') ? 'sign record' : 'sign probe');
  return account.signMessage({ message });
};

function publish(overrides: Partial<Parameters<typeof ensureOwnerLocationRecord>[0]> = {}) {
  return ensureOwnerLocationRecord({
    address: address.toLowerCase(),
    hostedHost: DEFAULT_NODE,
    signMessage,
    hosted: {
      kind: 'complete_row',
      probe: () => probeAccountSpaceHosted({ address, chainId: 1, tinycloudHost: DEFAULT_NODE, signMessage }),
    },
    ...overrides,
  });
}

beforeEach(async () => {
  ({
    probeAccountSpaceHosted,
    ensureTinyCloudBootstrapForApprovedSign,
    TINYCLOUD_BOOTSTRAP_VERSION,
    setTinyCloudBootstrapExecutorForTests: setExecutor,
    setTinyCloudBootstrapProbeForTests: setProbe,
  } = await import('../services/tinycloud-bootstrap.ts?owner-location-existing' as string));
  events = [];
  resetOwnerLocationMemoForTests();
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  delete process.env.TINYCLOUD_BOOTSTRAP_HOST;
  setExecutor();
  setProbe();
});

describe('an existing account publishes only after a fresh 2xx from the node', () => {
  test('registry reads, then the probe, then the record, then one PUT', async () => {
    stubWorld(HOSTED);
    let putBody = '';
    const inner = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
      if (init.method === 'PUT') putBody = String(init.body);
      return inner(input, init);
    }) as typeof fetch;

    expect(await publish()).toBe('published');

    expect(events).toEqual(['GET v2', 'GET v1', 'sign probe', 'POST /delegate', 'POST /invoke', 'sign record', 'PUT v1']);
    const record = JSON.parse(putBody);
    expect(record).toMatchObject({
      version: 1,
      subject: `did:pkh:eip155:1:${address}`,
      multiaddrs: ['/dns/node.tinycloud.xyz/tcp/443/tls/http'],
      sequence: 0,
    });
    expect(await verifyLocationRecord(record)).toBe(true);
  });

  const notHosted: Array<[string, World]> = [
    ['a 401 on the list', { ...HOSTED, invoke: () => new Response('{}', { status: 401 }) }],
    ['a 403 on the list', { ...HOSTED, invoke: () => new Response('{}', { status: 403 }) }],
    ['a 404 on the list', { ...HOSTED, invoke: () => new Response('{}', { status: 404 }) }],
    ['a 500 on the list', { ...HOSTED, invoke: () => new Response('{}', { status: 500 }) }],
    ['a 503 on the list', { ...HOSTED, invoke: () => new Response('{}', { status: 503 }) }],
    ['a timeout on the list', { ...HOSTED, invoke: () => new DOMException('timed out', 'TimeoutError') }],
    ['a 404 on /delegate', { ...HOSTED, delegate: () => new Response('{}', { status: 404 }) }],
    ['a 401 on /delegate', { ...HOSTED, delegate: () => new Response('{}', { status: 401 }) }],
    ['a 500 on /delegate', { ...HOSTED, delegate: () => new Response('{}', { status: 500 }) }],
    ['the space listed as skipped', {
      ...HOSTED,
      delegate: () => new Response(JSON.stringify({ activated: [], skipped: [ACCOUNT_SPACE] }), { status: 200 }),
    }],
  ];
  for (const [name, world] of notHosted) {
    test(`${name} skips: the record is never signed and nothing is PUT`, async () => {
      stubWorld(world);

      expect(await publish()).toBe('skipped_not_hosted');
      expect(events).not.toContain('sign record');
      expect(events).not.toContain('PUT v1');
    });
  }

  test('a probe that throws skips', async () => {
    stubWorld(HOSTED);
    const outcome = await publish({ hosted: { kind: 'complete_row', probe: async () => { throw new Error('boom'); } } });

    expect(outcome).toBe('skipped_not_hosted');
    expect(events).toEqual(['GET v2', 'GET v1']);
  });

  const registryAnswers: Array<[string, Partial<World>]> = [
    ['a v2 record', { v2: () => new Response('{"record":{}}', { status: 200 }) }],
    ['a v1 record', { v1: () => new Response('{"record":{}}', { status: 200 }) }],
    ['a v2 401', { v2: () => new Response('{}', { status: 401 }) }],
    ['a v1 403', { v1: () => new Response('{}', { status: 403 }) }],
    ['a v2 5xx', { v2: () => new Response('{}', { status: 503 }) }],
    ['a v1 non-canonical 404', { v1: () => new Response('nope', { status: 404 }) }],
  ];
  for (const [name, answer] of registryAnswers) {
    test(`${name} skips before any probe: no key use, no node call`, async () => {
      stubWorld({ ...HOSTED, ...answer });

      expect((await publish()).startsWith('skipped_registry_')).toBe(true);
      expect(events.every((event) => event.startsWith('GET '))).toBe(true);
      expect(events).not.toContain('sign probe');
    });
  }

  test('a row on any host but the default node never probes and never signs', async () => {
    stubWorld(HOSTED);
    const outcome = await publish({ hostedHost: TEE_NODE });

    expect(outcome).toBe('skipped_not_default_node');
    expect(events).toEqual([]);
  });

  test('a PUT refusal after the probe is final', async () => {
    for (const status of [400, 401, 409, 500]) {
      resetOwnerLocationMemoForTests();
      events = [];
      stubWorld({ ...HOSTED, put: () => new Response('{}', { status }) });

      expect(await publish()).toBe(`failed_${status}`);
      expect(events.filter((event) => event === 'PUT v1')).toHaveLength(1);
    }
  });
});

describe('the per-owner memo', () => {
  test('an owner looked at in the last five minutes is skipped, whatever the answer was; after five it is looked at again', async () => {
    let clock = new Date('2026-11-23T12:00:00.000Z');
    const now = () => clock;
    stubWorld({ ...HOSTED, invoke: () => new Response('{}', { status: 404 }) });

    expect(await publish({ now })).toBe('skipped_not_hosted');
    const firstRound = events.length;

    clock = new Date(clock.getTime() + OWNER_LOCATION_MEMO_MS - 1);
    expect(await publish({ now })).toBe('skipped_checked_recently');
    expect(events).toHaveLength(firstRound);

    clock = new Date(clock.getTime() + 2);
    stubWorld(HOSTED);
    expect(await publish({ now })).toBe('published');
  });

  test('is per owner', async () => {
    stubWorld({ ...HOSTED, v2: () => new Response('{"record":{}}', { status: 200 }) });
    expect(await publish()).toBe('skipped_registry_exists');
    // A second owner is not blocked by the first (a different address, same stubbed answers).
    const other = privateKeyToAccount('0x1111111111111111111111111111111111111111111111111111111111111111');
    globalThis.fetch = (async (_input: RequestInfo | URL) => new Response(JSON.stringify({ record: {} }), { status: 200 })) as typeof fetch;
    expect(await publish({ address: other.address })).toBe('skipped_registry_exists');
  });
});

describe('the bootstrap hook that starts it', () => {
  const key = { id: 'key_1', address, keyType: 'MANAGED' };
  let state: { id: string; status: string; attemptId?: string | null; lockExpiresAt?: Date | null; checkedAt?: Date } | null = null;
  let autoSignEnabled = true;
  const executor = mock(async () => undefined);
  const probe = mock(async () => undefined);
  const prisma = {
    user: { findUnique: mock(async () => ({ autoSignEnabled })) },
    tinyCloudBootstrapState: {
      findUnique: mock(async () => state),
      create: mock(async ({ data }: { data: NonNullable<typeof state> }) => {
        state = { ...data, id: 'state_1' };
        return state;
      }),
      updateMany: mock(async ({ where, data }: { where: Record<string, unknown>; data: Partial<NonNullable<typeof state>> }) => {
        if (!state || where.bootstrapVersion !== TINYCLOUD_BOOTSTRAP_VERSION) return { count: 0 };
        if (where.attemptId && where.attemptId !== state.attemptId) return { count: 0 };
        state = { ...state, ...data };
        return { count: 1 };
      }),
    },
  };

  const siwe = () => prepareSession({
    address,
    chainId: 1,
    domain: 'home.tinycloud.xyz',
    issuedAt: new Date().toISOString(),
    expirationTime: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    spaceId: ACCOUNT_SPACE,
    jwk: { kty: 'OKP', crv: 'Ed25519', x: 'test' },
    abilities: { capabilities: { capabilities: ['tinycloud.capabilities/read'] } },
  }).siwe;

  const run = (hooks: Record<string, unknown>) => ensureTinyCloudBootstrapForApprovedSign({
    prisma, userId: 'user_1', key, privateKey, message: siwe(), format: 'personal_sign', ...hooks,
  });

  beforeEach(() => {
    autoSignEnabled = true;
    state = { id: 'state_1', status: 'complete', attemptId: null, lockExpiresAt: null, checkedAt: new Date() };
    process.env.TINYCLOUD_BOOTSTRAP_HOST = DEFAULT_NODE;
    executor.mockClear();
    probe.mockClear();
    setExecutor(executor);
    setProbe(probe);
  });

  test('fires for a complete row, with the row\'s host, and runs no setup', async () => {
    const onAlreadyComplete = mock(() => undefined);
    const onFreshlyComplete = mock(() => undefined);

    expect(await run({ onAlreadyComplete, onFreshlyComplete })).toEqual({ status: 'complete' });

    expect(onAlreadyComplete).toHaveBeenCalledTimes(1);
    expect(onAlreadyComplete).toHaveBeenCalledWith({ host: DEFAULT_NODE, chainId: 1 });
    expect(onFreshlyComplete).not.toHaveBeenCalled();
    expect(probe).not.toHaveBeenCalled();
    expect(executor).not.toHaveBeenCalled();
  });

  test('does not fire inside a run that completes the setup, or with Auto-Sign off, or for a row that is not complete', async () => {
    const onAlreadyComplete = mock(() => undefined);

    state = null;
    await run({ onAlreadyComplete });
    autoSignEnabled = false;
    state = { id: 'state_1', status: 'complete', attemptId: null, lockExpiresAt: null, checkedAt: new Date() };
    await run({ onAlreadyComplete });
    autoSignEnabled = true;
    state = { id: 'state_1', status: 'failed', attemptId: null, lockExpiresAt: null, checkedAt: new Date() };
    await run({ onAlreadyComplete });

    expect(onAlreadyComplete).not.toHaveBeenCalled();
  });

  test('a hook that throws does not change the outcome', async () => {
    expect(await run({ onAlreadyComplete: () => { throw new Error('hook failed'); } })).toEqual({ status: 'complete' });
  });

  test('a stale complete row alone publishes nothing: the node says the space is not there', async () => {
    stubWorld({ ...HOSTED, delegate: () => new Response('{}', { status: 404 }) });
    let outcome: Promise<string> | undefined;

    await run({
      onAlreadyComplete: ({ host, chainId }: { host: string; chainId: number }) => {
        outcome = ensureOwnerLocationRecord({
          address,
          hostedHost: host,
          signMessage,
          hosted: { kind: 'complete_row', probe: () => probeAccountSpaceHosted({ address, chainId, tinycloudHost: host, signMessage }) },
        });
      },
    });

    expect(await outcome).toBe('skipped_not_hosted');
    expect(events).not.toContain('sign record');
    expect(events).not.toContain('PUT v1');
  });

  test('a complete row on the TEE host never reaches the node', async () => {
    process.env.TINYCLOUD_BOOTSTRAP_HOST = TEE_NODE;
    stubWorld(HOSTED);
    let outcome: Promise<string> | undefined;

    await run({
      onAlreadyComplete: ({ host, chainId }: { host: string; chainId: number }) => {
        outcome = ensureOwnerLocationRecord({
          address,
          hostedHost: host,
          signMessage,
          hosted: { kind: 'complete_row', probe: () => probeAccountSpaceHosted({ address, chainId, tinycloudHost: host, signMessage }) },
        });
      },
    });

    expect(await outcome).toBe('skipped_not_default_node');
    expect(events).toEqual([]);
  });
});
