import { describe, expect, test } from 'bun:test';
import { bootstrapSteps, KV } from '@tinycloud/bootstrap';
import {
  kvSpaceRegistryStore,
  registerMissingBootstrapSpaces,
  type BootstrapSpaceRef,
  type SpaceIndexRow,
  type SpaceRegistryStore,
} from '../services/tinycloud-space-registry';

const address = '0x31d40B62C395B9418C4198363619B11c65cD406F';
const ownerDid = `did:pkh:eip155:1:${address}`;
const now = '2026-10-09T12:00:00.000Z';
const seedStep = bootstrapSteps(address, 1).find((step) => step.kind === 'seed-spaces');
if (!seedStep) throw new Error('bootstrap package does not include seed-spaces');
const spaces: readonly BootstrapSpaceRef[] = seedStep.spaces;

function key(space: BootstrapSpaceRef) {
  return `spaces/${space.spaceId}`;
}

function body(space: BootstrapSpaceRef, values: Record<string, unknown> = {}) {
  return JSON.stringify({
    space_id: space.spaceId,
    name: space.name,
    owner_did: ownerDid,
    type: 'owned',
    permissions: ['*'],
    status: 'active',
    registered_at: now,
    updated_at: now,
    ...values,
  });
}

function memoryStore(initial: Record<string, string> = {}) {
  const records = new Map(Object.entries(initial));
  const calls: Array<{ op: string; key?: string; body?: string }> = [];
  const indexes: SpaceIndexRow[][] = [];
  let readFault: ((key: string, count: number) => unknown) | undefined;
  let createFault: ((key: string, value: string) => unknown) | undefined;
  let reads = 0;
  let indexFault: unknown;
  const store: SpaceRegistryStore = {
    async read(recordKey) {
      calls.push({ op: 'read', key: recordKey });
      reads += 1;
      const fault = readFault?.(recordKey, reads);
      if (fault) throw fault;
      const record = records.get(recordKey);
      return record === undefined ? { found: false } : { found: true, body: record };
    },
    async createOnly(recordKey, value) {
      calls.push({ op: 'createOnly', key: recordKey, body: value });
      const fault = createFault?.(recordKey, value);
      if (fault) throw fault;
      if (records.has(recordKey)) throw new Error('412 Precondition Failed');
      records.set(recordKey, value);
    },
    async writeIndex(rows) {
      calls.push({ op: 'writeIndex' });
      if (indexFault) throw indexFault;
      indexes.push(rows);
    },
  };
  return {
    store,
    records,
    calls,
    indexes,
    setReadFault: (fault?: typeof readFault) => { readFault = fault; reads = 0; },
    setCreateFault: (fault?: typeof createFault) => { createFault = fault; },
    setIndexFault: (fault?: unknown) => { indexFault = fault; },
  };
}

describe('registerMissingBootstrapSpaces', () => {
  test('creates each missing canonical space and writes one index', async () => {
    const memory = memoryStore();
    const result = await registerMissingBootstrapSpaces(memory.store, spaces, ownerDid, now);

    expect(result).toEqual({ created: spaces.length, preserved: 0 });
    expect(memory.calls.filter((call) => call.op === 'read')).toHaveLength(spaces.length);
    expect(memory.calls.filter((call) => call.op === 'createOnly')).toHaveLength(spaces.length);
    expect(memory.indexes).toHaveLength(1);
    expect(memory.indexes[0]).toHaveLength(spaces.length);
    for (const space of spaces) {
      expect(memory.records.get(key(space))).toBe(body(space));
    }
  });

  test('preserves existing customized and archived records, and heals index from KV', async () => {
    const defaults = spaces.find((space) => space.name === 'default')!;
    const publicSpace = spaces.find((space) => space.name === 'public')!;
    const secrets = spaces.find((space) => space.name === 'secrets')!;
    const agents = spaces.find((space) => space.name === 'agents');
    const renamed = body(defaults, { name: 'My renamed space' });
    const archived = body(publicSpace, { status: 'archived' });
    const custom = body(secrets, { permissions: ['read'], extra: { keep: true } });
    const customKey = `spaces/tinycloud:pkh:eip155:1:${address}:custom`;
    const memory = memoryStore({ [key(defaults)]: renamed, [key(publicSpace)]: archived, [key(secrets)]: custom, [customKey]: 'custom-record' });

    const result = await registerMissingBootstrapSpaces(memory.store, spaces, ownerDid, now);

    expect(result.created).toBe(spaces.length - 3);
    expect(result.preserved).toBe(3);
    expect(memory.records.get(key(defaults))).toBe(renamed);
    expect(memory.records.get(key(publicSpace))).toBe(archived);
    expect(memory.records.get(key(secrets))).toBe(custom);
    expect(memory.records.get(customKey)).toBe('custom-record');
    expect(memory.calls.filter((call) => call.op === 'createOnly').map((call) => call.key)).not.toContain(key(defaults));
    const index = memory.indexes[0]!;
    expect(index.find((row) => row.spaceId === defaults.spaceId)?.name).toBe('My renamed space');
    expect(index.find((row) => row.spaceId === publicSpace.spaceId)?.status).toBe('archived');
    expect(index.find((row) => row.spaceId === secrets.spaceId)?.permissionsJson).toBe('["read"]');
    if (agents) expect(memory.records.has(key(agents))).toBe(true);
  });

  test('heals the index when all records already exist without writing KV', async () => {
    const memory = memoryStore(Object.fromEntries(spaces.map((space) => [key(space), body(space)])));
    const result = await registerMissingBootstrapSpaces(memory.store, spaces, ownerDid, now);
    expect(result).toEqual({ created: 0, preserved: spaces.length });
    expect(memory.calls.filter((call) => call.op === 'createOnly')).toHaveLength(0);
    expect(memory.indexes).toHaveLength(1);
  });

  test.each([412, 503])('reconciles create race after HTTP %i without a second put', async (status) => {
    const target = spaces[0]!;
    const concurrent = body(target, { name: 'written concurrently' });
    const memory = memoryStore();
    memory.setCreateFault((recordKey) => {
      if (recordKey === key(target)) {
        memory.records.set(recordKey, concurrent);
        return new Error(`HTTP ${status}`);
      }
      return undefined;
    });
    await registerMissingBootstrapSpaces(memory.store, spaces, ownerDid, now);
    expect(memory.records.get(key(target))).toBe(concurrent);
    expect(memory.calls.filter((call) => call.op === 'createOnly' && call.key === key(target))).toHaveLength(1);
    expect(memory.indexes[0]!.find((row) => row.spaceId === target.spaceId)?.name).toBe('written concurrently');
  });

  test('aborts before writes when any initial read has unknown state', async () => {
    const memory = memoryStore();
    memory.setReadFault((_recordKey, count) => count === spaces.length ? new Error('HTTP 500') : undefined);
    await expect(registerMissingBootstrapSpaces(memory.store, spaces, ownerDid, now)).rejects.toThrow('HTTP 500');
    expect(memory.calls.filter((call) => call.op === 'createOnly')).toHaveLength(0);
    expect(memory.indexes).toHaveLength(0);
  });

  test('does not write the index after an unreconciled create failure', async () => {
    const target = spaces[0]!;
    const memory = memoryStore();
    memory.setCreateFault((recordKey) => recordKey === key(target) ? new Error('503 unavailable') : undefined);
    await expect(registerMissingBootstrapSpaces(memory.store, spaces, ownerDid, now)).rejects.toThrow('503 unavailable');
    expect(memory.indexes).toHaveLength(0);
  });

  test('preserves the original create error when reconciliation finds 404 or fails', async () => {
    const target = spaces[0]!;
    for (const readFailure of [undefined, new Error('reconcile read failed')]) {
      const memory = memoryStore();
      const createFailure = new Error('original create failure');
      memory.setCreateFault((recordKey) => recordKey === key(target) ? createFailure : undefined);
      memory.setReadFault((_recordKey, count) => count > spaces.length && readFailure ? readFailure : undefined);
      await expect(registerMissingBootstrapSpaces(memory.store, spaces, ownerDid, now)).rejects.toBe(createFailure);
      expect(memory.indexes).toHaveLength(0);
    }
  });

  test('retries partial failures safely and never overwrites prior successful creates', async () => {
    const publicSpace = spaces.find((space) => space.name === 'public')!;
    const target = spaces.find((space) => space.name === 'agents') ?? spaces.find((space) => space.name === 'secrets')!;
    const memory = memoryStore(Object.fromEntries(spaces.filter((space) => space !== publicSpace && space !== target).map((space) => [key(space), body(space)])));
    memory.setCreateFault((recordKey) => recordKey === key(target) ? new Error('503 unavailable') : undefined);
    await expect(registerMissingBootstrapSpaces(memory.store, spaces, ownerDid, now)).rejects.toThrow('503 unavailable');
    const firstSuccessfulBody = memory.records.get(key(publicSpace));
    memory.setCreateFault();
    await registerMissingBootstrapSpaces(memory.store, spaces, ownerDid, now);
    expect(memory.records.get(key(publicSpace))).toBe(firstSuccessfulBody);
    expect(memory.calls.filter((call) => call.op === 'createOnly' && call.key === key(publicSpace))).toHaveLength(1);
  });

  test('keeps malformed existing bytes and builds a fallback index row', async () => {
    const target = spaces[0]!;
    const memory = memoryStore({ [key(target)]: 'not-json' });
    await registerMissingBootstrapSpaces(memory.store, spaces, ownerDid, now);
    expect(memory.records.get(key(target))).toBe('not-json');
    expect(memory.indexes[0]!.find((row) => row.spaceId === target.spaceId)).toEqual({
      spaceId: target.spaceId,
      name: target.name,
      ownerDid: '',
      type: 'discovered',
      permissionsJson: '[]',
      status: 'active',
      registeredAt: null,
      updatedAt: now,
      expiresAt: null,
    });
  });

  test('fails on index write and safely heals on a rerun', async () => {
    const memory = memoryStore();
    memory.setIndexFault(new Error('index unavailable'));
    await expect(registerMissingBootstrapSpaces(memory.store, spaces, ownerDid, now)).rejects.toThrow('index unavailable');
    memory.setIndexFault();
    const createsBeforeRetry = memory.calls.filter((call) => call.op === 'createOnly').length;
    await registerMissingBootstrapSpaces(memory.store, spaces, ownerDid, now);
    expect(memory.calls.filter((call) => call.op === 'createOnly')).toHaveLength(createsBeforeRetry);
    expect(memory.indexes).toHaveLength(1);
  });
});

describe('kvSpaceRegistryStore', () => {
  test('reads 2xx, maps 404 to missing, rejects other statuses, and sends create-only puts', async () => {
    const sent: Array<{ path: string; action: string; body?: string; headers?: Record<string, string> }> = [];
    const responses = [
      new Response('record'),
      new Response('', { status: 404 }),
      new Response('', { status: 401 }),
      new Response('', { status: 500 }),
      new Response('bad', { status: 503 }),
    ];
    const store = kvSpaceRegistryStore(async (request) => {
      sent.push(request);
      return responses.shift() ?? new Response(null, { status: 204 });
    }, async () => undefined);

    expect(await store.read('spaces/a')).toEqual({ found: true, body: 'record' });
    expect(await store.read('spaces/b')).toEqual({ found: false });
    await expect(store.read('spaces/c')).rejects.toThrow('HTTP 401');
    await expect(store.read('spaces/d')).rejects.toThrow('HTTP 500');
    await expect(store.createOnly('spaces/e', 'body')).rejects.toThrow('HTTP 503');
    await store.createOnly('spaces/e', 'body');
    expect(sent.at(-1)).toEqual({
      path: 'spaces/e',
      action: KV.PUT,
      body: 'body',
      headers: { 'if-none-match': '*' },
    });
  });
});
