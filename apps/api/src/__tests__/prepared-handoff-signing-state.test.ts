// TC-2382: the prepared CLI handoff has a SIGNING state. Reserving a handoff to sign does not
// spend it; only the signature that was produced does, and a failed signing releases it.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import { MemoryPreparedHandoffStore, PreparedHandoffService, type PreparedHandoffStore } from '../services/prepared-handoff';
import { createPrismaPreparedHandoffStore } from '../services/prepared-handoff-store';

const address = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef').address;
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const host = 'https://node.tinycloud.xyz';
const spaceId = `tinycloud:pkh:eip155:1:${address}:default`;
const siwe = prepareSession({
  address, chainId: 1, domain: 'cli.tinycloud.xyz',
  issuedAt: '2026-10-16T17:00:00.000Z', expirationTime: '2026-10-23T17:00:00.000Z',
  spaceId, jwk, abilities: { kv: { [spaceId]: ['tinycloud.kv/get', 'tinycloud.kv/sync'] } },
}).siwe;
const state = Buffer.alloc(32, 1).toString('base64url');
const cancelSecret = Buffer.alloc(32, 2).toString('base64url');
const ticket = Buffer.alloc(32, 3).toString('base64url');
const ticketHash = createHash('sha256').update(ticket).digest('hex');
const claimInput = {
  transportVersion: 2,
  request: { protocolVersion: 1, siwe, jwk, host, sessionDid: 'did:key:session-cli', keyId: 'key-one' },
  delivery: { handoffId: ticket, state, cancelSecret },
};

let database: PGlite;
let client: PrismaClient;
beforeAll(async () => {
  database = new PGlite();
  await database.waitReady;
  await database.exec('CREATE TABLE "user" ("id" TEXT PRIMARY KEY)');
  await database.exec(await readFile(new URL('../../../../packages/db/prisma/migrations/20261016_0001_prepared_siwe_handoff/migration.sql', import.meta.url), 'utf8'));
  await database.exec('INSERT INTO "user" ("id") VALUES (\'owner\'), (\'stranger\')');
  client = new PrismaClient({ adapter: new PrismaPGlite(database) });
});
afterAll(async () => {
  await client.$disconnect();
  await database.close();
});

const stores: Array<[string, () => PreparedHandoffStore]> = [
  ['in memory', () => new MemoryPreparedHandoffStore()],
  ['Prisma over PGlite', () => createPrismaPreparedHandoffStore(client)],
];

describe.each(stores)('prepared handoff signing state (%s)', (_name, makeStore) => {
  async function bound() {
    await client.preparedHandoff.deleteMany();
    const store = makeStore();
    const service = new PreparedHandoffService(store, { now: () => Date.parse('2026-10-16T17:00:00.000Z') });
    await service.claim(claimInput, 'owner');
    await service.bindContext(ticket, 'owner', { keyId: 'key-one', siwe, jwk, host, authorizationContextToken: 'context-one' });
    return {
      service,
      status: async () => (await store.find(ticketHash))?.status,
      reserve: () => service.reserveSigning(ticket, 'owner', 'context-one', 'key-one'),
      release: (user = 'owner', context = 'context-one') => service.releaseSigning(ticket, user, context, 'key-one'),
      complete: () => service.completeSigning(ticket, 'owner', 'context-one', 'key-one'),
    };
  }

  test('reserving moves the handoff to SIGNING, not to a spent state', async () => {
    const handoff = await bound();
    await handoff.reserve();
    expect(await handoff.status()).toBe('SIGNING');
  });

  test('while it is being signed, a second signer and a cancel are told it is being signed, not that it was signed', async () => {
    const handoff = await bound();
    await handoff.reserve();
    await expect(handoff.reserve()).rejects.toMatchObject({ code: 'handoff_signing', status: 409 });
    await expect(handoff.service.cancel(ticket, cancelSecret)).rejects.toMatchObject({ code: 'handoff_signing', status: 409 });
    await expect(handoff.service.cancelClaimed(ticket, 'owner')).rejects.toMatchObject({ code: 'handoff_signing', status: 409 });
    expect(await handoff.status()).toBe('SIGNING');
  });

  test('a failed signing is released: the same context signs again and the handoff can still be cancelled', async () => {
    const handoff = await bound();
    await handoff.reserve();
    await handoff.release();
    expect(await handoff.status()).toBe('PENDING');
    await handoff.reserve();
    expect(await handoff.complete()).toEqual({ deliveryState: state, selectedKeyId: 'key-one' });
    const again = await bound();
    await again.reserve();
    await again.release();
    await again.service.cancelClaimed(ticket, 'owner');
    expect(await again.status()).toBe('CANCELLED');
  });

  test('completing spends the handoff: it cannot be reserved, released or cancelled afterwards', async () => {
    const handoff = await bound();
    await handoff.reserve();
    await handoff.complete();
    expect(await handoff.status()).toBe('CONSUMED');
    await expect(handoff.reserve()).rejects.toMatchObject({ code: 'handoff_consumed' });
    await expect(handoff.service.cancel(ticket, cancelSecret)).rejects.toMatchObject({ code: 'handoff_consumed' });
    await handoff.release();
    expect(await handoff.status()).toBe('CONSUMED');
  });

  test('a signature cannot be delivered for a handoff nobody reserved', async () => {
    const handoff = await bound();
    await expect(handoff.complete()).rejects.toMatchObject({ code: 'binding_mismatch' });
    expect(await handoff.status()).toBe('PENDING');
  });

  test('only the holder of the bound context releases a handoff that is being signed', async () => {
    const handoff = await bound();
    await handoff.reserve();
    await handoff.release('stranger');
    await handoff.release('owner', 'other-context');
    expect(await handoff.status()).toBe('SIGNING');
    await handoff.release();
    expect(await handoff.status()).toBe('PENDING');
  });

  test('of concurrent signers, exactly one reserves the handoff', async () => {
    const handoff = await bound();
    const attempts = await Promise.allSettled([handoff.reserve(), handoff.reserve(), handoff.reserve()]);
    expect(attempts.filter((attempt) => attempt.status === 'fulfilled')).toHaveLength(1);
    for (const attempt of attempts) if (attempt.status === 'rejected') expect(attempt.reason).toMatchObject({ code: 'handoff_signing' });
  });
});
