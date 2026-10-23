import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { Hono } from 'hono';
import { createDelegationCodeRouter, createPrismaDelegationCodeStore } from '../routes/delegation-codes';

const MIGRATION_URL = new URL('../../../../packages/db/prisma/migrations/20261005_0001_delegation_code_broker/migration.sql', import.meta.url);
const delegation = { delegationCid: 'bafy-delegation', spaceId: 'tinycloud:pkh:eip155:1:0x123:default' };

describe('Prisma delegation code store (PGlite)', () => {
  let database: PGlite;
  let client: PrismaClient;

  beforeAll(async () => {
    database = new PGlite();
    await database.waitReady;
    await database.exec(await readFile(MIGRATION_URL, 'utf8'));
    client = new PrismaClient({ adapter: new PrismaPGlite(database) });
  });

  afterAll(async () => {
    await client.$disconnect();
    await database.close();
  });

  beforeEach(async () => {
    await client.delegationCode.deleteMany();
  });

  test('the first consume returns the record and deletes it; the second finds nothing', async () => {
    const store = createPrismaDelegationCodeStore(client);
    const expiresAt = new Date('2099-01-01T00:00:00.000Z');
    expect(await store.create('aaaa-bbbb', delegation, expiresAt)).toBe(true);
    expect(await store.consume('aaaa-bbbb')).toEqual({ delegation, expiresAt });
    expect(await client.delegationCode.count()).toBe(0);
    expect(await store.consume('aaaa-bbbb')).toBeNull();
  });

  test('consuming an unknown code resolves to null instead of throwing', async () => {
    const store = createPrismaDelegationCodeStore(client);
    await expect(store.consume('zzzz-zzzz')).resolves.toBeNull();
  });

  test('a duplicate code is refused by create', async () => {
    const store = createPrismaDelegationCodeStore(client);
    const expiresAt = new Date('2099-01-01T00:00:00.000Z');
    expect(await store.create('cccc-dddd', delegation, expiresAt)).toBe(true);
    expect(await store.create('cccc-dddd', delegation, expiresAt)).toBe(false);
  });

  test('of 50 concurrent consumes of one code, exactly one receives the record', async () => {
    const store = createPrismaDelegationCodeStore(client);
    await store.create('eeee-ffff', delegation, new Date('2099-01-01T00:00:00.000Z'));
    const results = await Promise.all(Array.from({ length: 50 }, () => store.consume('eeee-ffff')));
    expect(results.filter((record) => record !== null)).toHaveLength(1);
    expect(await client.delegationCode.count()).toBe(0);
  });

  test('through the router, a redeemed code and an unknown code both answer 404 with the same body', async () => {
    const store = createPrismaDelegationCodeStore(client);
    const app = new Hono().route('/api/delegation-codes', createDelegationCodeRouter({
      store,
      sessionMiddleware: async (_c, next) => next(),
    }));
    await store.create('gggg-hhhh', delegation, new Date('2099-01-01T00:00:00.000Z'));
    const first = await app.request('/api/delegation-codes/gggg-hhhh');
    expect(first.status).toBe(200);
    expect(await first.json()).toEqual({ delegation });
    const redeemed = await app.request('/api/delegation-codes/gggg-hhhh');
    const unknown = await app.request('/api/delegation-codes/zzzz-zzzz');
    expect(redeemed.status).toBe(404);
    expect(unknown.status).toBe(404);
    expect(await redeemed.text()).toBe(await unknown.text());
  });
});
