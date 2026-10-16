import { describe, expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { generateKeyPairSync } from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { privateKeyToAccount } from 'viem/accounts';
import {
  PreparedHandoffService,
  MemoryPreparedHandoffStore,
  type PreparedHandoffRequest,
} from '../services/prepared-handoff';
import { createPrismaPreparedHandoffStore } from '../services/prepared-handoff-store';

const address = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef').address;
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const host = 'https://node.tinycloud.xyz';
const spaceId = `tinycloud:pkh:eip155:1:${address}:default`;
const siwe = prepareSession({
  address,
  chainId: 1,
  domain: 'cli.tinycloud.xyz',
  issuedAt: '2026-10-16T17:00:00.000Z',
  expirationTime: '2026-10-23T17:00:00.000Z',
  spaceId,
  jwk,
  abilities: { kv: { [spaceId]: ['tinycloud.kv/get', 'tinycloud.kv/sync'] } },
}).siwe;
const callback = 'http://127.0.0.1:42317/callback/AAAAAAAAAAAAAAAAAAAAAA';
const state = Buffer.alloc(32, 1).toString('base64url');
const cancelSecret = Buffer.alloc(32, 2).toString('base64url');
const handoffId = Buffer.alloc(32, 3).toString('base64url');
const request: PreparedHandoffRequest = {
  protocolVersion: 1,
  siwe,
  jwk,
  host,
  sessionDid: 'did:key:session-cli',
  keyId: 'key-one',
};
function distinctInput(index: number) {
  const publicJwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
  const preparedSiwe = prepareSession({
    address, chainId: 1, domain: 'cli.tinycloud.xyz',
    issuedAt: '2026-10-16T17:00:00.000Z', expirationTime: '2026-10-23T17:00:00.000Z',
    spaceId, jwk: publicJwk,
    abilities: { kv: { [spaceId]: ['tinycloud.kv/get', 'tinycloud.kv/sync'] } },
  }).siwe;
  return {
    transportVersion: 2,
    request: { ...request, siwe: preparedSiwe, jwk: publicJwk },
    delivery: { handoffId: Buffer.alloc(32, index + 10).toString('base64url'), callback, state, cancelSecret },
  };
}

function setup() {
  let now = Date.parse('2026-10-16T17:00:00.000Z');
  const service = new PreparedHandoffService(new MemoryPreparedHandoffStore(), { now: () => now });
  const create = (override: Partial<PreparedHandoffRequest> = {}, delivery = { handoffId, callback, state, cancelSecret }, ownerId = 'owner') =>
    service.claim({ transportVersion: 2, request: { ...request, ...override }, delivery }, ownerId);
  return { service, create, advance: (ms: number) => { now += ms; } };
}

describe('prepared CLI handoff', () => {
  test('authenticated claim returns only a ticket and cannot reveal delivery state or a signed result', async () => {
    const { create } = setup();
    const claimed = await create();
    expect(claimed.ticket).toBe(handoffId);
    expect(Object.keys(claimed).sort()).toEqual(['expiresAt', 'ticket', 'transportVersion']);
    expect(JSON.stringify(claimed)).not.toContain(siwe);
    expect(JSON.stringify(claimed)).not.toContain(state);
    expect(JSON.stringify(claimed)).not.toContain(cancelSecret);
    expect(await create()).toEqual(claimed);
    await expect(create({}, undefined, 'stranger')).rejects.toMatchObject({ code: 'handoff_claimed' });
  });

  test('rejects tampered SIWE, JWK, keyId and host at context binding', async () => {
    const { service, create } = setup();
    const { ticket } = await create();
    const bind = (overrides: Record<string, unknown>) => service.bindContext(ticket, 'owner', {
      keyId: 'key-one', siwe, jwk, host, authorizationContextToken: 'context-one', ...overrides,
    });
    await expect(bind({ siwe: siwe.replace('cli.tinycloud.xyz', 'evil.example') })).rejects.toMatchObject({ code: 'binding_mismatch' });
    await expect(bind({ jwk: { ...jwk, x: 'B'.repeat(43) } })).rejects.toMatchObject({ code: 'binding_mismatch' });
    await expect(bind({ keyId: 'key-two' })).rejects.toMatchObject({ code: 'binding_mismatch' });
    await expect(bind({ host: 'https://evil.example' })).rejects.toMatchObject({ code: 'binding_mismatch' });
    await bind({});
    await expect(service.reserveSigning(ticket, 'owner', 'different-context', 'key-one')).rejects.toMatchObject({ code: 'binding_mismatch' });
    expect(await service.reserveSigning(ticket, 'owner', 'context-one', 'key-one')).toBeUndefined();
    await expect(service.reserveSigning(ticket, 'owner', 'context-one', 'key-one')).rejects.toMatchObject({ code: 'handoff_consumed' });
    expect(await service.completeSigning(ticket, 'owner', 'context-one', 'key-one')).toEqual({ deliveryState: state, selectedKeyId: 'key-one' });
  });

  test('prepare rejects changed original bytes, JWK, requested key, host and presentation before issuing a context', async () => {
    const { service, create } = setup();
    const { ticket } = await create();
    const prepare = (override: Record<string, unknown>) => service.assertRequest(ticket, 'owner', {
      keyId: 'key-one', siwe, jwk, host, ...override,
    });
    for (const altered of [
      { siwe: siwe.replace('cli.tinycloud.xyz', 'evil.example') },
      { jwk: { ...jwk, x: 'B'.repeat(43) } },
      { keyId: 'key-two' },
      { host: 'https://evil.example' },
      { presentation: { reason: 'injected' } },
    ]) {
      await expect(prepare(altered)).rejects.toMatchObject({ code: 'binding_mismatch' });
    }
    await expect(prepare({})).resolves.toBeTruthy();
  });

  test('cancellation needs the CLI secret, survives a browser claim, and wins against signing', async () => {
    const { service, create } = setup();
    const { ticket } = await create();
    await service.bindContext(ticket, 'owner', { keyId: 'key-one', siwe, jwk, host, authorizationContextToken: 'context' });
    await expect(service.cancel(ticket, 'wrong-secret')).rejects.toMatchObject({ code: 'invalid_cancel_secret' });
    await service.cancel(ticket, cancelSecret);
    await expect(service.reserveSigning(ticket, 'owner', 'context', 'key-one')).rejects.toMatchObject({ code: 'handoff_cancelled' });
    await expect(create()).rejects.toMatchObject({ code: 'handoff_cancelled' });
  });

  test('claimed user can cancel before signing but another user cannot', async () => {
    const { service, create } = setup();
    const { ticket } = await create();
    await expect(service.cancelClaimed(ticket, 'stranger')).rejects.toMatchObject({ code: 'handoff_claimed' });
    await service.bindContext(ticket, 'owner', { keyId: 'key-one', siwe, jwk, host, authorizationContextToken: 'context' });
    await service.cancelClaimed(ticket, 'owner');
    await expect(service.reserveSigning(ticket, 'owner', 'context', 'key-one')).rejects.toMatchObject({ code: 'handoff_cancelled' });
  });

  test('only one authorization context can bind a ticket', async () => {
    const { service, create } = setup();
    const { ticket } = await create();
    const attempts = await Promise.allSettled(['context-1', 'context-2'].map((authorizationContextToken) =>
      service.bindContext(ticket, 'owner', { keyId: 'key-one', siwe, jwk, host, authorizationContextToken })));
    expect(attempts.filter((attempt) => attempt.status === 'fulfilled')).toHaveLength(1);
    expect(attempts.filter((attempt) => attempt.status === 'rejected')).toHaveLength(1);
    const winner = attempts[0]?.status === 'fulfilled' ? 'context-1' : 'context-2';
    const loser = winner === 'context-1' ? 'context-2' : 'context-1';
    await expect(service.reserveSigning(ticket, 'owner', loser, 'key-one')).rejects.toMatchObject({ code: 'binding_mismatch' });
    await service.reserveSigning(ticket, 'owner', winner, 'key-one');
  });

  test('Prisma admission serializes the account count and insert across service instances', async () => {
    const database = new PGlite();
    await database.waitReady;
    let client: PrismaClient | undefined;
    try {
      await database.exec('CREATE TABLE "user" ("id" TEXT PRIMARY KEY)');
      const migration = await readFile(new URL('../../../../packages/db/prisma/migrations/20261016_0001_prepared_siwe_handoff/migration.sql', import.meta.url), 'utf8');
      await database.exec(migration);
      await database.exec('INSERT INTO "user" ("id") VALUES (\'owner\')');
      client = new PrismaClient({ adapter: new PrismaPGlite(database) });
      const now = Date.parse('2026-10-16T17:00:00.000Z');
      const first = new PreparedHandoffService(createPrismaPreparedHandoffStore(client), { now: () => now });
      const second = new PreparedHandoffService(createPrismaPreparedHandoffStore(client), { now: () => now });
      for (let n = 1; n <= 4; n++) await first.claim(distinctInput(n), 'owner');
      const attempts = await Promise.allSettled([
        first.claim(distinctInput(5), 'owner'),
        second.claim(distinctInput(6), 'owner'),
      ]);
      expect(attempts.filter(attempt => attempt.status === 'fulfilled')).toHaveLength(1);
      expect(attempts.find(attempt => attempt.status === 'rejected')).toMatchObject({
        reason: { code: 'rate_limited' },
      });
      expect(await client.preparedHandoff.count()).toBe(5);
    } finally {
      await client?.$disconnect();
      await database.close();
    }
  });

  test('enforces ticket expiry, public JWK and exact loopback callback', async () => {
    const { service, create, advance } = setup();
    const first = await create();
    await expect(create({ jwk: { ...jwk, d: 'private' } })).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(create({ siwe: siwe.replace(/^URI: .+$/m, 'URI: did:key:tampered') })).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(create({ host: `${host}/unexpected` })).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(setup().create({ sessionDid: 'display-only-value' })).resolves.toMatchObject({ transportVersion: 2 });
    for (const unsafe of [
      'http://localhost:42317/callback/AAAAAAAAAAAAAAAAAAAAAA',
      'http://127.0.0.1:42317/callback/AAAAAAAAAAAAAAAAAAAAAA?next=evil',
      'http://127.0.0.1:80/callback/AAAAAAAAAAAAAAAAAAAAAA',
      'https://evil.example/callback/AAAAAAAAAAAAAAAAAAAAAA',
    ]) {
      await expect(create({}, { handoffId, callback: unsafe, state, cancelSecret })).rejects.toMatchObject({ code: 'invalid_request' });
    }
    advance(300_001);
    await expect(service.assertRequest(first.ticket, 'owner', { keyId: 'key-one', siwe, jwk, host })).rejects.toMatchObject({ code: 'handoff_expired' });
  });
  test('authenticated claim owns a fresh SIWE nonce, keeps one ticket, and refuses late reuse', async () => {
    const { service, advance } = setup();
    const input = { transportVersion: 2, request, delivery: { handoffId, callback, state, cancelSecret } };
    const first = await service.claim(input, 'owner');
    expect(first.ticket).toBe(handoffId);
    expect(await service.claim(input, 'owner')).toEqual(first);
    await expect(service.claim(input, 'another-owner')).rejects.toMatchObject({ code: 'handoff_claimed' });
    const anotherId = Buffer.alloc(32, 4).toString('base64url');
    await expect(service.claim({ ...input, delivery: { ...input.delivery, handoffId: anotherId } }, 'owner')).rejects.toMatchObject({ code: 'handoff_replayed' });
    advance(300_001);
    await expect(service.claim({ ...input, delivery: { ...input.delivery, handoffId: anotherId } }, 'third-owner')).rejects.toMatchObject({ code: 'prepared_expired' });
  });

  test('simultaneous authenticated claims enforce five per account while another account remains independent', async () => {
    const store = new MemoryPreparedHandoffStore();
    const now = Date.parse('2026-10-16T17:00:00.000Z');
    const first = new PreparedHandoffService(store, { now: () => now });
    const second = new PreparedHandoffService(store, { now: () => now });
    for (let n = 1; n <= 4; n++) await first.claim(distinctInput(n), 'owner');
    const attempts = await Promise.allSettled([
      first.claim(distinctInput(5), 'owner'),
      second.claim(distinctInput(6), 'owner'),
    ]);
    expect(attempts.filter(attempt => attempt.status === 'fulfilled')).toHaveLength(1);
    expect(attempts.find(attempt => attempt.status === 'rejected')).toMatchObject({ reason: { code: 'rate_limited' } });
    await expect(second.claim(distinctInput(7), 'another-owner')).resolves.toMatchObject({ transportVersion: 2 });
  });

  test('authenticated claim rejects stale or expired SIWE and private JWK before storage', async () => {
    const { service, advance } = setup();
    const input = { transportVersion: 2, request, delivery: { handoffId, callback, state, cancelSecret } };
    await expect(service.claim({ ...input, request: { ...request, jwk: { ...jwk, d: 'private' } } }, 'owner')).rejects.toMatchObject({ code: 'invalid_request' });
    advance(120_000);
    const expiredSiwe = prepareSession({
      address, chainId: 1, domain: 'cli.tinycloud.xyz', issuedAt: '2026-10-16T17:00:00.000Z',
      expirationTime: '2026-10-16T17:01:00.000Z', spaceId, jwk,
      abilities: { kv: { [spaceId]: ['tinycloud.kv/get', 'tinycloud.kv/sync'] } },
    }).siwe;
    await expect(service.claim({ ...input, request: { ...request, siwe: expiredSiwe } }, 'owner')).rejects.toMatchObject({ code: 'prepared_expired' });
    advance(180_001);
    await expect(service.claim(input, 'owner')).rejects.toMatchObject({ code: 'prepared_expired' });
  });
});
