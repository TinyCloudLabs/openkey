import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient } from '@openkey/db';
import { Hono } from 'hono';
import { createDelegationCodeRouter, createPrismaDelegationCodeStore } from '../routes/delegation-codes';

const MIGRATIONS = ['20261005_0001_delegation_code_broker', '20261103_0001_delegation_code_claim']
  .map((name) => new URL(`../../../../packages/db/prisma/migrations/${name}/migration.sql`, import.meta.url));
const MINUTE = 60 * 1000;
const CLAIM_HEADER = 'OpenKey-Delegation-Claim';
const delegation = {
  delegationHeader: { Authorization: 'Bearer signed-delegation' },
  delegationCid: 'bafy-delegation',
  spaceId: 'tinycloud:pkh:eip155:1:0x123:default',
  verificationMethod: 'did:key:zSession',
  jwk: { kty: 'OKP', crv: 'Ed25519', x: 'public-key' },
};
const newClaim = () => randomBytes(16).toString('base64url');

describe('delegation short codes: spent only after the client acknowledges', () => {
  let database: PGlite;
  let client: PrismaClient;
  let now = Date.UTC(2026, 10, 3);

  beforeAll(async () => {
    database = new PGlite();
    await database.waitReady;
    for (const migration of MIGRATIONS) await database.exec(await readFile(migration, 'utf8'));
    client = new PrismaClient({ adapter: new PrismaPGlite(database) });
  });
  afterAll(async () => {
    await client.$disconnect();
    await database.close();
  });
  beforeEach(async () => {
    now = Date.UTC(2026, 10, 3);
    await client.delegationCodeClaim.deleteMany();
    await client.delegationCode.deleteMany();
  });

  function app() {
    return new Hono().route('/api/delegation-codes', createDelegationCodeRouter({
      store: createPrismaDelegationCodeStore(client),
      now: () => new Date(now),
      sessionMiddleware: async (_c, next) => next(),
    }));
  }
  async function issue(router: Hono): Promise<string> {
    const created = await router.request('/api/delegation-codes', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ delegation }),
    });
    expect(created.status).toBe(201);
    const { code } = await created.json() as { code: string };
    return code;
  }
  const redeem = (router: Hono, code: string, claim?: string) =>
    router.request(`/api/delegation-codes/${code}`, { headers: claim ? { [CLAIM_HEADER]: claim } : {} });
  const acknowledge = (router: Hono, code: string, claim?: string) =>
    router.request(`/api/delegation-codes/${code}/ack`, { method: 'POST', headers: claim ? { [CLAIM_HEADER]: claim } : {} });

  test('a lost response is recoverable: the same claim fetches the delegation again', async () => {
    const router = app();
    const code = await issue(router);
    const claim = newClaim();
    const first = await redeem(router, code, claim);
    expect(first.status).toBe(200);
    expect(await first.json()).toEqual({ delegation });
    // The client never saw that response and asks again.
    const retry = await redeem(router, code, claim);
    expect(retry.status).toBe(200);
    expect(await retry.json()).toEqual({ delegation });
  });

  test('a second claimant gets exactly the unknown-code answer, and so does a client with no claim', async () => {
    const router = app();
    const code = await issue(router);
    await redeem(router, code, newClaim());
    const other = await redeem(router, code, newClaim());
    const bare = await redeem(router, code);
    const unknown = await redeem(router, 'sf23-22cs');
    expect(other.status).toBe(404);
    expect(bare.status).toBe(404);
    const unknownBody = await unknown.text();
    expect(await other.text()).toBe(unknownBody);
    expect(await bare.text()).toBe(unknownBody);
  });

  test('of concurrent first redeems with different claims, exactly one receives the delegation', async () => {
    const router = app();
    const code = await issue(router);
    const responses = await Promise.all(Array.from({ length: 10 }, () => redeem(router, code, newClaim())));
    expect(responses.filter((response) => response.status === 200)).toHaveLength(1);
    expect(responses.filter((response) => response.status === 404)).toHaveLength(9);
  });

  test('an acknowledgement spends the code: the claim cannot fetch again and the delegation is cleared', async () => {
    const router = app();
    const code = await issue(router);
    const claim = newClaim();
    await redeem(router, code, claim);
    const acked = await acknowledge(router, code, claim);
    expect(acked.status).toBe(200);
    expect((await redeem(router, code, claim)).status).toBe(404);
    const stored = await client.delegationCodeClaim.findFirstOrThrow();
    expect(stored.delegation).toBeNull();
    expect(stored.acknowledgedAt).not.toBeNull();
    expect(await client.delegationCode.count()).toBe(0);
  });

  test('a repeated acknowledgement succeeds, so a lost ACK response can be retried', async () => {
    const router = app();
    const code = await issue(router);
    const claim = newClaim();
    await redeem(router, code, claim);
    expect((await acknowledge(router, code, claim)).status).toBe(200);
    expect((await acknowledge(router, code, claim)).status).toBe(200);
  });

  test('only the claim holder may acknowledge: a wrong claim, no claim or an unclaimed code changes nothing', async () => {
    const router = app();
    const code = await issue(router);
    // Not yet redeemed: no claim exists to acknowledge, and the code stays redeemable.
    expect((await acknowledge(router, code, newClaim())).status).toBe(404);
    const claim = newClaim();
    expect((await redeem(router, code, claim)).status).toBe(200);
    expect((await acknowledge(router, code, newClaim())).status).toBe(404);
    expect((await acknowledge(router, code)).status).toBe(400);
    const stillThere = await redeem(router, code, claim);
    expect(stillThere.status).toBe(200);
    expect(await stillThere.json()).toEqual({ delegation });
  });

  test('an acknowledgement for an unknown code answers exactly like a wrong claim', async () => {
    const router = app();
    const code = await issue(router);
    await redeem(router, code, newClaim());
    const wrong = await acknowledge(router, code, newClaim());
    const unknown = await acknowledge(router, 'sf23-22cs', newClaim());
    expect(wrong.status).toBe(404);
    expect(await wrong.text()).toBe(await unknown.text());
  });

  test('a client that never acknowledges is served only until retention ends, then the row is swept', async () => {
    const router = app();
    const code = await issue(router);
    const claim = newClaim();
    now += 4 * MINUTE;
    expect((await redeem(router, code, claim)).status).toBe(200);
    // The code itself expired at five minutes, but a redeemed code is retained from its redemption.
    now += 4 * MINUTE;
    expect((await redeem(router, code, claim)).status).toBe(200);
    now += MINUTE + 1;
    expect((await redeem(router, code, claim)).status).toBe(404);
    await issue(router);
    expect(await client.delegationCodeClaim.count()).toBe(0);
  });

  test('an unredeemed code still expires after five minutes for a claiming client', async () => {
    const router = app();
    const code = await issue(router);
    now += 5 * MINUTE;
    expect((await redeem(router, code, newClaim())).status).toBe(404);
  });

  test('a malformed claim is refused before any lookup and spends nothing', async () => {
    const router = app();
    const code = await issue(router);
    expect((await redeem(router, code, 'short')).status).toBe(400);
    expect((await acknowledge(router, code, 'short')).status).toBe(400);
    expect((await redeem(router, code, newClaim())).status).toBe(200);
  });

  test('a client that sends no claim keeps the original behaviour: the code works once', async () => {
    const router = app();
    const code = await issue(router);
    expect((await redeem(router, code)).status).toBe(200);
    expect((await redeem(router, code)).status).toBe(404);
    expect((await redeem(router, code, newClaim())).status).toBe(404);
  });

  test('an acknowledgement is bound to its own code: it cannot be replayed to clear another code', async () => {
    const router = app();
    const first = await issue(router);
    const second = await issue(router);
    const claimA = newClaim();
    const claimB = newClaim();
    await redeem(router, first, claimA);
    await redeem(router, second, claimB);
    // The first client's acknowledgement, aimed at the second code, finds nothing to clear.
    expect((await acknowledge(router, second, claimA)).status).toBe(404);
    expect((await redeem(router, second, claimB)).status).toBe(200);
    expect((await acknowledge(router, first, claimA)).status).toBe(200);
    expect((await redeem(router, second, claimB)).status).toBe(200);
    expect((await acknowledge(router, second, claimB)).status).toBe(200);
  });
});
