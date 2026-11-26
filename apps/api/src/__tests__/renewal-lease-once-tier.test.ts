import { expect, test } from 'bun:test';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { courierSpace, courierTuples } from '../../../../packages/capability-review/test/fixtures/courier';
import { FIXTURE_META } from '../../../../packages/capability-review/test/fixtures/index';
import { prepareRenewalStage } from '../services/renewal-lease';

const { address, chainId, ownSpace: space } = FIXTURE_META;
const network = `urn:tinycloud:encryption:did:pkh:eip155:${chainId}:${address}:default`;
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const issuedAt = new Date('2026-11-22T12:00:00.000Z');
const daySeconds = 86_400;

function setupLease(rawAbilities: Record<string, string[]>, windowSeconds: number) {
  const { siwe } = prepareSession({
    address, chainId, domain: 'openkey.so', spaceId: space, jwk,
    issuedAt: issuedAt.toISOString(),
    expirationTime: new Date(issuedAt.getTime() + windowSeconds * 1000).toISOString(),
    abilities: {},
    rawAbilities,
  } as unknown as Parameters<typeof prepareSession>[0]);
  const nodeDid = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  const renewerDid = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';
  const nodeCalls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL) => {
    const { pathname } = new URL(String(input));
    nodeCalls.push(pathname);
    return Response.json(pathname === '/info' ? { nodeId: nodeDid } : {
      nodeDid,
      renewerDid,
      renewerPublicKey: 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik',
      renewerEpoch: 0,
    });
  }) as typeof fetch;

  return {
    nodeCalls,
    prepare: (sensitiveConfirmed: boolean) => prepareRenewalStage({
      userId: 'owner',
      host: 'http://127.0.0.1:8000',
      leaseLifetimeSeconds: 90 * daySeconds,
      delegation: {
        delegationHeader: { Authorization: 'Bearer original' },
        delegationCid: 'bafyreigdmqpykrgxyaxtlafqpqhzrb7qy2rh75nldvfd4tucqmqqme5yse',
        spaceId: space,
        hostActivated: true,
        siwe,
      },
      now: issuedAt,
      fetchImpl,
      sensitiveConfirmed,
    }),
  };
}

const onceTierGrants: Record<string, Record<string, string[]>> = {
  'standalone whole-vault KV read': { [`${space}/kv/vault/secrets/`]: ['tinycloud.kv/get'] },
  'decrypt on default/qa/': { [`${network}/qa/`]: ['tinycloud.encryption/decrypt'] },
  'decrypt on default/secretsish/': { [`${network}/secretsish/`]: ['tinycloud.encryption/decrypt'] },
};

for (const [name, abilities] of Object.entries(onceTierGrants)) {
  test(`${name} requires owner confirmation`, async () => {
    const lease = setupLease(abilities, 7 * daySeconds);
    await expect(lease.prepare(false)).rejects.toMatchObject({
      code: 'renewal_refused', status: 400, message: expect.stringContaining('needs your confirmation'),
    });
    expect(lease.nodeCalls).toEqual([]);
  });

  test(`${name} with confirmation refuses a 30-day grant window`, async () => {
    const lease = setupLease(abilities, 30 * daySeconds);
    await expect(lease.prepare(true)).rejects.toMatchObject({
      code: 'renewal_refused', status: 400, message: expect.stringContaining('at most 7 days'),
    });
    expect(lease.nodeCalls).toEqual([]);
  });

  test(`${name} with confirmation accepts a seven-day grant window`, async () => {
    const lease = setupLease(abilities, 7 * daySeconds);
    expect((await lease.prepare(true)).approvedLeaseLifetimeSeconds).toBe(90 * daySeconds);
    expect(lease.nodeCalls.sort()).toEqual(['/.well-known/tinycloud/node-keys', '/info']);
  });
}

test("Courier's scoped agents KV and hooks accept an unconfirmed 30-day grant window", async () => {
  const abilities = Object.fromEntries(courierTuples.map(([service, path, verbs]) => [
    `${courierSpace}/${service.replace('tinycloud.', '')}/${path}`,
    verbs.map((verb) => `${service}/${verb}`),
  ]));
  const lease = setupLease(abilities, 30 * daySeconds);
  expect((await lease.prepare(false)).approvedLeaseLifetimeSeconds).toBe(90 * daySeconds);
});

test("Share's own default/share/ library accepts an unconfirmed 30-day grant window", async () => {
  const lease = setupLease({
    [`${network}/share/`]: ['tinycloud.encryption/decrypt', 'tinycloud.encryption/key.create'],
  }, 30 * daySeconds);
  expect((await lease.prepare(false)).approvedLeaseLifetimeSeconds).toBe(90 * daySeconds);
});
