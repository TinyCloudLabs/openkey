import { describe, expect, test } from 'bun:test';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import { FIXTURE_META, makeRecapResource, siweWithResources } from '../../../../packages/capability-review/test/fixtures';
import { assertLeaseableGrant, prepareRenewalStage, renewalGrantSensitivity, signLease } from '../services/renewal-lease';

const owner = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const network = `urn:tinycloud:encryption:${owner}:default`;
const appPrefix = `${network}/apps/xyz.tinycloud.listen/`;

function message(resource: string, abilities: string[]): string {
  return prepareSession({
    address: FIXTURE_META.address,
    chainId: FIXTURE_META.chainId,
    domain: 'openkey.so',
    spaceId: FIXTURE_META.ownSpace,
    jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
    issuedAt: '2026-11-22T00:00:00.000Z',
    expirationTime: '2026-11-23T00:00:00.000Z',
    abilities: {},
    rawAbilities: { [resource]: abilities },
  } as unknown as Parameters<typeof prepareSession>[0]).siwe;
}

describe('renewal lease encryption verbs', () => {
  for (const ability of [
    'tinycloud.encryption/Decrypt',
    'tinycloud.encryption/decrypt2',
    'encryption/Decrypt',
    'tinycloud.kv/decrypt',
    'TinyCloud.Encryption/decrypt',
  ]) {
    test(`refuses ${ability} on an app prefix even with owner confirmation`, () => {
      const siwe = message(appPrefix, [ability]);
      expect(renewalGrantSensitivity(siwe)).toBeNull();
      for (const confirmed of [false, true]) {
        expect(() => assertLeaseableGrant(siwe, confirmed)).toThrow("couldn't read one of its permissions");
      }
    });
  }

  test('refuses a grant mixing a known and an unknown encryption verb', () => {
    const siwe = message(appPrefix, ['tinycloud.encryption/decrypt', 'tinycloud.encryption/decrypt2']);
    expect(() => assertLeaseableGrant(siwe, true)).toThrow("couldn't read one of its permissions");
  });

  test('rechecks a saved stage against the current verb rules before rebuilding the lease', async () => {
    const renewer = {
      nodeDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      renewerDid: 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp',
      renewerPublicKey: 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik',
      renewerEpoch: 0,
    };
    const stage = await prepareRenewalStage({
      userId: 'owner',
      host: 'http://127.0.0.1:8000',
      leaseLifetimeSeconds: 86_400,
      delegation: {
        delegationHeader: { Authorization: 'Bearer original' },
        delegationCid: 'bafyreigdmqpykrgxyaxtlafqpqhzrb7qy2rh75nldvfd4tucqmqqme5yse',
        spaceId: FIXTURE_META.ownSpace,
        hostActivated: true,
        siwe: message(appPrefix, ['tinycloud.encryption/decrypt']),
      },
      now: new Date('2026-11-22T00:00:00.000Z'),
      fetchImpl: (async (input: RequestInfo | URL) => {
        return Response.json(new URL(String(input)).pathname === '/info' ? { nodeId: renewer.nodeDid } : renewer);
      }) as typeof fetch,
    });
    const saved = { ...stage, delegation: { ...stage.delegation, siwe: message(appPrefix, ['tinycloud.encryption/Decrypt']) } };
    expect(() => signLease(saved, '0x00')).toThrow("couldn't read one of its permissions");
  });

  test('refuses an empty encryption verb', () => {
    const recap = makeRecapResource({ [appPrefix]: { 'tinycloud.encryption/': [{}] } });
    const siwe = siweWithResources([recap]);
    expect(() => assertLeaseableGrant(siwe, true)).toThrow("couldn't read one of its permissions");
  });

  for (const verb of ['decrypt', 'key.create', 'key.block', 'key.unblock']) {
    test(`accepts ${verb} on an app prefix`, () => {
      for (const namespace of ['tinycloud.encryption', 'encryption']) {
        const siwe = message(appPrefix, [`${namespace}/${verb}`]);
        expect(() => assertLeaseableGrant(siwe, false)).not.toThrow();
      }
    });
  }

  for (const [resource, verb] of [[network, '*'], [`${network}/secrets/a`, 'key.describe']]) {
    test(`accepts ${verb} only with owner confirmation`, () => {
      const siwe = message(resource, [`tinycloud.encryption/${verb}`]);
      expect(() => assertLeaseableGrant(siwe, false)).toThrow('needs your confirmation');
      expect(() => assertLeaseableGrant(siwe, true)).not.toThrow();
    });
  }
});
