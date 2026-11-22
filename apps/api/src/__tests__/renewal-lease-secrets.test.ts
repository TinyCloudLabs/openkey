// TC-3821: a renewal lease on a grant that reaches secrets (any permission on a `secrets/` key or prefix, or decrypt on
// a whole encryption network) needs the owner's "Renew sensitive access?" confirm in the choice, and a grant window of
// at most 7 days: the node renews such a grant for its own expiry less its issued-at each time. Real WASM SIWE
// builder; the node is a fake that only answers identity discovery, and is never asked when a lease is refused.
import { describe, expect, test } from 'bun:test';
import { Wallet } from 'ethers';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import {
  RenewalLeaseError,
  SENSITIVE_RENEWAL_WINDOW_SECONDS,
  parseRenewalChoice,
  prepareRenewalStage,
} from '../services/renewal-lease';

const HOST = 'http://127.0.0.1:8000';
const NODE_DID = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
const RENEWER_DID = 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp';
const RENEWER_PUBLIC_KEY = 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik';
const ORIGINAL_CID = 'bafyreigdmqpykrgxyaxtlafqpqhzrb7qy2rh75nldvfd4tucqmqqme5yse';
const DAY = 86_400;
const jwk = { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
const owner = Wallet.createRandom();
const ownerDid = `did:pkh:eip155:1:${owner.address}`;
const space = `tinycloud:pkh:eip155:1:${owner.address}:default`;
const network = `urn:tinycloud:encryption:${ownerDid}:default`;

function node() {
  const asked: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input));
    asked.push(url.pathname);
    const body = url.pathname === '/info' ? { nodeId: NODE_DID } : { nodeDid: NODE_DID, renewerDid: RENEWER_DID, renewerPublicKey: RENEWER_PUBLIC_KEY, renewerEpoch: 0 };
    return Response.json(body);
  }) as typeof fetch;
  return { fetchImpl, asked };
}

/** An approved grant whose SIWE carries `rawAbilities` beside a KV read, lasting `windowSeconds` from its issued-at. */
function grant(rawAbilities: Record<string, string[]>, windowSeconds: number) {
  const issuedAt = new Date(Math.floor(Date.now() / 1000) * 1000);
  const siwe = prepareSession({
    address: owner.address, chainId: 1, domain: 'openkey.so', spaceId: space, jwk,
    issuedAt: issuedAt.toISOString(), expirationTime: new Date(issuedAt.getTime() + windowSeconds * 1000).toISOString(),
    abilities: { kv: { [space]: ['tinycloud.kv/get'] } },
    rawAbilities,
  } as unknown as Parameters<typeof prepareSession>[0]).siwe;
  return { delegationHeader: { Authorization: 'Bearer original' }, delegationCid: ORIGINAL_CID, spaceId: space, hostActivated: true, siwe };
}

async function lease(delegation: Record<string, unknown>, sensitiveConfirmed?: boolean) {
  const fake = node();
  try {
    const stage = await prepareRenewalStage({
      userId: 'owner', host: HOST, leaseLifetimeSeconds: 90 * DAY, delegation, now: new Date(), fetchImpl: fake.fetchImpl,
      ...(sensitiveConfirmed === undefined ? {} : { sensitiveConfirmed }),
    });
    return { stage, error: null, asked: fake.asked };
  } catch (error) {
    return { stage: null, error: error as RenewalLeaseError, asked: fake.asked };
  }
}

const SECRET_DECRYPT = { [`${network}/secrets/openai_api_key`]: ['tinycloud.encryption/decrypt'] };
const SCOPE_DECRYPT = { [`${network}/secrets/scoped/agents/`]: ['tinycloud.encryption/decrypt'] };
const SECRETS_CREATE = { [`${network}/secrets/`]: ['tinycloud.encryption/key.create'] };
const NETWORK_DECRYPT = { [network]: ['tinycloud.encryption/decrypt'] };
const NETWORK_ALL = { [network]: ['tinycloud.encryption/*'] };

describe('the owner choice carries the sensitive-access confirm', () => {
  const signed = { version: 1 as const, leaseLifetimeSeconds: 182 * DAY };
  test('a confirmed leased choice keeps the confirm; a bare one has none', () => {
    expect(parseRenewalChoice({ choice: 'leased', leaseLifetimeSeconds: 90 * DAY, sensitiveConfirmed: true }, signed, true))
      .toEqual({ choice: 'leased', leaseLifetimeSeconds: 90 * DAY, sensitiveConfirmed: true });
    expect(parseRenewalChoice({ choice: 'leased', leaseLifetimeSeconds: 90 * DAY }, signed, true))
      .toEqual({ choice: 'leased', leaseLifetimeSeconds: 90 * DAY });
  });

  test('a confirm that is not exactly true, or any other extra field, is refused', () => {
    for (const choice of [
      { choice: 'leased', leaseLifetimeSeconds: 90 * DAY, sensitiveConfirmed: false },
      { choice: 'leased', leaseLifetimeSeconds: 90 * DAY, sensitiveConfirmed: 'true' },
      { choice: 'leased', leaseLifetimeSeconds: 90 * DAY, sensitiveConfirmed: true, extra: 1 },
      { choice: 'finite', sensitiveConfirmed: true },
    ]) {
      expect(() => parseRenewalChoice(choice, signed, true)).toThrow('does not match');
    }
  });
});

describe('a lease the app asked for, on a grant that reaches secrets, without the owner confirm', () => {
  for (const [name, abilities] of [
    ['decrypt on one secret', SECRET_DECRYPT],
    ['decrypt on a secrets scope prefix', SCOPE_DECRYPT],
    ['key creation on the secrets/ prefix', SECRETS_CREATE],
    ['decrypt on the whole network', NETWORK_DECRYPT],
    ['every ability on the whole network', NETWORK_ALL],
  ] as const) {
    test(`${name}: refused before the node is asked`, async () => {
      for (const confirmed of [undefined, false]) {
        const result = await lease(grant(abilities, DAY), confirmed);
        expect(result.error).toBeInstanceOf(RenewalLeaseError);
        expect(result.error).toMatchObject({ code: 'renewal_refused', status: 400 });
        expect(result.error!.message).toContain('needs your confirmation');
        expect(result.asked).toEqual([]);
      }
    });
  }
});

describe('the owner confirmed renewing sensitive access', () => {
  test('accepted when each renewed window is at most 7 days; the lease length stays the owner choice', async () => {
    for (const abilities of [SECRET_DECRYPT, NETWORK_DECRYPT]) {
      for (const window of [DAY, SENSITIVE_RENEWAL_WINDOW_SECONDS]) {
        const result = await lease(grant(abilities, window), true);
        expect(result.error).toBeNull();
        expect(result.stage!.approvedLeaseLifetimeSeconds).toBe(90 * DAY);
        expect(Date.parse(result.stage!.leaseExpiresAt) - Date.parse(result.stage!.approvedAt)).toBe(90 * DAY * 1000);
      }
    }
    expect(SENSITIVE_RENEWAL_WINDOW_SECONDS).toBe(7 * DAY);
  });

  test('refused when the window is longer than 7 days, even by a second', async () => {
    for (const abilities of [SECRET_DECRYPT, NETWORK_DECRYPT]) {
      for (const window of [7 * DAY + 1, 30 * DAY]) {
        const result = await lease(grant(abilities, window), true);
        expect(result.error).toMatchObject({ code: 'renewal_refused', status: 400 });
        expect(result.error!.message).toContain('at most 7 days');
        expect(result.asked).toEqual([]);
      }
    }
  });
});

describe('leases on other grants are unchanged', () => {
  test('a KV grant, key creation on a whole network, and keys outside secrets/ need no confirm and keep long windows', async () => {
    for (const abilities of [
      {},
      { [network]: ['tinycloud.encryption/key.create'] },
      { [`${network}/share/inbox`]: ['tinycloud.encryption/decrypt'] },
      { [`${network}/secretsish/`]: ['tinycloud.encryption/decrypt'] },
    ]) {
      const result = await lease(grant(abilities, 30 * DAY));
      expect(result.error).toBeNull();
      expect(result.stage!.approvedLeaseLifetimeSeconds).toBe(90 * DAY);
      expect(result.asked.sort()).toEqual(['/.well-known/tinycloud/node-keys', '/info']);
    }
  });
});

describe('a grant OpenKey cannot read is refused (fail closed)', () => {
  test('a ReCap that does not decode', async () => {
    const delegation = grant({}, DAY);
    const broken = { ...delegation, siwe: delegation.siwe.replace(/urn:recap:[A-Za-z0-9_-]+/, 'urn:recap:eyJhIjp') };
    for (const confirmed of [false, true]) {
      const result = await lease(broken, confirmed);
      expect(result.error).toMatchObject({ code: 'renewal_refused', status: 400 });
      expect(result.asked).toEqual([]);
    }
  });

  test('an encryption permission on a resource that is not a valid encryption URN', async () => {
    for (const confirmed of [false, true]) {
      const result = await lease(grant({ [`urn:tinycloud:encryption:${ownerDid}:Default/secrets/x`]: ['tinycloud.encryption/decrypt'] }, DAY), confirmed);
      expect(result.error).toMatchObject({ code: 'renewal_refused', status: 400 });
      expect(result.error!.message).toContain("couldn't read one of its permissions");
      expect(result.asked).toEqual([]);
    }
  });
});
