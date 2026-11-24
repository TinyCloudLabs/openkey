import { expect, test } from 'bun:test';
import { base64UrlDecode, sessionDidForPublicKey, type NativeFetch, type NativeRenewalAsk } from '@openkey/core';
import { OpenKeyNative, type OpenKeyCapacitorPlugin } from '../src';

const issuer = 'https://api.openkey.test/api/auth';
const redirectUri = 'xyz.tinycloud.test://openkey/callback';
const host = 'https://node.tinycloud.xyz';
const cid = 'bafyreigdmqpykrgxyaxtlafqpqhzrb7qy2rh75nldvfd4tucqmqqme5yse';
const leaseCid = 'bafyreigucs4tl77haf3cc3ovdji6fftouih5qugdloujfccehr7wzn4e24';
const day = 86_400;
const ask: NativeRenewalAsk = { version: 1, leaseLifetimeSeconds: 90 * day, purpose: 'standing' };

function fixture(kind: 'leased' | 'malformed' | 'finite' = 'leased') {
  const values = new Map<string, string>();
  const requests = { ask: undefined as NativeRenewalAsk | undefined, renew: 0, revoke: [] as string[] };
  const approvedAt = Math.floor(Date.now() / 1000) * 1000;
  const leaseExpiresAt = approvedAt + ask.leaseLifetimeSeconds * 1000;
  const renewal = {
    version: 1,
    approvedLeaseLifetimeSeconds: ask.leaseLifetimeSeconds,
    approvedAt: new Date(approvedAt).toISOString(),
    receipt: {
      originalCid: cid, leaseCid, leaseAuthorization: 'bGVhc2U',
      leaseExpiresAt: new Date(leaseExpiresAt).toISOString(), leaseGeneration: 1,
      nodeIdentity: {
        nodeDid: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        renewerDid: 'did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp',
        renewerPublicKey: 'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik',
        renewerEpoch: 0,
      },
    },
  };
  let state = '';
  let did = '';
  let revokeAvailable = true;
  const plugin: OpenKeyCapacitorPlugin = {
    async openAuthSession() { return { url: `${redirectUri}?code=code&state=${state}&iss=${encodeURIComponent(issuer)}` }; },
    async secureStoreGet({ key }) { return { value: values.get(key) ?? null }; },
    async secureStoreSet({ key, value }) { values.set(key, value); },
    async secureStoreRemove({ key }) { values.delete(key); },
  };
  const fetchFn: NativeFetch = async (url, init) => {
    if (url.includes('.well-known')) return Response.json({
      issuer, authorization_endpoint: `${issuer}/oauth2/authorize`, token_endpoint: `${issuer}/oauth2/token`,
      pushed_authorization_request_endpoint: `${issuer}/oauth2/par`,
      tinycloud_delegation_renew_endpoint: `${issuer}/oauth2/tinycloud/renew`,
      tinycloud_delegation_revocation_endpoint: `${issuer}/oauth2/tinycloud/revoke`,
    });
    if (url.endsWith('/par')) {
      const form = new URLSearchParams(init?.body);
      const [detail] = JSON.parse(form.get('authorization_details')!);
      requests.ask = detail.renewal;
      state = form.get('state')!;
      did = sessionDidForPublicKey(base64UrlDecode(detail.session_key.x));
      return Response.json({ request_uri: 'urn:request:standing', expires_in: 90 }, { status: 201 });
    }
    if (url.endsWith('/token') || url.endsWith('/renew')) {
      const remint = url.endsWith('/renew');
      if (remint) requests.renew++;
      const delegation = {
        verificationMethod: `${did}#${did.slice('did:key:'.length)}`,
        issuedAt: new Date(approvedAt - 3600_000).toISOString(),
        expiresAt: new Date(approvedAt + (remint ? 3600_000 : 30_000)).toISOString(),
        permissions: [{ service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] }],
        tinycloudHost: host, delegationCid: remint ? 'bafyremint' : cid,
      };
      return Response.json(remint ? { tinycloud_delegation: delegation, refresh_token: 'rotated' } : {
        tinycloud_delegation: delegation, access_token: 'access', refresh_token: 'original',
        renewal: kind === 'leased' ? renewal : kind === 'malformed' ? { version: 2 } : null,
      });
    }
    if (url.endsWith('/revoke')) {
      requests.revoke.push(new URLSearchParams(init?.body).get('refresh_token')!);
      return revokeAvailable ? Response.json({}) : Response.json({ error: 'temporarily_unavailable' }, { status: 503 });
    }
    throw new Error(`Unexpected request ${url}`);
  };
  const client = () => new OpenKeyNative({
    clientId: 'phone', issuer, redirectUri, tinycloudHost: host, plugin, fetchFn,
    verifyDelegation: async () => {}, sleepFn: async () => {},
  });
  return { client, values, requests, renewal, leaseExpiresAt, revokeAvailable: (value: boolean) => { revokeAvailable = value; } };
}

test('the phone receives a fresh transport receipt and retains its exact CID across restart', async () => {
  const f = fixture();
  const native = f.client();
  const before = performance.now();
  const session = await native.signIn({ capabilities: [], renewal: ask });
  expect(f.requests.ask).toEqual(ask);
  expect(session.delegation.delegationCid).toBe(cid);
  expect(session.renewalMode).toBe('leased');
  expect(session.renewal).toEqual(f.renewal);
  expect(session.renewalArrivedAt).toBeGreaterThanOrEqual(before);
  expect(session.renewalArrivedAt).toBeLessThanOrEqual(performance.now());
  expect([...f.values.values()].some(value => value.includes(f.renewal.receipt.leaseAuthorization))).toBe(false);
  const restored = await f.client().current();
  expect(restored).toMatchObject({ renewalMode: 'leased', delegation: { delegationCid: cid } });
  expect(restored?.renewal).toBeUndefined();
  await expect(native.renew()).rejects.toMatchObject({ code: 'CONSENT_REQUIRED' });
  expect(f.requests.renew).toBe(0);
});

test('a malformed leased receipt leaves the original signed grant and does not switch to remint', async () => {
  const f = fixture('malformed');
  const session = await f.client().signIn({ capabilities: [], renewal: ask });
  expect(session).toMatchObject({ renewalMode: 'leased', renewal: null, delegation: { delegationCid: cid } });
  expect(f.requests.renew).toBe(0);
});

test('a finite response still uses the existing immediate rotation near grant expiry', async () => {
  const f = fixture('finite');
  const session = await f.client().signIn({ capabilities: [], renewal: ask });
  expect(session.renewalMode).toBeUndefined();
  expect(session.delegation.delegationCid).toBe('bafyremint');
  expect(f.requests.renew).toBe(1);
});

test('sign-out queues a transient stop with the lease deadline and retries the original token', async () => {
  const f = fixture();
  const native = f.client();
  await native.signIn({ capabilities: [], renewal: ask });
  f.revokeAvailable(false);
  await expect(native.signOut()).rejects.toMatchObject({ code: 'TEMPORARILY_UNAVAILABLE' });
  const queued = [...f.values.entries()].find(([key]) => key.endsWith(':pending-revoke'));
  expect(queued).toBeDefined();
  expect(JSON.parse(queued![1])).toMatchObject({ grants: [{ refreshToken: 'original', expiresAt: f.leaseExpiresAt, standing: true }] });
  expect(await native.current()).toBeNull();
  f.revokeAvailable(true);
  await f.client().signOut();
  expect(f.values.has(queued![0])).toBe(false);
  expect(f.requests.revoke).toEqual(['original', 'original', 'original']);
});
