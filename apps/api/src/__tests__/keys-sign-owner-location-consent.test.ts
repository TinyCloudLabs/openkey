// TC-4082: `/api/keys/:keyId/sign` under `required` consent. The owner-location hooks exist only for a first-party
// origin whose request says `publishOwnerLocation: true` AND carries a passkey assertion for the publish itself
// (`ownerLocationPasskeyAssertion`, from `/:keyId/owner-location/passkey`). It is checked before the key is unsealed,
// whatever the account's passkey-approval setting, and a refusal never fails the sign: it only means no publish.

import './tc1777-test-env';
import { beforeEach, describe, expect, mock, test } from 'bun:test';
import { createMiddleware } from 'hono/factory';
import { privateKeyToAccount } from 'viem/accounts';
import { createApprovalPasskeyChallenge, approvalRequestDigest } from '../services/approval-passkey';
import { ownerLocationPublishBinding } from '../services/owner-location-record';
import { createFakeApprovalDb } from './fake-approval-db';
import { mockModules, replaceModules } from './mock-module';
import { createRouteConsent, TEST_RP_ID, TEST_RP_ORIGIN } from './owner-location-route-consent';
import { createSoftPasskey } from './soft-passkey';

const privateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const address = privateKeyToAccount(privateKey).address;
const otherAddress = privateKeyToAccount('0x1111111111111111111111111111111111111111111111111111111111111111').address;
const user = { id: 'user_1', email: 'test@example.com' };
const FIRST_PARTY = 'https://home.tinycloud.xyz';
const rp = { rpID: TEST_RP_ID, origin: TEST_RP_ORIGIN };

type Hooks = { onFreshlyComplete?: unknown; onAlreadyComplete?: unknown };
let hooks: Hooks[] = [];
let events: string[] = [];
const ensureTinyCloudBootstrapForApprovedSign = mock(async (input: Hooks) => {
  hooks.push({ onFreshlyComplete: input.onFreshlyComplete, onAlreadyComplete: input.onAlreadyComplete });
  return { status: 'complete' as const };
});
const unseal = mock(async () => {
  events.push('unseal');
  return privateKey;
});

/** The user's approval tables: with one step-up passkey, or with none. */
const withPasskey = await createRouteConsent(user.id);
const withoutPasskey = createFakeApprovalDb('NEVER');
let active: object = withPasskey.db;
const tables = () => active as Record<string, unknown>;
const keyRecord = { id: 'key_1', userId: user.id, address, keyType: 'MANAGED', sealedBlob: 'sealed-private-key', archivedAt: null };
const prisma = {
  ethereumKey: {
    findFirst: mock(async ({ where }: { where: Record<string, unknown> }) =>
      where.userId === user.id && where.id === keyRecord.id && where.archivedAt === null ? keyRecord : null),
  },
  get user() { return tables().user; },
  get passkey() { return tables().passkey; },
  get $transaction() { return tables().$transaction; },
  // Every read of the stored challenges is the consent check running: when it runs is what is asserted.
  get verification() {
    const real = tables().verification as { findFirst: (args: unknown) => Promise<unknown> };
    return new Proxy(real, {
      get: (target, property) => property === 'findFirst'
        ? (args: unknown) => { events.push('consent'); return target.findFirst(args); }
        : (target as unknown as Record<string | symbol, unknown>)[property],
    });
  },
};

replaceModules({
  '../middleware/session': () => ({
    requireSession: createMiddleware(async (c, next) => {
      c.set('user', user);
      c.set('session', { id: 'session_1', userId: user.id, expiresAt: new Date(Date.now() + 60_000) });
      await next();
    }),
  }),
});
await mockModules({
  '@openkey/db': () => ({ createPrismaClient: () => prisma }),
  '@openkey/tee': () => ({
    createTeeClient: () => ({ deriveKey: mock(async () => new Uint8Array(32)), getQuote: mock(async () => 'quote'), isInTee: () => false }),
    seal: mock(async () => 'sealed-private-key'),
    unseal,
    createWalletFromPrivateKey: (key: string) => privateKeyToAccount(key as `0x${string}`),
    generatePrivateKey: () => privateKey,
    getAddressFromPrivateKey: () => address,
  }),
  '../services/tinycloud-bootstrap': () => ({ ensureTinyCloudBootstrapForApprovedSign }),
});

beforeEach(() => {
  hooks = [];
  events = [];
  active = withPasskey.db;
  unseal.mockClear();
  ensureTinyCloudBootstrapForApprovedSign.mockClear();
});

async function router() {
  const { keysRouter } = await import('../routes/keys?keys-sign-owner-location-consent' as string);
  return keysRouter as { request: (path: string, init: RequestInit) => Promise<Response> };
}
async function post(path: string, body: Record<string, unknown>) {
  return (await router()).request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'http://localhost:5173' },
    body: JSON.stringify(body),
  });
}
const sign = (body: Record<string, unknown>) => post('/key_1/sign', { message: 'Sign in to Example', ...body });
const hooked = (): string[][] => hooks.map((hook) => [String(typeof hook.onFreshlyComplete), String(typeof hook.onAlreadyComplete)]);
const NO_HOOKS = [['undefined', 'undefined']];
const BOTH_HOOKS = [['function', 'function']];

/** An assertion from a challenge the server issued for `binding`, as a passkey tap would answer it. */
async function assertionFor(binding: { purpose: string; requestDigest: string }) {
  const offer = await createApprovalPasskeyChallenge(
    withPasskey.db as Parameters<typeof createApprovalPasskeyChallenge>[0], { userId: user.id, sessionId: 'session_1' }, binding, rp,
  );
  return { challengeToken: offer!.challengeToken, response: withPasskey.passkey.assert(offer!.options) };
}

describe('the challenge endpoint', () => {
  test('a first-party origin gets a passkey challenge for the publish, always a passkey, whatever the account setting', async () => {
    const res = await post('/key_1/owner-location/passkey', { requestOrigin: FIRST_PARTY });
    const offer = await res.json() as { required: boolean; challengeToken: string; options: { rpId: string } };

    expect(res.status).toBe(200);
    expect(offer.required).toBe(true);
    expect(offer.challengeToken).toBeTruthy();
    expect(offer.options.rpId).toBe(TEST_RP_ID);
  });

  test('a third-party or unattributed origin gets no challenge', async () => {
    for (const body of [{ requestOrigin: 'https://app.example.test' }, { requestOrigin: 'http://home.tinycloud.xyz' }, {}]) {
      const res = await post('/key_1/owner-location/passkey', body);
      expect(await res.json()).toEqual({ available: false });
    }
  });

  test('an account with no passkey that counts for step-up gets no challenge', async () => {
    active = withoutPasskey.db;
    const res = await post('/key_1/owner-location/passkey', { requestOrigin: FIRST_PARTY });

    expect(await res.json()).toEqual({ available: false });
  });

  test('an unknown key is a 404', async () => {
    const res = await post('/key_9/owner-location/passkey', { requestOrigin: FIRST_PARTY });
    expect(res.status).toBe(404);
  });
});

describe('/sign under required consent', () => {
  test('field plus a passkey assertion for the publish gives both hooks, and the consent is checked before the key is unsealed', async () => {
    const assertion = await withPasskey.assertionFor(await router(), 'key_1', FIRST_PARTY);
    const res = await sign({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true, ...assertion });

    expect(res.status).toBe(200);
    expect(hooked()).toEqual(BOTH_HOOKS);
    expect(events).toEqual(['consent', 'unseal']);
  });

  test('no assertion is no publish and no passkey read; the sign still succeeds', async () => {
    for (const body of [{ publishOwnerLocation: true }, { publishOwnerLocation: true, ownerLocationPasskeyAssertion: null }, {}]) {
      hooks = [];
      events = [];
      const res = await sign({ requestOrigin: FIRST_PARTY, ...body });

      expect(res.status).toBe(200);
      expect(hooked()).toEqual(NO_HOOKS);
      expect(events).toEqual(['unseal']);
    }
  });

  test('an assertion without the field is no publish', async () => {
    const assertion = await withPasskey.assertionFor(await router(), 'key_1', FIRST_PARTY);
    const res = await sign({ requestOrigin: FIRST_PARTY, ...assertion });

    expect(res.status).toBe(200);
    expect(hooked()).toEqual(NO_HOOKS);
  });

  const mismatched: Array<[string, () => { purpose: string; requestDigest: string }]> = [
    ['another key id', () => ownerLocationPublishBinding('key_2', address)],
    ['another subject', () => ownerLocationPublishBinding('key_1', otherAddress)],
    ['another host', () => ({
      purpose: 'owner_location_publish',
      requestDigest: approvalRequestDigest('key_1', `did:pkh:eip155:1:${address}`, 'https://tee.node.tinycloud.xyz', 'v1', '0'),
    })],
    ['another purpose', () => ({ purpose: 'key_sign', requestDigest: ownerLocationPublishBinding('key_1', address).requestDigest })],
  ];
  for (const [name, binding] of mismatched) {
    test(`an assertion bound to ${name} is no publish, and the sign still succeeds`, async () => {
      const assertion = await assertionFor(binding());
      const res = await sign({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true, ownerLocationPasskeyAssertion: assertion });

      expect(res.status).toBe(200);
      expect(hooked()).toEqual(NO_HOOKS);
    });
  }

  test('an assertion works once', async () => {
    const assertion = await withPasskey.assertionFor(await router(), 'key_1', FIRST_PARTY);
    await sign({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true, ...assertion });
    await sign({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true, ...assertion });

    expect(hooked()).toEqual([...BOTH_HOOKS, ...NO_HOOKS]);
  });

  test('an account with no passkey fails closed: no challenge, and a made-up assertion is no publish', async () => {
    active = withoutPasskey.db;
    const forged = { challengeToken: 'made-up', response: { id: 'no-such-credential' } };
    const res = await sign({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true, ownerLocationPasskeyAssertion: forged });

    expect(res.status).toBe(200);
    expect(hooked()).toEqual(NO_HOOKS);
  });

  test('a passkey that does not count for step-up fails closed too', async () => {
    const weakOnly = createFakeApprovalDb('NEVER');
    const weak = await createSoftPasskey(weakOnly.db as Parameters<typeof createSoftPasskey>[0], user.id, false, TEST_RP_ORIGIN);
    active = weakOnly.db;
    const forged = { challengeToken: 'made-up', response: { id: weak.credentialID } };
    await sign({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true, ownerLocationPasskeyAssertion: forged });

    expect(hooked()).toEqual(NO_HOOKS);
  });

  test('a third-party or unattributed origin gets nothing, even with a valid assertion for this very publish', async () => {
    for (const requestOrigin of ['https://app.example.test', 'https://home.tinycloud.xyz.evil.example', undefined]) {
      hooks = [];
      events = [];
      const assertion = await assertionFor(ownerLocationPublishBinding('key_1', address));
      const res = await sign({
        ...(requestOrigin ? { requestOrigin } : {}), publishOwnerLocation: true, ownerLocationPasskeyAssertion: assertion,
      });

      expect(res.status).toBe(200);
      expect(hooked()).toEqual(NO_HOOKS);
      expect(events).toEqual(['unseal']);
    }
  });
});
