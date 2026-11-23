// TC-4082: under `required` consent the owner's say-so is a passkey assertion for the publish itself (purpose
// `owner_location_publish`, digest of key id, v1 subject, default node, version and sequence), forced on whatever the
// account's passkey-approval setting. The real challenge and verification code runs against an in-memory database.

import { beforeEach, describe, expect, test } from 'bun:test';
import { privateKeyToAccount } from 'viem/accounts';
import { approvalRequestDigest, createApprovalPasskeyChallenge, type ApprovalBinding } from '../services/approval-passkey';
import {
  OWNER_LOCATION_NODE_HOST,
  ownerLocationPublishAllowed,
  ownerLocationPublishBinding,
  type OwnerLocationConsentContext,
} from '../services/owner-location-record';
import { createFakeApprovalDb, type FakeApprovalDb } from './fake-approval-db';
import { createSoftPasskey, type SoftPasskey } from './soft-passkey';

const rp = { rpID: 'openkey.test', origin: 'https://openkey.test' };
const address = privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef').address;
const otherAddress = privateKeyToAccount('0x1111111111111111111111111111111111111111111111111111111111111111').address;
const FIRST_PARTY = 'https://home.tinycloud.xyz';
const subject = { userId: 'user_1', sessionId: 'session_1' };
const KEY_ID = 'key_1';

let fake: FakeApprovalDb;
let passkey: SoftPasskey;
type Db = OwnerLocationConsentContext['db'];
const context = (overrides: Partial<OwnerLocationConsentContext> = {}): OwnerLocationConsentContext => ({
  db: fake.db as unknown as Db, subject, keyId: KEY_ID, address, rp, ...overrides,
});

/** The assertion a user-present passkey tap would give for a challenge issued for `binding`. */
async function assertionFor(binding: ApprovalBinding, who = subject, options?: { userVerified?: boolean }) {
  const offer = await createApprovalPasskeyChallenge(fake.db as unknown as Db, who, binding, rp);
  if (!offer) throw new Error('no challenge issued');
  return { challengeToken: offer.challengeToken, response: passkey.assert(offer.options, options) };
}
const publishAssertion = () => assertionFor(ownerLocationPublishBinding(KEY_ID, address));
const ask = (request: Record<string, unknown>, overrides?: Partial<OwnerLocationConsentContext>) =>
  ownerLocationPublishAllowed({ requestOrigin: FIRST_PARTY, ...request }, context(overrides), 'required');

beforeEach(async () => {
  fake = createFakeApprovalDb('NEVER');
  passkey = await createSoftPasskey(fake.db as unknown as Parameters<typeof createSoftPasskey>[0], subject.userId, true, rp.origin);
});

describe('what the passkey confirms', () => {
  test('the binding is the purpose and the digest of key id, EIP-55 v1 subject, default node, v1 and 0', () => {
    expect(ownerLocationPublishBinding(KEY_ID, address.toLowerCase())).toEqual({
      purpose: 'owner_location_publish',
      requestDigest: approvalRequestDigest(KEY_ID, `did:pkh:eip155:1:${address}`, 'https://node.tinycloud.xyz', 'v1', '0'),
    });
    expect(OWNER_LOCATION_NODE_HOST).toBe('https://node.tinycloud.xyz');
  });

  test('a first-party sign with the field and a passkey assertion for the publish is consent, even when the account setting is NEVER', async () => {
    expect(await ask({ publishOwnerLocation: true, ownerLocationPasskeyAssertion: await publishAssertion() })).toBe(true);
  });

  test('the account setting is not consulted: ALWAYS and SENSITIVE give the same answer', async () => {
    for (const mode of ['ALWAYS', 'SENSITIVE'] as const) {
      fake = createFakeApprovalDb(mode);
      passkey = await createSoftPasskey(fake.db as unknown as Parameters<typeof createSoftPasskey>[0], subject.userId, true, rp.origin);
      expect(await ask({ publishOwnerLocation: true, ownerLocationPasskeyAssertion: await publishAssertion() }), mode).toBe(true);
    }
  });
});

describe('required consent is refused without a matching assertion', () => {
  test('no assertion, however the field is set, is no consent and touches no stored challenge', async () => {
    await publishAssertion(); // a live challenge exists, unused
    for (const assertion of [undefined, null]) {
      expect(await ask({ publishOwnerLocation: true, ownerLocationPasskeyAssertion: assertion })).toBe(false);
    }
    expect(fake.verifications).toHaveLength(1);
  });

  test('an assertion without the boolean field is no consent', async () => {
    const assertion = await publishAssertion();
    for (const field of [undefined, false, 'true', 1, {}]) {
      expect(await ask({ publishOwnerLocation: field, ownerLocationPasskeyAssertion: assertion })).toBe(false);
    }
  });

  test('an assertion that is not an assertion is no consent', async () => {
    for (const junk of ['yes', 42, {}, { challengeToken: 'x' }, { challengeToken: 'x', response: {} }, { challengeToken: 1, response: { id: 'a' } }]) {
      expect(await ask({ publishOwnerLocation: true, ownerLocationPasskeyAssertion: junk })).toBe(false);
    }
  });

  const otherBindings: Array<[string, ApprovalBinding]> = [
    ['a different key id', ownerLocationPublishBinding('key_2', address)],
    ['a different subject', ownerLocationPublishBinding(KEY_ID, otherAddress)],
    ['a different host', {
      purpose: 'owner_location_publish',
      requestDigest: approvalRequestDigest(KEY_ID, `did:pkh:eip155:1:${address}`, 'https://tee.node.tinycloud.xyz', 'v1', '0'),
    }],
    ['a different version', {
      purpose: 'owner_location_publish',
      requestDigest: approvalRequestDigest(KEY_ID, `did:pkh:eip155:1:${address}`, OWNER_LOCATION_NODE_HOST, 'v2', '0'),
    }],
    ['a different sequence', {
      purpose: 'owner_location_publish',
      requestDigest: approvalRequestDigest(KEY_ID, `did:pkh:eip155:1:${address}`, OWNER_LOCATION_NODE_HOST, 'v1', '1'),
    }],
    ['a different purpose (a message sign)', {
      purpose: 'key_sign',
      requestDigest: ownerLocationPublishBinding(KEY_ID, address).requestDigest,
    }],
  ];
  for (const [name, binding] of otherBindings) {
    test(`an assertion bound to ${name} is refused`, async () => {
      expect(await ask({ publishOwnerLocation: true, ownerLocationPasskeyAssertion: await assertionFor(binding) })).toBe(false);
    });
  }

  test('an assertion issued to another session is refused', async () => {
    const assertion = await assertionFor(ownerLocationPublishBinding(KEY_ID, address), { userId: subject.userId, sessionId: 'session_2' });
    expect(await ask({ publishOwnerLocation: true, ownerLocationPasskeyAssertion: assertion })).toBe(false);
  });

  test('an assertion is spent by its first use', async () => {
    const assertion = await publishAssertion();
    expect(await ask({ publishOwnerLocation: true, ownerLocationPasskeyAssertion: assertion })).toBe(true);
    expect(await ask({ publishOwnerLocation: true, ownerLocationPasskeyAssertion: assertion })).toBe(false);
  });

  test('an assertion without user verification is refused', async () => {
    const assertion = await assertionFor(ownerLocationPublishBinding(KEY_ID, address), subject, { userVerified: false });
    expect(await ask({ publishOwnerLocation: true, ownerLocationPasskeyAssertion: assertion })).toBe(false);
  });

  test('a database that fails is no consent, not an error', async () => {
    const assertion = await publishAssertion();
    const failing = { ...fake.db, verification: { findFirst: async () => { throw new Error('db down'); } } };
    expect(await ask({ publishOwnerLocation: true, ownerLocationPasskeyAssertion: assertion }, { db: failing as unknown as Db })).toBe(false);
  });
});

describe('an account with no passkey that counts for step-up fails closed', () => {
  test('no passkey at all: no challenge can be issued, so no assertion exists to present', async () => {
    fake = createFakeApprovalDb('NEVER');
    expect(await createApprovalPasskeyChallenge(fake.db as unknown as Db, subject, ownerLocationPublishBinding(KEY_ID, address), rp)).toBeNull();
    for (const forged of [{ challengeToken: 'abc', response: { id: 'nobody' } }, { challengeToken: '', response: { id: '' } }]) {
      expect(await ask({ publishOwnerLocation: true, ownerLocationPasskeyAssertion: forged })).toBe(false);
    }
  });

  test('a passkey that does not count for step-up gives no challenge and no consent', async () => {
    fake = createFakeApprovalDb('NEVER');
    const weak = await createSoftPasskey(fake.db as unknown as Parameters<typeof createSoftPasskey>[0], subject.userId, false, rp.origin);
    expect(await createApprovalPasskeyChallenge(fake.db as unknown as Db, subject, ownerLocationPublishBinding(KEY_ID, address), rp)).toBeNull();
    expect(weak.credentialID).toBeTruthy();
    expect(await ask({ publishOwnerLocation: true, ownerLocationPasskeyAssertion: { challengeToken: 'abc', response: { id: weak.credentialID } } })).toBe(false);
  });
});

describe('origin and the silent switch', () => {
  test('a third-party or unattributed origin is refused, with a valid assertion, and the assertion is not spent', async () => {
    const assertion = await publishAssertion();
    for (const requestOrigin of ['https://app.example.test', 'https://home.tinycloud.xyz.evil.example', 'http://home.tinycloud.xyz', undefined]) {
      expect(await ownerLocationPublishAllowed(
        { requestOrigin, publishOwnerLocation: true, ownerLocationPasskeyAssertion: assertion }, context(), 'required',
      )).toBe(false);
    }
    expect(fake.verifications).toHaveLength(1);
  });

  test('silent: a first-party sign needs no field and no passkey, and the database is not read', async () => {
    const untouched = new Proxy({}, { get: () => { throw new Error('the database must not be read under silent consent'); } });
    for (const request of [{}, { publishOwnerLocation: true }, { publishOwnerLocation: false }]) {
      expect(await ownerLocationPublishAllowed(
        { requestOrigin: FIRST_PARTY, ...request }, context({ db: untouched as Db }), 'silent',
      )).toBe(true);
    }
  });

  test('silent: a third-party or unattributed origin still never publishes', async () => {
    for (const requestOrigin of ['https://app.example.test', undefined]) {
      expect(await ownerLocationPublishAllowed({ requestOrigin, publishOwnerLocation: true }, context(), 'silent')).toBe(false);
    }
  });

  test('with no mode given the shipped constant applies: required', async () => {
    expect(await ownerLocationPublishAllowed({ requestOrigin: FIRST_PARTY, publishOwnerLocation: true }, context())).toBe(false);
    expect(await ownerLocationPublishAllowed(
      { requestOrigin: FIRST_PARTY, publishOwnerLocation: true, ownerLocationPasskeyAssertion: await publishAssertion() }, context(),
    )).toBe(true);
  });
});
