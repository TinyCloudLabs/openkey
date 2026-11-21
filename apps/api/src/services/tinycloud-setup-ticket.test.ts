// TC-3657: unit tests for the setup ticket store. Covers signature + binding + TTL +
// single-use + decode/consume roundtrip.

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  SETUP_TICKET_TTL_MS,
  SetupTicketError,
  createInMemorySetupNonceStore,
  createSetupTicketStore,
} from './tinycloud-setup-ticket';

const secret = randomBytes(32);
const binding = {
  subject: 'did:pkh:eip155:1:0x00000000000000000000000000000000000000Aa',
  verifiedRequestingOrigin: 'https://gk.example',
  recordHash: 'a'.repeat(64),
};
const makeStore = () => createSetupTicketStore(secret, createInMemorySetupNonceStore());

test('mint + consume with matching binding within TTL succeeds once', async () => {
  const store = makeStore();
  const now = new Date();
  const ticket = store.mint(binding, now);
  await store.consume(ticket, binding, now);
  let err: SetupTicketError | undefined;
  try { await store.consume(ticket, binding, now); } catch (e) { err = e as SetupTicketError; }
  assert.ok(err, 'second consume must throw (single-use)');
  assert.equal(err.code, 'already_used');
  assert.equal(err.status, 409);
});

test('consume rejects a ticket after TTL expires', async () => {
  const store = makeStore();
  const mintedAt = new Date(1_700_000_000_000);
  const afterTtl = new Date(mintedAt.getTime() + SETUP_TICKET_TTL_MS + 1);
  const ticket = store.mint(binding, mintedAt);
  let err: SetupTicketError | undefined;
  try { await store.consume(ticket, binding, afterTtl); } catch (e) { err = e as SetupTicketError; }
  assert.ok(err);
  assert.equal(err.code, 'expired_ticket');
  assert.equal(err.status, 410);
});

test('consume rejects when subject / origin / recordHash do not match', async () => {
  const now = new Date();
  for (const bad of [
    { ...binding, subject: 'did:pkh:eip155:1:0x00000000000000000000000000000000000000Bb' },
    { ...binding, verifiedRequestingOrigin: 'https://attacker.example' },
    { ...binding, recordHash: 'b'.repeat(64) },
  ]) {
    const store = makeStore();
    const ticket = store.mint(binding, now);
    let err: SetupTicketError | undefined;
    try { await store.consume(ticket, bad, now); } catch (e) { err = e as SetupTicketError; }
    assert.ok(err, 'binding mismatch must throw');
    assert.equal(err.status, 403);
  }
});

test('consume rejects a ticket signed with a different server secret (HMAC)', async () => {
  const otherSecret = randomBytes(32);
  const minter = createSetupTicketStore(otherSecret, createInMemorySetupNonceStore());
  const verifier = makeStore();
  const now = new Date();
  const ticket = minter.mint(binding, now);
  let err: SetupTicketError | undefined;
  try { await verifier.consume(ticket, binding, now); } catch (e) { err = e as SetupTicketError; }
  assert.ok(err);
  assert.equal(err.code, 'bad_signature');
  assert.equal(err.status, 403);
});

test('consume rejects a malformed ticket envelope', async () => {
  const store = makeStore();
  let err: SetupTicketError | undefined;
  try { await store.consume('not-a-ticket', binding, new Date()); } catch (e) { err = e as SetupTicketError; }
  assert.ok(err);
  assert.equal(err.code, 'malformed_ticket');
  assert.equal(err.status, 400);
});

test('nonces are rejected after an API restart when the persistent store already has them', async () => {
  // The single-use property must survive restarts. Simulate it by
  // creating a fresh store that shares a nonce store (as Prisma would in production): the
  // previously-consumed ticket is refused even though the in-memory signer forgot it.
  const sharedNonceStore = createInMemorySetupNonceStore();
  const now = new Date();
  const firstBoot = createSetupTicketStore(secret, sharedNonceStore);
  const ticket = firstBoot.mint(binding, now);
  await firstBoot.consume(ticket, binding, now);
  const secondBoot = createSetupTicketStore(secret, sharedNonceStore);
  let err: SetupTicketError | undefined;
  try { await secondBoot.consume(ticket, binding, now); } catch (e) { err = e as SetupTicketError; }
  assert.ok(err, 'replay after restart must be refused');
  assert.equal(err.code, 'already_used');
});

test('decode returns the ticket mintedAt without consuming it', async () => {
  // The route uses `decode` to rebuild the canonical payload at the ticket's mintedAt so the
  // hash matches what the ticket was bound to. Calling decode must NOT burn the nonce.
  const store = makeStore();
  const mintedAt = new Date(1_700_000_000_000);
  const ticket = store.mint(binding, mintedAt);
  const decoded = store.decode(ticket);
  assert.equal(decoded.subject, binding.subject);
  assert.equal(decoded.verifiedRequestingOrigin, binding.verifiedRequestingOrigin);
  assert.equal(decoded.recordHash, binding.recordHash);
  assert.equal(decoded.mintedAt.getTime(), mintedAt.getTime());
  // Second decode works; consume still succeeds once.
  store.decode(ticket);
  await store.consume(ticket, binding, mintedAt);
});

test('decode rejects forged / malformed tickets without consuming', () => {
  const store = makeStore();
  assert.throws(() => store.decode('garbage'), SetupTicketError);
});

test('constructor refuses a signing secret shorter than 32 bytes (fail-closed)', () => {
  assert.throws(() => createSetupTicketStore(randomBytes(31), createInMemorySetupNonceStore()));
});
