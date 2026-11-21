import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  SETUP_TICKET_TTL_MS,
  SetupTicketError,
  createSetupTicketStore,
} from './tinycloud-setup-ticket';

const secret = randomBytes(32);
const binding = {
  subject: 'did:pkh:eip155:1:0x00000000000000000000000000000000000000Aa',
  verifiedRequestingOrigin: 'https://gk.example',
  recordHash: 'a'.repeat(64),
};

test('mint + consume with matching binding within TTL succeeds once', () => {
  const store = createSetupTicketStore(secret);
  const now = new Date();
  const ticket = store.mint(binding, now);
  assert.doesNotThrow(() => store.consume(ticket, binding, now));
  // Second consume: single-use.
  assert.throws(() => store.consume(ticket, binding, now), SetupTicketError);
});

test('consume rejects a ticket after TTL expires', () => {
  const store = createSetupTicketStore(secret);
  const mintedAt = new Date(1_700_000_000_000);
  const afterTtl = new Date(mintedAt.getTime() + SETUP_TICKET_TTL_MS + 1);
  const ticket = store.mint(binding, mintedAt);
  let err: SetupTicketError | undefined; try { store.consume(ticket, binding, afterTtl); } catch (e) { err = e as SetupTicketError; } assert.ok(err);
  assert.equal(err.code, 'expired_ticket');
  assert.equal(err.status, 410);
});

test('consume rejects when subject / origin / recordHash do not match (Bobbie C1 binding)', () => {
  const store = createSetupTicketStore(secret);
  const now = new Date();
  const ticket = store.mint(binding, now);
  const wrongSubject = { ...binding, subject: 'did:pkh:eip155:1:0x00000000000000000000000000000000000000Bb' };
  const wrongOrigin = { ...binding, verifiedRequestingOrigin: 'https://attacker.example' };
  const wrongHash = { ...binding, recordHash: 'b'.repeat(64) };
  for (const bad of [wrongSubject, wrongOrigin, wrongHash]) {
    const fresh = createSetupTicketStore(secret);
    const freshTicket = fresh.mint(binding, now);
    let err: SetupTicketError | undefined; try { fresh.consume(freshTicket, bad, now); } catch (e) { err = e as SetupTicketError; } assert.ok(err);
    assert.equal(err.status, 403);
  }
});

test('consume rejects a ticket signed with a different server secret', () => {
  const minter = createSetupTicketStore(secret);
  const verifier = createSetupTicketStore(randomBytes(32));
  const ticket = minter.mint(binding, new Date());
  let err: SetupTicketError | undefined; try { verifier.consume(ticket, binding, new Date()); } catch (e) { err = e as SetupTicketError; } assert.ok(err);
  assert.equal(err.code, 'bad_signature');
});

test('malformed ticket input is rejected without crashing', () => {
  const store = createSetupTicketStore(secret);
  for (const bad of ['', 'not-base64url', Buffer.from('not json', 'utf8').toString('base64url')]) {
    assert.throws(() => store.consume(bad, binding, new Date()), SetupTicketError);
  }
});

test('consumed-nonce set is pruned after TTL to bound memory', () => {
  const store = createSetupTicketStore(secret);
  const start = new Date(1_700_000_000_000);
  const ticket = store.mint(binding, start);
  store.consume(ticket, binding, start);
  assert.equal(store.consumedSize, 1);
  // Mint a second ticket well after TTL; its consume triggers the purge of the first nonce.
  const later = new Date(start.getTime() + SETUP_TICKET_TTL_MS * 2);
  const laterTicket = store.mint(binding, later);
  store.consume(laterTicket, binding, later);
  assert.equal(store.consumedSize, 1);
});
