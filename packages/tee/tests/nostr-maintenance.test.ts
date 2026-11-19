import { expect, test } from 'bun:test';
import { verifyEvent } from 'nostr-tools/pure';
import * as nostr from '../src/nostr';

const secret = Buffer.alloc(32, 7).toString('hex');

test('derives the identity used to verify a managed Nostr record', async () => {
  const pubkey = nostr.deriveNostrPubkey(secret);
  const event = await nostr.signNostrEvent({
    unsealSecret: async () => secret,
    expectedPubkeyHex: pubkey,
  }, { pubkey, created_at: 1700000000, kind: 9, tags: [], content: 'TEST ONLY maintenance signing' });
  expect(verifyEvent(event)).toBe(true);
});

test('refuses a mismatched record even with an injected record-bound unsealer', async () => {
  await expect(nostr.signNostrEvent({
    unsealSecret: async () => secret,
    expectedPubkeyHex: '00'.repeat(32),
  }, { pubkey: '00'.repeat(32), created_at: 1700000000, kind: 9, tags: [], content: 'TEST ONLY refusal' })).rejects.toThrow('nostr_key_mismatch');
});
