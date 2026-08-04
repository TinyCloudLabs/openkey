import { describe, expect, test } from 'bun:test';
import { getEventHash, serializeEvent, verifyEvent, type Event as NostrToolsEvent } from 'nostr-tools/pure';
import { seal } from '../src/index';
import {
  canonicalizeNip01,
  computeEventId,
  generateNostrKeypair,
  signNostrEvent,
  type SealedNostrSecret,
  type UnsignedNostrEvent,
} from '../src/nostr';

const FIXED_VECTOR: UnsignedNostrEvent = {
  pubkey: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
  created_at: 1700000000,
  kind: 1,
  tags: [['relay', 'wss://relay.example.com'], ['challenge', 'abc123']],
  content: 'hello "nostr" \n world',
};

describe('canonicalizeNip01', () => {
  test('matches the exact NIP-01 [0,pubkey,created_at,kind,tags,content] serialization, hand-verified', () => {
    const expected =
      '[0,"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",1700000000,1,[["relay","wss://relay.example.com"],["challenge","abc123"]],"hello \\"nostr\\" \\n world"]';
    expect(canonicalizeNip01(FIXED_VECTOR)).toBe(expected);
  });

  test('produces the exact same bytes nostr-tools would serialize for the same template', () => {
    // nostr-tools' serializeEvent implements the same NIP-01 spec independently;
    // cross-checking against it validates canonicalizeNip01 without trusting our
    // own hand-written expected string alone.
    expect(canonicalizeNip01(FIXED_VECTOR)).toBe(serializeEvent(FIXED_VECTOR));
  });

  test('has no incidental pretty-printing whitespace around JSON separators', () => {
    const serialized = canonicalizeNip01({ ...FIXED_VECTOR, content: 'no-whitespace-content' });
    expect(serialized).not.toMatch(/,\s|:\s/);
  });
});

describe('computeEventId', () => {
  test('is the sha256 hex digest of the canonical serialization', () => {
    const id = computeEventId(FIXED_VECTOR);
    expect(id).toMatch(/^[0-9a-f]{64}$/);
  });

  test('matches nostr-tools getEventHash for the same template', () => {
    expect(computeEventId(FIXED_VECTOR)).toBe(getEventHash(FIXED_VECTOR));
  });

  test('changes when any field changes', () => {
    const base = computeEventId(FIXED_VECTOR);
    expect(computeEventId({ ...FIXED_VECTOR, content: 'different' })).not.toBe(base);
    expect(computeEventId({ ...FIXED_VECTOR, kind: 9 })).not.toBe(base);
    expect(computeEventId({ ...FIXED_VECTOR, created_at: FIXED_VECTOR.created_at + 1 })).not.toBe(base);
    expect(computeEventId({ ...FIXED_VECTOR, tags: [] })).not.toBe(base);
  });
});

async function sealSecret(secretKeyHex: string): Promise<{ sealedSecret: string; sealingKey: Uint8Array }> {
  const sealingKey = new Uint8Array(32).fill(7);
  const sealedSecret = await seal(secretKeyHex, sealingKey);
  return { sealedSecret, sealingKey };
}

describe('signNostrEvent', () => {
  test('sign-then-verify round trip is independently valid per nostr-tools verifyEvent', async () => {
    const keypair = generateNostrKeypair();
    const { sealedSecret, sealingKey } = await sealSecret(keypair.secretKeyHex);
    const sealed: SealedNostrSecret = { sealedSecret, sealingKey, expectedPubkeyHex: keypair.pubkeyHex };

    const unsignedEvent: UnsignedNostrEvent = {
      pubkey: keypair.pubkeyHex,
      created_at: Math.floor(Date.now() / 1000),
      kind: 22242,
      tags: [['relay', 'wss://relay.example.com'], ['challenge', 'xyz']],
      content: '',
    };

    const signed = await signNostrEvent(sealed, unsignedEvent);

    expect(signed.id).toBe(computeEventId(unsignedEvent));
    expect(signed.pubkey).toBe(keypair.pubkeyHex);
    expect(signed.sig).toMatch(/^[0-9a-f]{128}$/);

    // Cross-check with an independent implementation - never sign/generate
    // with nostr-tools, only verify.
    expect(verifyEvent(signed as NostrToolsEvent)).toBe(true);
  });

  test('tampering with content after signing fails independent verification', async () => {
    const keypair = generateNostrKeypair();
    const { sealedSecret, sealingKey } = await sealSecret(keypair.secretKeyHex);
    const sealed: SealedNostrSecret = { sealedSecret, sealingKey, expectedPubkeyHex: keypair.pubkeyHex };
    const unsignedEvent: UnsignedNostrEvent = {
      pubkey: keypair.pubkeyHex,
      created_at: Math.floor(Date.now() / 1000),
      kind: 9,
      tags: [],
      content: 'original',
    };
    const signed = await signNostrEvent(sealed, unsignedEvent);

    expect(verifyEvent({ ...signed, content: 'tampered' } as NostrToolsEvent)).toBe(false);
  });

  test('tampering with kind after signing fails independent verification', async () => {
    const keypair = generateNostrKeypair();
    const { sealedSecret, sealingKey } = await sealSecret(keypair.secretKeyHex);
    const sealed: SealedNostrSecret = { sealedSecret, sealingKey, expectedPubkeyHex: keypair.pubkeyHex };
    const unsignedEvent: UnsignedNostrEvent = {
      pubkey: keypair.pubkeyHex,
      created_at: Math.floor(Date.now() / 1000),
      kind: 9,
      tags: [],
      content: 'hello',
    };
    const signed = await signNostrEvent(sealed, unsignedEvent);

    expect(verifyEvent({ ...signed, kind: 22242 } as NostrToolsEvent)).toBe(false);
  });

  test('tampering with tags after signing fails independent verification', async () => {
    const keypair = generateNostrKeypair();
    const { sealedSecret, sealingKey } = await sealSecret(keypair.secretKeyHex);
    const sealed: SealedNostrSecret = { sealedSecret, sealingKey, expectedPubkeyHex: keypair.pubkeyHex };
    const unsignedEvent: UnsignedNostrEvent = {
      pubkey: keypair.pubkeyHex,
      created_at: Math.floor(Date.now() / 1000),
      kind: 22242,
      tags: [['relay', 'wss://relay.example.com'], ['challenge', 'xyz']],
      content: '',
    };
    const signed = await signNostrEvent(sealed, unsignedEvent);

    expect(
      verifyEvent({ ...signed, tags: [['relay', 'wss://evil.example.com'], ['challenge', 'xyz']] } as NostrToolsEvent),
    ).toBe(false);
  });

  test('tampering with pubkey after signing fails independent verification', async () => {
    const keypairA = generateNostrKeypair();
    const keypairB = generateNostrKeypair();
    const { sealedSecret, sealingKey } = await sealSecret(keypairA.secretKeyHex);
    const sealed: SealedNostrSecret = { sealedSecret, sealingKey, expectedPubkeyHex: keypairA.pubkeyHex };
    const unsignedEvent: UnsignedNostrEvent = {
      pubkey: keypairA.pubkeyHex,
      created_at: Math.floor(Date.now() / 1000),
      kind: 9,
      tags: [],
      content: 'hello',
    };
    const signed = await signNostrEvent(sealed, unsignedEvent);

    expect(verifyEvent({ ...signed, pubkey: keypairB.pubkeyHex } as NostrToolsEvent)).toBe(false);
  });

  test('tampering with created_at after signing fails independent verification', async () => {
    const keypair = generateNostrKeypair();
    const { sealedSecret, sealingKey } = await sealSecret(keypair.secretKeyHex);
    const sealed: SealedNostrSecret = { sealedSecret, sealingKey, expectedPubkeyHex: keypair.pubkeyHex };
    const unsignedEvent: UnsignedNostrEvent = {
      pubkey: keypair.pubkeyHex,
      created_at: Math.floor(Date.now() / 1000),
      kind: 9,
      tags: [],
      content: 'hello',
    };
    const signed = await signNostrEvent(sealed, unsignedEvent);

    expect(verifyEvent({ ...signed, created_at: signed.created_at + 1 } as NostrToolsEvent)).toBe(false);
  });

  test('fails closed when the unsealed secret does not derive the stored pubkey', async () => {
    const actualKeypair = generateNostrKeypair();
    const impersonatedPubkeyHex = generateNostrKeypair().pubkeyHex;
    const { sealedSecret, sealingKey } = await sealSecret(actualKeypair.secretKeyHex);

    // A grant record whose pubkeyHex does not actually match the sealed secret
    // (e.g. DB row corruption or a sealing-context mixup) must never sign.
    const sealed: SealedNostrSecret = { sealedSecret, sealingKey, expectedPubkeyHex: impersonatedPubkeyHex };
    const unsignedEvent: UnsignedNostrEvent = {
      pubkey: impersonatedPubkeyHex,
      created_at: Math.floor(Date.now() / 1000),
      kind: 9,
      tags: [],
      content: 'hello',
    };

    await expect(signNostrEvent(sealed, unsignedEvent)).rejects.toThrow(/nostr_key_mismatch/);
  });

  test('fails closed when the event template pubkey does not match the signing key', async () => {
    const keypair = generateNostrKeypair();
    const otherPubkeyHex = generateNostrKeypair().pubkeyHex;
    const { sealedSecret, sealingKey } = await sealSecret(keypair.secretKeyHex);
    const sealed: SealedNostrSecret = { sealedSecret, sealingKey, expectedPubkeyHex: keypair.pubkeyHex };
    const unsignedEvent: UnsignedNostrEvent = {
      pubkey: otherPubkeyHex,
      created_at: Math.floor(Date.now() / 1000),
      kind: 9,
      tags: [],
      content: 'hello',
    };

    await expect(signNostrEvent(sealed, unsignedEvent)).rejects.toThrow(/nostr_key_mismatch/);
  });
});

describe('generateNostrKeypair', () => {
  test('produces a well-formed x-only pubkey and matching npub', () => {
    const keypair = generateNostrKeypair();
    expect(keypair.secretKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(keypair.pubkeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(keypair.npub.startsWith('npub1')).toBe(true);
  });

  test('generates distinct keys on repeated calls', () => {
    const a = generateNostrKeypair();
    const b = generateNostrKeypair();
    expect(a.secretKeyHex).not.toBe(b.secretKeyHex);
    expect(a.pubkeyHex).not.toBe(b.pubkeyHex);
  });
});
