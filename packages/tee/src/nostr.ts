// Nostr identity custody - secp256k1 Schnorr signing (BIP-340 / NIP-01)
//
// This is a structurally independent asset type from the Ethereum ECDSA
// keys in wallet.ts: Nostr identities are signed with BIP-340 Schnorr
// signatures, not ECDSA, and use x-only (32-byte) public keys.
import { createHash } from 'crypto';
import { schnorr } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/curves/abstract/utils';
import { bech32 } from '@scure/base';
import { unseal } from './index';

/** NIP-01 unsigned event template. `tags` is an array of string arrays. */
export interface UnsignedNostrEvent {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}

/** A fully signed NIP-01 event. */
export interface SignedNostrEvent extends UnsignedNostrEvent {
  id: string;
  sig: string;
}

export interface NostrKeypair {
  /** Hex-encoded 32-byte secp256k1 secret scalar. Never log or persist unsealed. */
  secretKeyHex: string;
  /** Hex-encoded 32-byte BIP-340 x-only public key. */
  pubkeyHex: string;
  /** Bech32 `npub1...` encoding of the public key (NIP-19). */
  npub: string;
}

/** Everything needed to unseal and use a custodied Nostr secret for exactly one signing operation. */
export interface SealedNostrSecret {
  /** Base64 sealed blob produced by `seal()` in ./index.ts. */
  sealedSecret: string;
  /** 32-byte TEE-derived sealing key for this record. */
  sealingKey: Uint8Array;
  /** The pubkeyHex on record for this key. The unsealed secret must derive this exact pubkey. */
  expectedPubkeyHex: string;
}

function normalizeHex(value: string): string {
  return value.trim().toLowerCase();
}

/**
 * Generate a new Nostr keypair.
 *
 * Uses the noble library's own secret-key generator (`schnorr.utils.randomPrivateKey`),
 * which draws uniform randomness over the scalar field rather than truncating raw
 * random bytes - the standard noble-curves technique for unbiased key generation.
 */
export function generateNostrKeypair(): NostrKeypair {
  const secretKey = schnorr.utils.randomPrivateKey();
  try {
    const pubkeyBytes = schnorr.getPublicKey(secretKey);
    const pubkeyHex = bytesToHex(pubkeyBytes);
    const npub = bech32.encode('npub', bech32.toWords(pubkeyBytes));
    return {
      secretKeyHex: bytesToHex(secretKey),
      pubkeyHex,
      npub,
    };
  } finally {
    secretKey.fill(0);
  }
}

/**
 * Exact NIP-01 serialization: `[0,pubkey,created_at,kind,tags,content]`.
 * No extra whitespace; relies on JSON.stringify's standard escaping, which
 * matches the NIP-01 reference serialization for the field types used here.
 */
export function canonicalizeNip01(event: UnsignedNostrEvent): string {
  return JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ]);
}

/** sha256(canonical NIP-01 serialization), hex-encoded. This is the NIP-01 event id. */
export function computeEventId(event: UnsignedNostrEvent): string {
  const canonical = canonicalizeNip01(event);
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Unseal a custodied Nostr secret, verify it derives the expected pubkey,
 * sign the event id per BIP-340, and zero the unsealed secret material.
 *
 * Fails closed (throws) if:
 *  - the unsealed secret does not derive `expectedPubkeyHex`, or
 *  - the event template's own `pubkey` field does not match `expectedPubkeyHex`.
 *
 * The unsealed hex string returned by `unseal()` cannot itself be zeroed
 * (JS strings are immutable); this function converts it to a Uint8Array as
 * its very first step and zeroes that buffer (and no other derived buffers)
 * in a `finally` block so it does not outlive the signing call.
 */
export async function signNostrEvent(
  sealed: SealedNostrSecret,
  unsignedEvent: UnsignedNostrEvent,
): Promise<SignedNostrEvent> {
  const expectedPubkeyHex = normalizeHex(sealed.expectedPubkeyHex);
  const secretHex = await unseal(sealed.sealedSecret, sealed.sealingKey);

  let secretBytes: Uint8Array | null = null;
  try {
    secretBytes = hexToBytes(secretHex);

    const derivedPubkeyHex = normalizeHex(bytesToHex(schnorr.getPublicKey(secretBytes)));
    if (derivedPubkeyHex !== expectedPubkeyHex) {
      throw new Error('nostr_key_mismatch: unsealed secret does not derive the expected pubkey');
    }
    if (normalizeHex(unsignedEvent.pubkey) !== expectedPubkeyHex) {
      throw new Error('nostr_key_mismatch: event template pubkey does not match the signing key');
    }

    const id = computeEventId(unsignedEvent);
    const sig = bytesToHex(schnorr.sign(hexToBytes(id), secretBytes));

    return {
      ...unsignedEvent,
      id,
      sig,
    };
  } finally {
    secretBytes?.fill(0);
  }
}

// The exact kind allowlist this signing slice supports: 22242 (NIP-42 relay
// auth) and 9 (channel message). Callers (API routes) enforce this against
// incoming requests; this module only signs whatever event it is given.
export const SUPPORTED_NOSTR_KINDS: ReadonlySet<number> = new Set([22242, 9]);
