// NIP-44 v2 encryption inside the custody boundary.
//
// Implements the exact NIP-44 v2 construction (secp256k1 ECDH ->
// HKDF-SHA256 -> ChaCha20 + HMAC-SHA256 with padded plaintexts) against the
// audited @noble primitives already used for signing. nostr-tools' own
// nip44 module is used only as an independent oracle in tests, never at
// runtime.
//
// Callers outside this package go through the *WithSealedKey wrappers,
// which unseal a custodied secret for exactly one operation and zero both
// the secret and the derived conversation key before returning. A
// conversation key is never returned to any caller.
import { secp256k1 } from '@noble/curves/secp256k1';
import { hexToBytes } from '@noble/curves/abstract/utils';
import { extract, expand } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { chacha20 } from '@noble/ciphers/chacha.js';
import { randomBytes } from 'crypto';
import { withUnsealedNostrSecret, type SealedNostrSecret } from './nostr';

export const NIP44_MIN_PLAINTEXT_BYTES = 1;
export const NIP44_MAX_PLAINTEXT_BYTES = 65535;
// Base64 payload length bounds fixed by the NIP-44 spec.
const MIN_PAYLOAD_CHARS = 132;
const MAX_PAYLOAD_CHARS = 87472;
// Decoded payload: version (1) + nonce (32) + ciphertext + mac (32).
const MIN_DECODED_BYTES = 99;
const MAX_DECODED_BYTES = 65603;
const VERSION = 2;

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder('utf-8');

const PUBKEY_HEX_RE = /^[0-9a-f]{64}$/;

function assertPeerPubkey(peerPubkeyHex: string): string {
  const normalized = peerPubkeyHex.trim().toLowerCase();
  if (!PUBKEY_HEX_RE.test(normalized)) {
    throw new Error('nip44_invalid_peer: peer pubkey must be 64 hex characters');
  }
  return normalized;
}

/**
 * NIP-44 v2 conversation key: HKDF-extract(sha256, ECDH-x, "nip44-v2").
 * Symmetric in the two parties. Exported for tests; runtime callers use the
 * sealed-key wrappers below and never see this value.
 */
export function getConversationKey(secretKey: Uint8Array, peerPubkeyHex: string): Uint8Array {
  const peer = assertPeerPubkey(peerPubkeyHex);
  // Throws for x-coordinates that are not on the curve - fail closed.
  const sharedPoint = secp256k1.getSharedSecret(secretKey, hexToBytes(`02${peer}`), true);
  const sharedX = sharedPoint.subarray(1, 33);
  try {
    return extract(sha256, sharedX, utf8Encoder.encode('nip44-v2'));
  } finally {
    sharedPoint.fill(0);
  }
}

function getMessageKeys(conversationKey: Uint8Array, nonce: Uint8Array) {
  const keys = expand(sha256, conversationKey, nonce, 76);
  return {
    chachaKey: keys.subarray(0, 32),
    chachaNonce: keys.subarray(32, 44),
    hmacKey: keys.subarray(44, 76),
    zero: () => keys.fill(0),
  };
}

function calcPaddedLen(unpaddedLen: number): number {
  if (unpaddedLen <= 32) return 32;
  const nextPower = 1 << (Math.floor(Math.log2(unpaddedLen - 1)) + 1);
  const chunk = nextPower <= 256 ? 32 : nextPower / 8;
  return chunk * (Math.floor((unpaddedLen - 1) / chunk) + 1);
}

function pad(plaintext: string): Uint8Array {
  const unpadded = utf8Encoder.encode(plaintext);
  if (unpadded.length < NIP44_MIN_PLAINTEXT_BYTES || unpadded.length > NIP44_MAX_PLAINTEXT_BYTES) {
    throw new Error('nip44_invalid_plaintext: plaintext length out of range');
  }
  const padded = new Uint8Array(2 + calcPaddedLen(unpadded.length));
  padded[0] = (unpadded.length >> 8) & 0xff;
  padded[1] = unpadded.length & 0xff;
  padded.set(unpadded, 2);
  unpadded.fill(0);
  return padded;
}

function unpad(padded: Uint8Array): string {
  const unpaddedLen = (padded[0]! << 8) | padded[1]!;
  if (
    unpaddedLen < NIP44_MIN_PLAINTEXT_BYTES
    || unpaddedLen > NIP44_MAX_PLAINTEXT_BYTES
    || padded.length !== 2 + calcPaddedLen(unpaddedLen)
  ) {
    throw new Error('nip44_invalid_padding');
  }
  return utf8Decoder.decode(padded.subarray(2, 2 + unpaddedLen));
}

function hmacAad(hmacKey: Uint8Array, message: Uint8Array, aad: Uint8Array): Uint8Array {
  const combined = new Uint8Array(aad.length + message.length);
  combined.set(aad, 0);
  combined.set(message, aad.length);
  try {
    return hmac(sha256, hmacKey, combined);
  } finally {
    combined.fill(0);
  }
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Structural (keyless) validation of a NIP-44 v2 payload: strict base64,
 * spec length bounds, version byte 2. Used by the API's kind-30300 content
 * validator to reject non-ciphertext content before it reaches a signature.
 */
export function isValidNip44PayloadShape(payload: unknown): payload is string {
  if (typeof payload !== 'string') return false;
  if (payload.length < MIN_PAYLOAD_CHARS || payload.length > MAX_PAYLOAD_CHARS) return false;
  if (!BASE64_RE.test(payload)) return false;
  let decoded: Buffer;
  try {
    decoded = Buffer.from(payload, 'base64');
  } catch {
    return false;
  }
  if (decoded.toString('base64') !== payload) return false;
  if (decoded.length < MIN_DECODED_BYTES || decoded.length > MAX_DECODED_BYTES) return false;
  return decoded[0] === VERSION;
}

/** NIP-44 v2 encrypt. `nonce` is injectable for tests only. */
export function nip44Encrypt(
  conversationKey: Uint8Array,
  plaintext: string,
  nonce: Uint8Array = new Uint8Array(randomBytes(32)),
): string {
  if (nonce.length !== 32) throw new Error('nip44_invalid_nonce');
  const keys = getMessageKeys(conversationKey, nonce);
  const padded = pad(plaintext);
  try {
    const ciphertext = chacha20(keys.chachaKey, keys.chachaNonce, padded);
    const mac = hmacAad(keys.hmacKey, ciphertext, nonce);
    const payload = new Uint8Array(1 + 32 + ciphertext.length + 32);
    payload[0] = VERSION;
    payload.set(nonce, 1);
    payload.set(ciphertext, 33);
    payload.set(mac, 33 + ciphertext.length);
    return Buffer.from(payload).toString('base64');
  } finally {
    padded.fill(0);
    keys.zero();
  }
}

/** NIP-44 v2 decrypt. Fails closed on any structural or MAC mismatch. */
export function nip44Decrypt(conversationKey: Uint8Array, payload: string): string {
  if (!isValidNip44PayloadShape(payload)) {
    throw new Error('nip44_invalid_payload');
  }
  const decoded = new Uint8Array(Buffer.from(payload, 'base64'));
  const nonce = decoded.subarray(1, 33);
  const ciphertext = decoded.subarray(33, decoded.length - 32);
  const mac = decoded.subarray(decoded.length - 32);
  const keys = getMessageKeys(conversationKey, nonce);
  let padded: Uint8Array | null = null;
  try {
    const expectedMac = hmacAad(keys.hmacKey, ciphertext, nonce);
    if (!constantTimeEqual(expectedMac, mac)) {
      throw new Error('nip44_invalid_mac');
    }
    padded = chacha20(keys.chachaKey, keys.chachaNonce, ciphertext);
    return unpad(padded);
  } finally {
    padded?.fill(0);
    keys.zero();
  }
}

/**
 * Encrypt with a custodied secret. The unsealed secret and the derived
 * conversation key exist only for the duration of this call and are zeroed
 * before it returns; only the ciphertext payload leaves the boundary.
 */
export async function nip44EncryptWithSealedKey(
  sealed: SealedNostrSecret,
  peerPubkeyHex: string,
  plaintext: string,
): Promise<string> {
  return withUnsealedNostrSecret(sealed, (secretBytes) => {
    const conversationKey = getConversationKey(secretBytes, peerPubkeyHex);
    try {
      return nip44Encrypt(conversationKey, plaintext);
    } finally {
      conversationKey.fill(0);
    }
  });
}

/**
 * Decrypt with a custodied secret. Same zeroing guarantees as encrypt; only
 * the bounded plaintext leaves the boundary.
 */
export async function nip44DecryptWithSealedKey(
  sealed: SealedNostrSecret,
  peerPubkeyHex: string,
  payload: string,
): Promise<string> {
  return withUnsealedNostrSecret(sealed, (secretBytes) => {
    const conversationKey = getConversationKey(secretBytes, peerPubkeyHex);
    try {
      return nip44Decrypt(conversationKey, payload);
    } finally {
      conversationKey.fill(0);
    }
  });
}
