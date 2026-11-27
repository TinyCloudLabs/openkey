import { secp256k1 } from '@noble/curves/secp256k1';

/**
 * EIP-191 `personal_sign` signer recovery, for checking that a signed SIWE
 * message was produced by the account that claims to own it. Self-contained
 * Keccak-256 (the original padding, not NIST SHA3) so core needs no extra
 * hashing dependency.
 */

const MASK_64 = (1n << 64n) - 1n;
const ROUNDS = 24;
const RATE_BYTES = 136;

// Rho rotation offsets and pi lane order for Rho-Pi (Keccak reference).
const ROTATIONS = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
const PI_LANES = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

// Iota round constants from the degree-8 LFSR of the Keccak specification.
const ROUND_CONSTANTS: bigint[] = (() => {
  const constants: bigint[] = [];
  let lfsr = 1;
  for (let round = 0; round < ROUNDS; round++) {
    let constant = 0n;
    for (let j = 0; j < 7; j++) {
      lfsr = ((lfsr << 1) ^ ((lfsr >> 7) * 0x71)) & 0xff;
      if (lfsr & 2) constant ^= 1n << BigInt((1 << j) - 1);
    }
    constants.push(constant);
  }
  return constants;
})();

function rotl64(value: bigint, shift: number): bigint {
  const left = BigInt(shift);
  return ((value << left) | (value >> (64n - left))) & MASK_64;
}

function keccakF(state: bigint[]): void {
  const columns = new Array<bigint>(5).fill(0n);
  const row = new Array<bigint>(5).fill(0n);
  for (let round = 0; round < ROUNDS; round++) {
    for (let x = 0; x < 5; x++) {
      columns[x] = state[x]! ^ state[x + 5]! ^ state[x + 10]! ^ state[x + 15]! ^ state[x + 20]!;
    }
    for (let x = 0; x < 5; x++) {
      const delta = columns[(x + 4) % 5]! ^ rotl64(columns[(x + 1) % 5]!, 1);
      for (let y = 0; y < 25; y += 5) state[y + x] = state[y + x]! ^ delta;
    }
    let carried = state[1]!;
    for (let i = 0; i < 24; i++) {
      const lane = PI_LANES[i]!;
      const next = state[lane]!;
      state[lane] = rotl64(carried, ROTATIONS[i]!);
      carried = next;
    }
    for (let y = 0; y < 25; y += 5) {
      for (let x = 0; x < 5; x++) row[x] = state[y + x]!;
      for (let x = 0; x < 5; x++) {
        state[y + x] = state[y + x]! ^ (~row[(x + 1) % 5]! & row[(x + 2) % 5]!);
      }
    }
    state[0] = state[0]! ^ ROUND_CONSTANTS[round]!;
  }
}

/** Keccak-256 of `data`. */
export function keccak256(data: Uint8Array): Uint8Array {
  const padded = new Uint8Array(Math.ceil((data.length + 1) / RATE_BYTES) * RATE_BYTES);
  padded.set(data);
  padded[data.length]! ^= 0x01;
  padded[padded.length - 1]! ^= 0x80;

  const state = new Array<bigint>(25).fill(0n);
  for (let offset = 0; offset < padded.length; offset += RATE_BYTES) {
    for (let lane = 0; lane < RATE_BYTES / 8; lane++) {
      let word = 0n;
      for (let byte = 7; byte >= 0; byte--) word = (word << 8n) | BigInt(padded[offset + lane * 8 + byte]!);
      state[lane] = state[lane]! ^ word;
    }
    keccakF(state);
  }

  const out = new Uint8Array(32);
  for (let lane = 0; lane < 4; lane++) {
    let word = state[lane]!;
    for (let byte = 0; byte < 8; byte++) {
      out[lane * 8 + byte] = Number(word & 0xffn);
      word >>= 8n;
    }
  }
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

/**
 * Recover the lowercase `0x` address that signed `message` with EIP-191
 * `personal_sign`. Returns `null` for a malformed or unrecoverable signature.
 */
export function recoverPersonalSignAddress(message: string, signature: string): string | null {
  if (!/^0x[0-9a-fA-F]{130}$/.test(signature)) return null;
  try {
    const body = new TextEncoder().encode(message);
    const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${body.length}`);
    const prefixed = new Uint8Array(prefix.length + body.length);
    prefixed.set(prefix);
    prefixed.set(body, prefix.length);
    const digest = keccak256(prefixed);

    const raw = hexToBytes(signature.slice(2));
    let recovery = raw[64]!;
    if (recovery >= 27) recovery -= 27;
    if (recovery !== 0 && recovery !== 1) return null;
    const publicKey = secp256k1.Signature.fromCompact(raw.slice(0, 64))
      .addRecoveryBit(recovery)
      .recoverPublicKey(digest)
      .toRawBytes(false);
    return `0x${bytesToHex(keccak256(publicKey.slice(1)).slice(12))}`;
  } catch {
    return null;
  }
}
