import { describe, expect, test } from 'bun:test';
import { v2 as oracleNip44 } from 'nostr-tools/nip44';
import { hexToBytes } from '@noble/curves/abstract/utils';
import { seal } from '../src/index';
import { generateNostrKeypair, type SealedNostrSecret } from '../src/nostr';
import {
  getConversationKey,
  isValidNip44PayloadShape,
  nip44Decrypt,
  nip44Encrypt,
  nip44DecryptWithSealedKey,
  nip44EncryptWithSealedKey,
  NIP44_MAX_PLAINTEXT_BYTES,
} from '../src/nip44';

// nostr-tools is used strictly as an independent oracle (verify/interop),
// never as the implementation under test.

function keypairWithBytes() {
  const keypair = generateNostrKeypair();
  return { ...keypair, secretBytes: hexToBytes(keypair.secretKeyHex) };
}

async function makeSealed(keypair: { secretKeyHex: string; pubkeyHex: string }): Promise<SealedNostrSecret> {
  const sealingKey = new Uint8Array(32).fill(7);
  const sealedSecret = await seal(keypair.secretKeyHex, sealingKey);
  return { sealedSecret, sealingKey, expectedPubkeyHex: keypair.pubkeyHex };
}

function tamperPayloadByte(payload: string, index: number): string {
  const decoded = Buffer.from(payload, 'base64');
  decoded[index] = decoded[index]! ^ 0x01;
  return decoded.toString('base64');
}

describe('getConversationKey', () => {
  test('matches nostr-tools nip44 v2 oracle for random keypairs', () => {
    for (let i = 0; i < 5; i++) {
      const a = keypairWithBytes();
      const b = keypairWithBytes();
      const ours = getConversationKey(a.secretBytes, b.pubkeyHex);
      const oracle = oracleNip44.utils.getConversationKey(hexToBytes(a.secretKeyHex), b.pubkeyHex);
      expect(Buffer.from(ours).toString('hex')).toBe(Buffer.from(oracle).toString('hex'));
    }
  });

  test('is symmetric: A->B equals B->A', () => {
    const a = keypairWithBytes();
    const b = keypairWithBytes();
    const ab = getConversationKey(a.secretBytes, b.pubkeyHex);
    const ba = getConversationKey(b.secretBytes, a.pubkeyHex);
    expect(Buffer.from(ab).toString('hex')).toBe(Buffer.from(ba).toString('hex'));
  });

  test('rejects a non-hex peer pubkey', () => {
    const a = keypairWithBytes();
    expect(() => getConversationKey(a.secretBytes, 'zz'.repeat(32))).toThrow(/nip44_invalid_peer/);
  });

  test('rejects a 63-character peer pubkey', () => {
    const a = keypairWithBytes();
    const b = keypairWithBytes();
    expect(() => getConversationKey(a.secretBytes, b.pubkeyHex.slice(0, 63))).toThrow(/nip44_invalid_peer/);
  });

  test('normalizes and accepts an uppercase peer pubkey', () => {
    const a = keypairWithBytes();
    const b = keypairWithBytes();
    const lower = getConversationKey(a.secretBytes, b.pubkeyHex);
    const upper = getConversationKey(a.secretBytes, b.pubkeyHex.toUpperCase());
    expect(Buffer.from(upper).toString('hex')).toBe(Buffer.from(lower).toString('hex'));
  });

  test('fails closed for an off-curve x-coordinate (ff * 32)', () => {
    const a = keypairWithBytes();
    expect(() => getConversationKey(a.secretBytes, 'ff'.repeat(32))).toThrow();
  });
});

describe('nip44Encrypt / nip44Decrypt round trips against the oracle', () => {
  test('our encrypt -> oracle decrypt (peer case)', () => {
    const a = keypairWithBytes();
    const b = keypairWithBytes();
    const conversationKey = getConversationKey(a.secretBytes, b.pubkeyHex);
    const oracleKey = oracleNip44.utils.getConversationKey(hexToBytes(b.secretKeyHex), a.pubkeyHex);
    const plaintext = 'hello nip44 \u{1F511} unicode and "quotes"';
    const payload = nip44Encrypt(conversationKey, plaintext);
    expect(oracleNip44.decrypt(payload, oracleKey)).toBe(plaintext);
  });

  test('oracle encrypt -> our decrypt (peer case)', () => {
    const a = keypairWithBytes();
    const b = keypairWithBytes();
    const oracleKey = oracleNip44.utils.getConversationKey(hexToBytes(a.secretKeyHex), b.pubkeyHex);
    const conversationKey = getConversationKey(b.secretBytes, a.pubkeyHex);
    const plaintext = 'oracle wrote this';
    const payload = oracleNip44.encrypt(plaintext, oracleKey);
    expect(nip44Decrypt(conversationKey, payload)).toBe(plaintext);
  });

  test('self-encryption round trip (own pubkey as peer) interoperates with the oracle', () => {
    const a = keypairWithBytes();
    const conversationKey = getConversationKey(a.secretBytes, a.pubkeyHex);
    const oracleKey = oracleNip44.utils.getConversationKey(hexToBytes(a.secretKeyHex), a.pubkeyHex);
    const plaintext = 'note to self';
    expect(oracleNip44.decrypt(nip44Encrypt(conversationKey, plaintext), oracleKey)).toBe(plaintext);
    expect(nip44Decrypt(conversationKey, oracleNip44.encrypt(plaintext, oracleKey))).toBe(plaintext);
  });

  test('our encrypt -> our decrypt across a range of padding boundary lengths', () => {
    const a = keypairWithBytes();
    const b = keypairWithBytes();
    const conversationKey = getConversationKey(a.secretBytes, b.pubkeyHex);
    for (const len of [1, 31, 32, 33, 255, 256, 257, 1000]) {
      const plaintext = 'x'.repeat(len);
      expect(nip44Decrypt(conversationKey, nip44Encrypt(conversationKey, plaintext))).toBe(plaintext);
    }
  });
});

describe('plaintext bounds', () => {
  const a = keypairWithBytes();
  const b = keypairWithBytes();
  const conversationKey = getConversationKey(a.secretBytes, b.pubkeyHex);

  test('empty plaintext is rejected', () => {
    expect(() => nip44Encrypt(conversationKey, '')).toThrow(/nip44_invalid_plaintext/);
  });

  test('65535-byte plaintext (max) round trips', () => {
    const plaintext = 'a'.repeat(NIP44_MAX_PLAINTEXT_BYTES);
    const payload = nip44Encrypt(conversationKey, plaintext);
    expect(nip44Decrypt(conversationKey, payload)).toBe(plaintext);
  });

  test('65536-byte plaintext is rejected', () => {
    expect(() => nip44Encrypt(conversationKey, 'a'.repeat(NIP44_MAX_PLAINTEXT_BYTES + 1))).toThrow(
      /nip44_invalid_plaintext/,
    );
  });
});

describe('isValidNip44PayloadShape', () => {
  const a = keypairWithBytes();
  const b = keypairWithBytes();
  const conversationKey = getConversationKey(a.secretBytes, b.pubkeyHex);
  const validPayload = nip44Encrypt(conversationKey, 'shape check plaintext');

  test('accepts a genuine payload', () => {
    expect(isValidNip44PayloadShape(validPayload)).toBe(true);
  });

  test('rejects non-strings', () => {
    expect(isValidNip44PayloadShape(12345)).toBe(false);
    expect(isValidNip44PayloadShape(null)).toBe(false);
    expect(isValidNip44PayloadShape(undefined)).toBe(false);
    expect(isValidNip44PayloadShape({ payload: validPayload })).toBe(false);
  });

  test('rejects non-base64 content of plausible length', () => {
    expect(isValidNip44PayloadShape('!'.repeat(132))).toBe(false);
    expect(isValidNip44PayloadShape('#' + validPayload)).toBe(false);
    expect(isValidNip44PayloadShape(validPayload.slice(0, -1) + ' ')).toBe(false);
  });

  test('rejects a wrong version byte, and nip44Decrypt refuses it too', () => {
    const decoded = Buffer.from(validPayload, 'base64');
    decoded[0] = 1;
    const wrongVersion = decoded.toString('base64');
    expect(isValidNip44PayloadShape(wrongVersion)).toBe(false);
    expect(() => nip44Decrypt(conversationKey, wrongVersion)).toThrow(/nip44_invalid_payload/);
  });

  test('rejects payloads below the minimum decoded length', () => {
    const short = Buffer.alloc(98);
    short[0] = 2;
    const shortPayload = short.toString('base64');
    expect(isValidNip44PayloadShape(shortPayload)).toBe(false);
    expect(() => nip44Decrypt(conversationKey, shortPayload)).toThrow(/nip44_invalid_payload/);
  });

  test('rejects payloads above the maximum decoded length', () => {
    const long = Buffer.alloc(65604);
    long[0] = 2;
    expect(isValidNip44PayloadShape(long.toString('base64'))).toBe(false);
  });

  test('rejects payloads below the minimum character length', () => {
    expect(isValidNip44PayloadShape('AgAA')).toBe(false);
    expect(() => nip44Decrypt(conversationKey, 'AgAA')).toThrow(/nip44_invalid_payload/);
  });
});

describe('nip44Decrypt failure modes', () => {
  const a = keypairWithBytes();
  const b = keypairWithBytes();
  const c = keypairWithBytes();
  const conversationKey = getConversationKey(a.secretBytes, b.pubkeyHex);
  const plaintext = 'tamper-evident message body long enough to have ciphertext room';
  const payload = nip44Encrypt(conversationKey, plaintext);

  test('tampered ciphertext byte fails the MAC', () => {
    // Index 40 sits inside the ciphertext region (starts at byte 33).
    expect(() => nip44Decrypt(conversationKey, tamperPayloadByte(payload, 40))).toThrow(/nip44_invalid_mac/);
  });

  test('tampered MAC byte fails the MAC', () => {
    const lastIndex = Buffer.from(payload, 'base64').length - 1;
    expect(() => nip44Decrypt(conversationKey, tamperPayloadByte(payload, lastIndex))).toThrow(/nip44_invalid_mac/);
  });

  test('tampered nonce byte fails the MAC', () => {
    // Bytes 1..32 are the nonce.
    expect(() => nip44Decrypt(conversationKey, tamperPayloadByte(payload, 5))).toThrow(/nip44_invalid_mac/);
  });

  test('truncated payload (still shape-valid) fails the MAC', () => {
    const bigPayload = nip44Encrypt(conversationKey, 'y'.repeat(300));
    const decoded = Buffer.from(bigPayload, 'base64');
    const truncated = decoded.subarray(0, decoded.length - 32).toString('base64');
    expect(isValidNip44PayloadShape(truncated)).toBe(true);
    expect(() => nip44Decrypt(conversationKey, truncated)).toThrow(/nip44_invalid_mac/);
  });

  test('decrypting with the wrong peer conversation key fails the MAC', () => {
    const wrongPeerKey = getConversationKey(a.secretBytes, c.pubkeyHex);
    expect(() => nip44Decrypt(wrongPeerKey, payload)).toThrow(/nip44_invalid_mac/);
  });

  test('decrypting with an unrelated random key fails the MAC', () => {
    const randomKey = new Uint8Array(32).fill(0xab);
    expect(() => nip44Decrypt(randomKey, payload)).toThrow(/nip44_invalid_mac/);
  });
});

describe('sealed-key wrappers', () => {
  test('nip44EncryptWithSealedKey -> nip44DecryptWithSealedKey round trip between two custodied keys', async () => {
    const a = generateNostrKeypair();
    const b = generateNostrKeypair();
    const sealedA = await makeSealed(a);
    const sealedB = await makeSealed(b);
    const plaintext = 'custody boundary round trip';

    const payload = await nip44EncryptWithSealedKey(sealedA, b.pubkeyHex, plaintext);
    expect(isValidNip44PayloadShape(payload)).toBe(true);
    expect(await nip44DecryptWithSealedKey(sealedB, a.pubkeyHex, payload)).toBe(plaintext);
  });

  test('sealed encrypt interoperates with an oracle decrypt', async () => {
    const a = generateNostrKeypair();
    const b = generateNostrKeypair();
    const sealedA = await makeSealed(a);
    const payload = await nip44EncryptWithSealedKey(sealedA, b.pubkeyHex, 'to the oracle');
    const oracleKey = oracleNip44.utils.getConversationKey(hexToBytes(b.secretKeyHex), a.pubkeyHex);
    expect(oracleNip44.decrypt(payload, oracleKey)).toBe('to the oracle');
  });

  test('mismatched expectedPubkeyHex fails closed with nostr_key_mismatch on encrypt and decrypt', async () => {
    const a = generateNostrKeypair();
    const b = generateNostrKeypair();
    const impersonated = generateNostrKeypair();
    const sealingKey = new Uint8Array(32).fill(7);
    const sealedSecret = await seal(a.secretKeyHex, sealingKey);
    const mismatched: SealedNostrSecret = { sealedSecret, sealingKey, expectedPubkeyHex: impersonated.pubkeyHex };

    await expect(nip44EncryptWithSealedKey(mismatched, b.pubkeyHex, 'never')).rejects.toThrow(/nostr_key_mismatch/);

    const sealedA = await makeSealed(a);
    const payload = await nip44EncryptWithSealedKey(sealedA, b.pubkeyHex, 'real payload');
    await expect(nip44DecryptWithSealedKey(mismatched, b.pubkeyHex, payload)).rejects.toThrow(/nostr_key_mismatch/);
  });
});
