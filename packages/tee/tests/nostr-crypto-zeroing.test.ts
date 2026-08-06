import { describe, expect, spyOn, test } from 'bun:test';
import { schnorr } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/curves/abstract/utils';
import { seal } from '../src/index';
import {
  computeEventId,
  generateNostrKeypair,
  signEventWithSecretBytes,
  withUnsealedNostrSecret,
  type SealedNostrSecret,
  type SignedNostrEvent,
} from '../src/nostr';
import {
  getConversationKey,
  nip44Encrypt,
  nip44DecryptWithSealedKey,
  nip44EncryptWithSealedKey,
} from '../src/nip44';
import { DM_RUMOR_KIND, GIFT_WRAP_KIND, SEAL_KIND, nip59UnwrapDm, nip59WrapDm } from '../src/nip59';

// Spy on the shared Uint8Array.prototype.fill (rather than mock.module-ing a
// dependency) so the spy is scoped to this test via mockRestore() and never
// leaks a replaced module into other test files running in the same process.
// Buffer overrides fill, so only genuine Uint8Array zeroing is captured.
function withZeroFillCapture<T>(run: (zeroFillTargets: Uint8Array[]) => Promise<T>): Promise<T> {
  const originalFill = Uint8Array.prototype.fill;
  const zeroFillTargets: Uint8Array[] = [];
  const fillSpy = spyOn(Uint8Array.prototype, 'fill').mockImplementation(function (
    this: Uint8Array,
    value: number,
    start?: number,
    end?: number,
  ) {
    const result = originalFill.call(this, value, start, end);
    if (value === 0) {
      zeroFillTargets.push(this);
    }
    return result;
  });

  return run(zeroFillTargets).finally(() => fillSpy.mockRestore());
}

/**
 * The unsealed secret and every derived conversation key are 32-byte
 * buffers. After an operation completes, at least `minCount` 32-byte buffers
 * must have been zeroed via fill(0) and every one of them must still be all
 * zeros (i.e. none was refilled with key material afterwards).
 */
function expectSecretSizedZeroFills(zeroFillTargets: Uint8Array[], minCount: number): void {
  const secretSized = zeroFillTargets.filter((buf) => buf.length === 32);
  expect(secretSized.length).toBeGreaterThanOrEqual(minCount);
  for (const buf of secretSized) {
    expect(Array.from(buf).every((byte) => byte === 0)).toBe(true);
  }
}

function containsUint8Array(value: unknown, seen = new Set<unknown>()): boolean {
  if (value instanceof Uint8Array) return true;
  if (!value || typeof value !== 'object' || seen.has(value)) return false;
  seen.add(value);
  if (Array.isArray(value)) return value.some((item) => containsUint8Array(item, seen));
  return Object.values(value).some((item) => containsUint8Array(item, seen));
}

async function makeSealed(keypair: { secretKeyHex: string; pubkeyHex: string }): Promise<SealedNostrSecret> {
  const sealingKey = new Uint8Array(32).fill(7);
  const sealedSecret = await seal(keypair.secretKeyHex, sealingKey);
  return { sealedSecret, sealingKey, expectedPubkeyHex: keypair.pubkeyHex };
}

describe('nip44EncryptWithSealedKey zeroing', () => {
  test('zeroes the secret and conversation key on success and returns no byte buffers', async () => {
    const a = generateNostrKeypair();
    const b = generateNostrKeypair();
    const sealed = await makeSealed(a);

    await withZeroFillCapture(async (zeroFillTargets) => {
      const payload = await nip44EncryptWithSealedKey(sealed, b.pubkeyHex, 'seal me tight');

      expect(typeof payload).toBe('string');
      expect(containsUint8Array(payload)).toBe(false);
      expect(payload).not.toContain(a.secretKeyHex);
      // secret (32) + conversation key (32) at minimum.
      expectSecretSizedZeroFills(zeroFillTargets, 2);
    });
  });

  test('zeroes the secret when conversation-key derivation fails (off-curve peer)', async () => {
    const a = generateNostrKeypair();
    const sealed = await makeSealed(a);

    await withZeroFillCapture(async (zeroFillTargets) => {
      await expect(nip44EncryptWithSealedKey(sealed, 'ff'.repeat(32), 'never leaves')).rejects.toThrow();
      // The unsealed secret buffer must still be zeroed even though no
      // conversation key ever existed.
      expectSecretSizedZeroFills(zeroFillTargets, 1);
    });
  });
});

describe('nip44DecryptWithSealedKey zeroing', () => {
  async function encryptFixture() {
    const a = generateNostrKeypair();
    const b = generateNostrKeypair();
    const sealedA = await makeSealed(a);
    const sealedB = await makeSealed(b);
    const payload = await nip44EncryptWithSealedKey(sealedA, b.pubkeyHex, 'decrypt zeroing fixture');
    return { a, b, sealedB, payload };
  }

  test('zeroes the secret and conversation key on successful decrypt', async () => {
    const { a, b, sealedB, payload } = await encryptFixture();

    await withZeroFillCapture(async (zeroFillTargets) => {
      const plaintext = await nip44DecryptWithSealedKey(sealedB, a.pubkeyHex, payload);
      expect(plaintext).toBe('decrypt zeroing fixture');
      expect(containsUint8Array(plaintext)).toBe(false);
      expect(plaintext).not.toContain(b.secretKeyHex);
      expectSecretSizedZeroFills(zeroFillTargets, 2);
    });
  });

  test('zeroes the secret and conversation key when the MAC check fails', async () => {
    const { a, sealedB, payload } = await encryptFixture();
    const decoded = Buffer.from(payload, 'base64');
    decoded[40] = decoded[40]! ^ 0x01;
    const tampered = decoded.toString('base64');

    await withZeroFillCapture(async (zeroFillTargets) => {
      await expect(nip44DecryptWithSealedKey(sealedB, a.pubkeyHex, tampered)).rejects.toThrow(
        /nip44_invalid_mac/,
      );
      // The conversation key was derived before the MAC failure, so both the
      // secret and the conversation key must have been zeroed.
      expectSecretSizedZeroFills(zeroFillTargets, 2);
    });
  });
});

describe('nip59WrapDm zeroing', () => {
  test('zeroes the secret, conversation keys, and ephemeral keys on success; wraps carry no buffers', async () => {
    const sender = generateNostrKeypair();
    const recipient = generateNostrKeypair();
    const sealed = await makeSealed(sender);

    await withZeroFillCapture(async (zeroFillTargets) => {
      const wraps = await nip59WrapDm(sealed, {
        content: 'zero the boundary',
        recipients: [recipient.pubkeyHex],
        createdAt: 1754399990,
        now: 1754400000,
      });

      expect(wraps.length).toBe(2);
      expect(containsUint8Array(wraps)).toBe(false);
      expect(JSON.stringify(wraps)).not.toContain(sender.secretKeyHex);
      // For one recipient: unsealed secret (1) + seal conversation keys (2)
      // + ephemeral secrets (2) + wrap conversation keys (2) = 7 buffers of
      // 32 bytes. Require at least 5 to stay robust to internal reshuffles.
      expectSecretSizedZeroFills(zeroFillTargets, 5);
    });
  });

  test('zeroes the secret when the sealed record fails the pubkey check', async () => {
    const sender = generateNostrKeypair();
    const impersonated = generateNostrKeypair();
    const recipient = generateNostrKeypair();
    const sealingKey = new Uint8Array(32).fill(3);
    const sealedSecret = await seal(sender.secretKeyHex, sealingKey);
    const mismatched: SealedNostrSecret = { sealedSecret, sealingKey, expectedPubkeyHex: impersonated.pubkeyHex };

    await withZeroFillCapture(async (zeroFillTargets) => {
      await expect(
        nip59WrapDm(mismatched, {
          content: 'must not wrap',
          recipients: [recipient.pubkeyHex],
          createdAt: 1754399990,
          now: 1754400000,
        }),
      ).rejects.toThrow(/nostr_key_mismatch/);
      expectSecretSizedZeroFills(zeroFillTargets, 1);
    });
  });
});

describe('nip59UnwrapDm zeroing', () => {
  test('zeroes the secret and conversation keys on successful unwrap; rumor carries no buffers', async () => {
    const sender = generateNostrKeypair();
    const recipient = generateNostrKeypair();
    const sealedSender = await makeSealed(sender);
    const sealedRecipient = await makeSealed(recipient);
    const [, wrap] = await nip59WrapDm(sealedSender, {
      content: 'unwrap and zero',
      recipients: [recipient.pubkeyHex],
      createdAt: 1754399990,
      now: 1754400000,
    });

    await withZeroFillCapture(async (zeroFillTargets) => {
      const rumor = await nip59UnwrapDm(sealedRecipient, wrap!);
      expect(rumor.content).toBe('unwrap and zero');
      expect(containsUint8Array(rumor)).toBe(false);
      expect(JSON.stringify(rumor)).not.toContain(recipient.secretKeyHex);
      // secret (1) + wrap conversation key (1) + seal conversation key (1).
      expectSecretSizedZeroFills(zeroFillTargets, 3);
    });
  });

  test('zeroes the secret and conversation key when the seal fails to decrypt (MAC failure)', async () => {
    const sender = generateNostrKeypair();
    const recipient = generateNostrKeypair();
    const sealedRecipient = await makeSealed(recipient);
    const senderSecret = hexToBytes(sender.secretKeyHex);

    // Craft a wrap whose signature is valid but whose content was encrypted
    // under a DIFFERENT ephemeral key than the one that signed it, so the
    // failure happens inside the unsealed-secret window.
    const rumorTemplate = {
      pubkey: sender.pubkeyHex,
      created_at: 1754399990,
      kind: DM_RUMOR_KIND,
      tags: [['p', recipient.pubkeyHex]],
      content: 'never readable',
    };
    const rumor = { ...rumorTemplate, id: computeEventId(rumorTemplate) };
    const sealConversationKey = getConversationKey(senderSecret, recipient.pubkeyHex);
    const sealEvent: SignedNostrEvent = signEventWithSecretBytes(senderSecret, {
      pubkey: sender.pubkeyHex,
      created_at: 1754399900,
      kind: SEAL_KIND,
      tags: [],
      content: nip44Encrypt(sealConversationKey, JSON.stringify(rumor)),
    });

    const signingEphemeral = schnorr.utils.randomPrivateKey();
    const encryptingEphemeral = schnorr.utils.randomPrivateKey();
    const wrongKeyContent = nip44Encrypt(
      getConversationKey(encryptingEphemeral, recipient.pubkeyHex),
      JSON.stringify(sealEvent),
    );
    const wrap = signEventWithSecretBytes(signingEphemeral, {
      pubkey: bytesToHex(schnorr.getPublicKey(signingEphemeral)),
      created_at: 1754399950,
      kind: GIFT_WRAP_KIND,
      tags: [['p', recipient.pubkeyHex]],
      content: wrongKeyContent,
    });

    await withZeroFillCapture(async (zeroFillTargets) => {
      await expect(nip59UnwrapDm(sealedRecipient, wrap)).rejects.toThrow(/nip44_invalid_mac/);
      // secret (1) + the wrap conversation key derived before the MAC failed.
      expectSecretSizedZeroFills(zeroFillTargets, 2);
    });
  });
});

describe('withUnsealedNostrSecret', () => {
  test('hands fn the exact secret bytes and zeroes the buffer after a successful return', async () => {
    const keypair = generateNostrKeypair();
    const sealed = await makeSealed(keypair);

    let captured: Uint8Array | null = null;
    const result = await withUnsealedNostrSecret(sealed, (secretBytes) => {
      captured = secretBytes;
      expect(secretBytes.length).toBe(32);
      expect(bytesToHex(secretBytes)).toBe(keypair.secretKeyHex);
      return 'fn result';
    });

    expect(result).toBe('fn result');
    expect(captured).not.toBeNull();
    expect(Array.from(captured!).every((byte) => byte === 0)).toBe(true);
  });

  test('zeroes the buffer even when fn throws, and propagates the error', async () => {
    const keypair = generateNostrKeypair();
    const sealed = await makeSealed(keypair);

    let captured: Uint8Array | null = null;
    await expect(
      withUnsealedNostrSecret(sealed, (secretBytes) => {
        captured = secretBytes;
        throw new Error('fn exploded');
      }),
    ).rejects.toThrow('fn exploded');

    expect(captured).not.toBeNull();
    expect(Array.from(captured!).every((byte) => byte === 0)).toBe(true);
  });

  test('fails closed without invoking fn when the secret does not derive the expected pubkey', async () => {
    const actual = generateNostrKeypair();
    const impersonated = generateNostrKeypair();
    const sealingKey = new Uint8Array(32).fill(9);
    const sealedSecret = await seal(actual.secretKeyHex, sealingKey);
    const mismatched: SealedNostrSecret = { sealedSecret, sealingKey, expectedPubkeyHex: impersonated.pubkeyHex };

    let fnCalled = false;
    await withZeroFillCapture(async (zeroFillTargets) => {
      await expect(
        withUnsealedNostrSecret(mismatched, () => {
          fnCalled = true;
          return 'unreachable';
        }),
      ).rejects.toThrow(/nostr_key_mismatch/);
      expect(fnCalled).toBe(false);
      expectSecretSizedZeroFills(zeroFillTargets, 1);
    });
  });
});
