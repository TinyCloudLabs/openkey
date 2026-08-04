import { describe, expect, spyOn, test } from 'bun:test';
import { seal } from '../src/index';
import { generateNostrKeypair, signNostrEvent } from '../src/nostr';

// Spy on the shared Uint8Array.prototype.fill (rather than mock.module-ing a
// dependency) so the spy is scoped to this test via mockRestore() and never
// leaks a replaced module into other test files running in the same process.
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

describe('signNostrEvent secret zeroing', () => {
  test('zeroes the unsealed secret buffer after signing', async () => {
    const keypair = generateNostrKeypair();
    const sealingKey = new Uint8Array(32).fill(9);
    const sealedSecret = await seal(keypair.secretKeyHex, sealingKey);

    await withZeroFillCapture(async (zeroFillTargets) => {
      const signed = await signNostrEvent(
        { sealedSecret, sealingKey, expectedPubkeyHex: keypair.pubkeyHex },
        {
          pubkey: keypair.pubkeyHex,
          created_at: Math.floor(Date.now() / 1000),
          kind: 9,
          tags: [],
          content: 'zero me',
        },
      );

      expect(signed.sig).toMatch(/^[0-9a-f]{128}$/);

      // At least one 32-byte buffer (the unsealed secret) was zeroed via fill(0).
      const secretSizedZeroFills = zeroFillTargets.filter((buf) => buf.length === 32);
      expect(secretSizedZeroFills.length).toBeGreaterThanOrEqual(1);
      for (const buf of secretSizedZeroFills) {
        expect(Array.from(buf).every((byte) => byte === 0)).toBe(true);
      }
    });
  });

  test('zeroes the secret buffer even when signing fails closed on a pubkey mismatch', async () => {
    const actual = generateNostrKeypair();
    const impersonated = generateNostrKeypair();
    const sealingKey = new Uint8Array(32).fill(3);
    const sealedSecret = await seal(actual.secretKeyHex, sealingKey);

    await withZeroFillCapture(async (zeroFillTargets) => {
      await expect(
        signNostrEvent(
          { sealedSecret, sealingKey, expectedPubkeyHex: impersonated.pubkeyHex },
          {
            pubkey: impersonated.pubkeyHex,
            created_at: Math.floor(Date.now() / 1000),
            kind: 9,
            tags: [],
            content: 'should never sign',
          },
        ),
      ).rejects.toThrow(/nostr_key_mismatch/);

      const secretSizedZeroFills = zeroFillTargets.filter((buf) => buf.length === 32);
      expect(secretSizedZeroFills.length).toBeGreaterThanOrEqual(1);
      for (const buf of secretSizedZeroFills) {
        expect(Array.from(buf).every((byte) => byte === 0)).toBe(true);
      }
    });
  });
});
