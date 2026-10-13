import { describe, expect, test } from 'bun:test';
import { createTeeClient, seal, unseal } from '../src/index';

describe('TEE sealing context compatibility', () => {
  test('new per-key and legacy user paths both seal and unseal', async () => {
    // The mock client needs an explicit TEE_MODE=development (TC-966).
    const savedMode = process.env.TEE_MODE;
    process.env.TEE_MODE = 'development';
    let tee;
    try {
      tee = createTeeClient();
    } finally {
      if (savedMode === undefined) delete process.env.TEE_MODE;
      else process.env.TEE_MODE = savedMode;
    }
    const plaintext = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const newPath = 'openkey/key/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const legacyPath = 'openkey/user/user-a/keys';

    const newKey = await tee.deriveKey(newPath);
    const legacyKey = await tee.deriveKey(legacyPath);
    const newBlob = await seal(plaintext, newKey);
    const legacyBlob = await seal(plaintext, legacyKey);

    expect(await unseal(newBlob, await tee.deriveKey(newPath))).toBe(plaintext);
    expect(await unseal(legacyBlob, await tee.deriveKey(legacyPath))).toBe(plaintext);
  });
});
