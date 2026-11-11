import { expect, test } from 'bun:test';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { deriveRecoveryTargetPolicy, recoveryPolicyId, RECOVERY_PROVENANCE_PATH } from '../src/escrow-recovery-policy';

test('target policy uses only the dedicated path and clears derived material on success and failure', async () => {
  const target = { targetAppId: 'a'.repeat(40), targetComposeHash: 'b'.repeat(64), targetImageDigest: 'sha256:' + 'c'.repeat(64), targetCodeHash: 'd'.repeat(64) };
  const secret = new Uint8Array(32); secret[31] = 1;
  const pub = Buffer.from(secp256k1.getPublicKey(secret, true)).toString('hex');
  const evidence = { derivedPublicKey: pub, sourcePublicKey: pub, signatureChain: ['0'.repeat(130), '1'.repeat(130)] };
  const client = { derivePath: async (path: string) => { expect(path).toBe(RECOVERY_PROVENANCE_PATH); return { ...evidence, key: secret }; } };
  const result = await deriveRecoveryTargetPolicy(client, target);
  expect(result.newPolicyId).toBe(recoveryPolicyId(target, evidence));
  expect(result).not.toHaveProperty('key');
  expect(secret.every(b => b === 0)).toBe(true);
  secret.fill(1);
  await expect(deriveRecoveryTargetPolicy({ derivePath: async () => ({ ...evidence, derivedPublicKey: 'invalid', key: secret }) }, target)).rejects.toThrow();
  expect(secret.every(b => b === 0)).toBe(true);
});
