import { createHash } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import type { RecoveryDescriptor } from './escrow-recovery-session';

export const RECOVERY_PROVENANCE_PATH = 'openkey/escrow/recovery-provenance/v1';
export interface TargetPolicyEvidence {
  derivedPublicKey: string; sourcePublicKey: string; signatureChain: string[];
}
export function recoveryPolicyId(target: Pick<RecoveryDescriptor, 'targetAppId' | 'targetComposeHash' | 'targetImageDigest' | 'targetCodeHash'>, evidence: TargetPolicyEvidence): string {
  if (typeof evidence.derivedPublicKey !== 'string' || !/^(02|03)[a-f0-9]{64}$/.test(evidence.derivedPublicKey)) throw new Error('Invalid recovery evidence');
  secp256k1.Point.fromBytes(Buffer.from(evidence.derivedPublicKey, 'hex'));
  if (typeof evidence.sourcePublicKey !== 'string' || !/^(?:0x)?(?:[a-f0-9]{66}|[a-f0-9]{130})$/.test(evidence.sourcePublicKey)) throw new Error('Invalid recovery evidence');
  secp256k1.Point.fromBytes(Buffer.from(evidence.sourcePublicKey.replace(/^0x/, ''), 'hex'));
  if (!Array.isArray(evidence.signatureChain) || evidence.signatureChain.length !== 2 || evidence.signatureChain.some(s => typeof s !== 'string' || !/^[a-f0-9]{130}$/.test(s))) throw new Error('Invalid recovery evidence');
  return createHash('sha256').update(JSON.stringify(['tinycloud/escrow/new-policy', 1, target.targetAppId, target.targetComposeHash,
    target.targetImageDigest, target.targetCodeHash, evidence.derivedPublicKey, evidence.sourcePublicKey])).digest('hex');
}

/** Derive evidence only on the fixed recovery path, then clear all key material. */
export async function deriveRecoveryTargetPolicy(client: { derivePath(path: string): Promise<TargetPolicyEvidence & { key: Uint8Array }> }, target: Pick<RecoveryDescriptor, 'targetAppId' | 'targetComposeHash' | 'targetImageDigest' | 'targetCodeHash'>) {
  const result = await client.derivePath(RECOVERY_PROVENANCE_PATH);
  try {
    const evidence: TargetPolicyEvidence = { derivedPublicKey: result.derivedPublicKey, sourcePublicKey: result.sourcePublicKey, signatureChain: [...result.signatureChain] };
    return { targetPolicyEvidence: evidence, newPolicyId: recoveryPolicyId(target, evidence) };
  } finally { result.key.fill(0); }
}
