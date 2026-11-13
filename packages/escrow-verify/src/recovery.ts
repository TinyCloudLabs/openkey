import { createHash } from 'node:crypto';
import { freezeRecoveryDescriptor, recoveryPolicyId, type RecoveryDescriptor, type TargetPolicyEvidence } from '@openkey/tee';
import { keccak256, recoverPublicKey } from 'viem';
import type { getCollateral, verify } from '@phala/dcap-qvl';
import { compressed, replay, GETKEY_SIGNED_PURPOSE, PCCS_URL } from './internal';
import { RECOVERY_RELEASES } from './recovery-trust';

export interface RecoveryTarget {
  descriptor: RecoveryDescriptor;
  targetPolicyEvidence: TargetPolicyEvidence;
  quote: { quote: string; eventLog: string };
}
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');

/** Internal DCAP test seam; public callers cannot provide trust or a verifier. */
export async function verifyRecoveryTarget(target: RecoveryTarget, exportHeaderHash: string, dependencies: { getCollateral: typeof getCollateral; verify: typeof verify }): Promise<string> {
  if (RECOVERY_RELEASES.length === 0) throw new Error('Recovery verifier trust not configured');
  const input = structuredClone(target);
  const frozen = await freezeRecoveryDescriptor(input.descriptor);
  const d = frozen.descriptor;
  if (d.exportHeaderHash !== exportHeaderHash) throw new Error('Recovery export mismatch');
  if (Date.parse(d.createdAt) > Date.now() + 300_000 || Date.parse(d.expiresAt) <= Date.now()) throw new Error('Recovery time mismatch');
  const matches = RECOVERY_RELEASES.filter(pin => pin.composeHash === d.targetComposeHash);
  if (matches.length !== 1) throw new Error('Recovery release not configured');
  const pin = matches[0]!;
  if (!/^[a-f0-9]{40}$/.test(pin.appId) || !/^[a-f0-9]{64}$/.test(pin.composeHash) || !/^[a-f0-9]{64}$/.test(pin.codeHash)
    || !/^sha256:[a-f0-9]{64}$/.test(pin.imageDigest)) throw new Error('Invalid recovery pins');
  for (const value of [pin.mrTd, pin.rtmr0, pin.rtmr1, pin.rtmr2]) if (!/^[a-f0-9]{96}$/.test(value) || /^0+$/.test(value)) throw new Error('Invalid recovery measurement pin');
  const root = compressed(pin.kmsRootPublicKey);
  if (d.targetAppId !== pin.appId || d.targetComposeHash !== pin.composeHash || d.targetImageDigest !== pin.imageDigest || d.targetCodeHash !== pin.codeHash) throw new Error('Recovery identity mismatch');
  if (typeof input.quote.quote !== 'string' || !/^(?:[a-f0-9]{2})+$/.test(input.quote.quote)) throw new Error('Invalid recovery quote');
  const quote = Buffer.from(input.quote.quote, 'hex');
  const collateral = await dependencies.getCollateral(PCCS_URL, quote);
  const result = dependencies.verify(quote, collateral, Math.floor(Date.now() / 1000));
  if (result.status !== 'UpToDate') throw new Error('Unacceptable recovery TCB status');
  const td = result.report.asTd10(); if (!td) throw new Error('Not a recovery TDX quote');
  const digest = createHash('sha256').update('tinycloud/escrow/recovery-quote/v1\0').update(frozen.descriptorHash).digest();
  if (hex(td.reportData) !== hex(Buffer.concat([digest, Buffer.alloc(32)]))) throw new Error('Recovery quote binding mismatch');
  const measured = replay(JSON.parse(input.quote.eventLog));
  if (hex(td.rtMr3) !== measured.register || measured.appId !== pin.appId || measured.composeHash !== pin.composeHash) throw new Error('Recovery event mismatch');
  for (const [field, name] of [['mrTd', 'mrTd'], ['rtMr0', 'rtmr0'], ['rtMr1', 'rtmr1'], ['rtMr2', 'rtmr2']] as const) if (hex(td[field]) !== pin[name]) throw new Error('Recovery measurement mismatch');
  const evidence = input.targetPolicyEvidence;
  if (recoveryPolicyId(d, evidence) !== d.newPolicyId) throw new Error('Recovery policy mismatch');
  const app = await recoverPublicKey({ hash: keccak256(Buffer.from(GETKEY_SIGNED_PURPOSE + ':' + evidence.derivedPublicKey)), signature: `0x${evidence.signatureChain[0]!}` });
  if (compressed(app) !== compressed(evidence.sourcePublicKey)) throw new Error('Invalid recovery source claim');
  const issued = Buffer.concat([Buffer.from('dstack-kms-issued:'), Buffer.from(pin.appId, 'hex'), Buffer.from(compressed(app), 'hex')]);
  const recoveredRoot = await recoverPublicKey({ hash: keccak256(issued), signature: `0x${evidence.signatureChain[1]!}` });
  if (compressed(recoveredRoot) !== root) throw new Error('Untrusted recovery KMS chain');
  return frozen.descriptorHash;
}
