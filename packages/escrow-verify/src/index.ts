import { getCollateral, verify } from '@phala/dcap-qvl';
import { verifyHolderBundle, type HolderBundle } from './internal';
export type { HolderBundle } from './internal';

/** Holder-release boundary: call before opening or releasing any HPKE share. */
export function verifyEscrowForHolder(bundle: HolderBundle, holderId: string, holderPublicKey: string): Promise<string> {
  return verifyHolderBundle(bundle, holderId, holderPublicKey, { getCollateral, verify });
}

import { freezeEscrowHeader, unwrapEscrowShare, wrapRecoveryShare, type ShareEnvelope } from '@openkey/tee';
import { verifyRecoveryTarget, type RecoveryTarget } from './recovery';
export type { RecoveryTarget } from './recovery';

/** Verify the recovery release and its KMS evidence before opening a holder share. */
export function verifyRecoveryForHolder(target: RecoveryTarget, exportHeaderHash: string): Promise<string> {
  return verifyRecoveryTarget(target, exportHeaderHash, { getCollateral, verify });
}

/** Runs on the holder device; only a newly HPKE-wrapped share leaves this call. */
export async function releaseEscrowShare(bundle: HolderBundle & { wrappers: ShareEnvelope[] }, target: RecoveryTarget, holderId: string, holderPublicKey: string, holderKeys: CryptoKeyPair) {
  const input = structuredClone({ bundle, target });
  const exportHeaderHash = await verifyEscrowForHolder(input.bundle, holderId, holderPublicKey);
  await verifyRecoveryForHolder(input.target, exportHeaderHash);
  const frozen = await freezeEscrowHeader(input.bundle.header);
  const holder = frozen.header.holders.find(h => h.id === holderId)!;
  const wrappers = input.bundle.wrappers.filter(w => w.holderId === holderId);
  if (wrappers.length !== 1) throw new Error('Holder envelope mismatch');
  const share = await unwrapEscrowShare(wrappers[0]!, holderKeys, { escrowId: frozen.header.escrowId, holderId, x: holder.x, headerHash: exportHeaderHash });
  try { return await wrapRecoveryShare(share, input.target.descriptor, holderId, holder.x); }
  finally { share.fill(0); }
}
