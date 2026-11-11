import { getCollateral, verify } from '@phala/dcap-qvl';
import { verifyHolderBundle, type HolderBundle } from './internal';
export type { HolderBundle } from './internal';

/** Holder-release boundary: call before opening or releasing any HPKE share. */
export function verifyEscrowForHolder(bundle: HolderBundle, holderId: string, holderPublicKey: string): Promise<string> {
  return verifyHolderBundle(bundle, holderId, holderPublicKey, { getCollateral, verify });
}
