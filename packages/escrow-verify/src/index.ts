import { getCollateral, verify } from '@phala/dcap-qvl';
import { verifyHolderBundle, type HolderBundle, type HolderPins } from './internal';
export type { HolderBundle, HolderPins } from './internal';

/** Holder-release boundary: call before opening or releasing any HPKE share. */
export function verifyEscrowForHolder(bundle: HolderBundle, pins: HolderPins): Promise<string> {
  return verifyHolderBundle(bundle, pins, { getCollateral, verify });
}
