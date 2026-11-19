// Whether the renewal box starts ticked (TC-2933), from spec #322's tier table.
import { grantReachesSecretDataOrDecryption, type CapabilityGrant } from '@openkey/capability-review';

/** D6 Once tier: any grant that reads or writes a secret, or decrypts. It never renews by default (D7). */
export function isOnceTier(grants: readonly CapabilityGrant[]): boolean {
  return grants.some(grantReachesSecretDataOrDecryption);
}

/**
 * D11/D12: the box starts ticked only for a request that signed `purpose: "standing"` (a missing purpose
 * is a task) and is not in the Once tier. The caller shows the box only where the request signed `renewal`.
 */
export function renewalStartsTicked(purpose: unknown, grants: readonly CapabilityGrant[]): boolean {
  return purpose === 'standing' && !isOnceTier(grants);
}
