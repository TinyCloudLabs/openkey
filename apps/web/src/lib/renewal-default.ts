// Two predicates for the approval screen: one for the one-hour expiry start
// (`isOnceTier`: access to all secrets or all encrypted data), one for the
// renewal opt-in and the "Renew sensitive access?" confirm (`isSensitiveTier`:
// any secret or decryption access). Both read capability-review's structural
// classifiers so the catalog and the UI agree on the set.
import {
  grantIsBroadOnce,
  grantReachesSecretDataOrDecryption,
  type CapabilityGrant,
} from '@openkey/capability-review';

/**
 * The one-hour approval tier: any grant capability-review's
 * `grantIsBroadOnce` places there (access to all secrets or all encrypted
 * data, or a shape it cannot place). Drives `onceDefaultExpiryMs` and the
 * matching copy note; never drives the renewal checkbox or the "Renew
 * sensitive access?" confirm step.
 */
export function isOnceTier(grants: readonly CapabilityGrant[]): boolean {
  return grants.some(grantIsBroadOnce);
}

/**
 * Sensitive tier: any grant that reaches secret data or decryption. Drives
 * the renewal opt-in (the checkbox never starts ticked for these) and the
 * "Renew sensitive access?" confirm step.
 */
export function isSensitiveTier(grants: readonly CapabilityGrant[]): boolean {
  return grants.some(grantReachesSecretDataOrDecryption);
}

/**
 * The renewal checkbox starts ticked only for a request that signed
 * `purpose: "standing"` (a missing purpose is a task) and is not Sensitive.
 * The caller shows the checkbox only where the request signed `renewal`.
 */
export function renewalStartsTicked(purpose: unknown, grants: readonly CapabilityGrant[]): boolean {
  return purpose === 'standing' && !isSensitiveTier(grants);
}
