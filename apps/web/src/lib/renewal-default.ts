// Two predicates for the approval screen: one for the one-hour expiry start
// (`isOnceTier`: access to all secrets or all encrypted data), one for the
// renewal opt-in and the "Renew sensitive access?" confirm
// (`renewalNeedsSensitiveConfirm`: any secret or decryption access, plus every
// grant the API's renewal rule refuses without a confirm). Both read
// capability-review's structural classifiers so the catalog, the UI and the
// server agree on the set.
import {
  grantIsBroadOnce,
  grantReachesSecretDataOrDecryption,
  renewalEntryVerdict,
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
 * Renewing these grants needs the owner's "Renew sensitive access?" confirm. The screen asks wherever any of three
 * holds: the Once tier (`isOnceTier`), the grant reaches secret data or decryption
 * (`grantReachesSecretDataOrDecryption`), or the shared `renewalEntryVerdict` (the rule
 * `leaseReachesSecrets` in apps/api/src/services/renewal-lease.ts runs) does not call it `none`. The last keeps the
 * screen from ever asking about fewer grants than the server later refuses: it covers the encryption permissions the
 * others miss (a key.create on `secrets/`, key.describe on one secret, every ability on the whole network), and an
 * unreadable encryption permission counts, since the API refuses its lease outright. Used only for renewal (the
 * confirm and the box default), never for the expiry tier.
 */
export function renewalNeedsSensitiveConfirm(grants: readonly CapabilityGrant[]): boolean {
  return isOnceTier(grants) || grants.some((grant) =>
    grantReachesSecretDataOrDecryption(grant) ||
    renewalEntryVerdict({
      service: grant.service, space: grant.space, path: grant.path, actions: grant.actions.map((action) => action.ability),
    }) !== 'none');
}

/**
 * D11/D12: the box starts ticked only for a request that signed `purpose: "standing"` (a missing purpose
 * is a task) and needs no confirm to renew. The caller shows the box only where the request signed `renewal`.
 */
export function renewalStartsTicked(purpose: unknown, grants: readonly CapabilityGrant[]): boolean {
  return purpose === 'standing' && !renewalNeedsSensitiveConfirm(grants);
}
