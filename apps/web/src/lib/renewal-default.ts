// Whether the renewal box starts ticked (TC-2933), from spec #322's tier table.
import {
  grantReachesSecretDataOrDecryption,
  renewalEntryVerdict,
  type CapabilityGrant,
} from '@openkey/capability-review';

/** D6 Once tier: any grant that reads or writes a secret, or decrypts. It never renews by default (D7). */
export function isOnceTier(grants: readonly CapabilityGrant[]): boolean {
  return grants.some(grantReachesSecretDataOrDecryption);
}

/**
 * TC-3821: renewing these grants needs the owner's "Renew sensitive access?" confirm, exactly where the API requires
 * it: the Once tier, and every grant the shared `renewalEntryVerdict` (the rule `leaseReachesSecrets` in
 * apps/api/src/services/renewal-lease.ts runs) does not call `none`. An unreadable encryption permission counts: the
 * API refuses its lease outright. Used only for renewal (the confirm and the box default), never for the expiry tier.
 */
export function renewalNeedsSensitiveConfirm(grants: readonly CapabilityGrant[]): boolean {
  return isOnceTier(grants) || grants.some((grant) =>
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
