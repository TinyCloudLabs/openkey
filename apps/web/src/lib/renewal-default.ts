// Whether the renewal box starts ticked (TC-2933), from spec #322's tier table.
import {
  elevatedAbilityVerb,
  encryptionResourceOfEntry,
  grantReachesSecretDataOrDecryption,
  parseEncryptionResource,
  type CapabilityGrant,
} from '@openkey/capability-review';

/** D6 Once tier: any grant that reads or writes a secret, or decrypts. It never renews by default (D7). */
export function isOnceTier(grants: readonly CapabilityGrant[]): boolean {
  return grants.some(grantReachesSecretDataOrDecryption);
}

/**
 * TC-3821: a grant the API leases only after the owner's "Renew sensitive access?" confirm, mirroring
 * `leaseReachesSecrets` in apps/api/src/services/renewal-lease.ts: any encryption permission on a `secrets/` key or
 * prefix, or decrypt (or `*`) on a whole encryption network. An encryption resource that does not parse counts too:
 * the API refuses its lease outright.
 */
function grantLeasesSecrets(grant: CapabilityGrant): boolean {
  const resource = encryptionResourceOfEntry(grant);
  if (resource === null) return false;
  const parsed = parseEncryptionResource(resource);
  if (parsed === null) return true;
  if (parsed.kind === 'network') {
    return grant.actions.some((action) => ['decrypt', '*'].includes(elevatedAbilityVerb(action.ability)));
  }
  return parsed.keyPath.startsWith('secrets/');
}

/**
 * TC-3821: renewing these grants needs the owner's "Renew sensitive access?" confirm, exactly where the API requires
 * it: the Once tier, and every grant `grantLeasesSecrets` matches. Used only for renewal (the confirm and the box
 * default), never for the expiry tier.
 */
export function renewalNeedsSensitiveConfirm(grants: readonly CapabilityGrant[]): boolean {
  return isOnceTier(grants) || grants.some(grantLeasesSecrets);
}

/**
 * D11/D12: the box starts ticked only for a request that signed `purpose: "standing"` (a missing purpose
 * is a task) and needs no confirm to renew. The caller shows the box only where the request signed `renewal`.
 */
export function renewalStartsTicked(purpose: unknown, grants: readonly CapabilityGrant[]): boolean {
  return purpose === 'standing' && !renewalNeedsSensitiveConfirm(grants);
}
