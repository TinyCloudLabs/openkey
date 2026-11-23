import { grantIsBroadOnce, parseCapabilityReview, parseSiweChainId, parseSiweFields, serializeSiwe } from '@openkey/capability-review';

// TC-2272: the user may change when an approval expires. The new time replaces
// the `Expiration Time:` line of the SIWE the server is about to preview or
// sign; no other byte changes. The app's own time is only the default.

export type ExpirationOverride = { ok: true; value: string } | { ok: false };

/** The shortest approval the server previews: the one-minute floor the clients enforce, less 10 s for clock skew and network delay. */
export const MIN_EXPIRATION_LEAD_MS = 50_000;
/** Minimum grant lifetime enforced by delegate requests. */
export const MIN_DELEGATION_EXPIRY_MS = 60 * 1000;

/** The last second a SIWE timestamp (four-digit year) can name. */
export const LATEST_SIWE_TIME_MS = Date.UTC(9999, 11, 31, 23, 59, 59);

/**
 * A chosen expiry must be an exact ISO-8601 UTC time (what `toISOString()`
 * writes), at least `minLeadMs` after now, after the message's Issued At and
 * after its Not Before when it has one. There is no upper limit beyond what a
 * four-digit year can hold. At sign time `minLeadMs` is 0: the preview already
 * met the floor, and the time must only still be in the future.
 */
export function validateExpirationOverride(
  value: unknown,
  siwe: { issuedAt: string; notBefore?: string },
  minLeadMs: number,
  now: number = Date.now(),
): ExpirationOverride {
  if (typeof value !== 'string') return { ok: false };
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) return { ok: false };
  if (time > LATEST_SIWE_TIME_MS || time <= now + minLeadMs) return { ok: false };
  for (const bound of [siwe.issuedAt, siwe.notBefore]) {
    const boundTime = bound ? Date.parse(bound) : Number.NaN;
    if (Number.isFinite(boundTime) && time <= boundTime) return { ok: false };
  }
  return { ok: true, value };
}

/** The SIWE with its `Expiration Time` field replaced; null when it does not parse (`parseSiweFields`) or has no expiry. */
export function withExpirationTime(siwe: string, expirationTime: string): string | null {
  const parsed = parseSiweFields(siwe);
  if (!parsed.ok || parsed.fields.expirationTime === undefined) return null;
  return serializeSiwe({ ...parsed.fields, expirationTime });
}

/**
 * Is this request in the one-hour tier: a grant that reaches all secrets or all encrypted data
 * (`grantIsBroadOnce`, the classifier the approval screen's `isOnceTier` runs)? Such a request is treated as
 * expiry-changeable whatever the app sent, and an approval with no owner pick starts at one hour. Grants are
 * classified with the signer's own address so an own `default/share/` folder stays out, as the screen reads it.
 * False for a message that does not parse: the other refusals report it.
 */
export function siweBroadOnceTier(siwe: string, signerAddress: string): boolean {
  const model = parseCapabilityReview({
    message: siwe,
    signer: { label: 'OpenKey', address: signerAddress, chainId: parseSiweChainId(siwe) ?? 1, provenance: 'managed' },
    editable: false,
    metadataTrust: { status: 'unsigned', reason: 'server classification' },
    reason: { text: '', source: 'none' },
    requester: {
      displayName: '', verifiedOrigin: null, appId: null, manifestName: null, manifestNameProvenance: 'none',
      manifestId: null, manifestIdProvenance: 'none', manifestDigest: null, domainWarning: false, originWarning: false,
    },
  });
  return model.permissions.some(grantIsBroadOnce);
}
