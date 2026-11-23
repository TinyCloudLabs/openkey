// TC-3821: one list of grants, each with what the API's renewal rule (`leaseReachesSecrets` in
// apps/api/src/services/renewal-lease.ts) and the web's renewal confirm (`renewalNeedsSensitiveConfirm` in
// apps/web/src/lib/renewal-default.ts) must say about it. apps/api/src/__tests__/renewal-sensitive-parity.test.ts runs
// both over every row on the same WASM-built message; apps/web/src/lib/signing-approval-renewal-confirm-mounted.test.ts
// mounts the confirm for the rows the web used to miss.
import { FIXTURE_META, makeRecapResource, siweWithResources } from "./index";

const OWNER = `did:pkh:eip155:${FIXTURE_META.chainId}:${FIXTURE_META.address}`;
const NETWORK = `urn:tinycloud:encryption:${OWNER}:default`;

export interface RenewalSensitiveCase {
  name: string;
  /** The grant: resource → abilities. */
  att: Record<string, string[]>;
  /** The API: the lease needs the owner's confirm (true), does not (false), or is refused outright as unreadable. */
  server: boolean | "unreadable";
  /** The web: the renewal box asks "Renew sensitive access?" and starts unticked. */
  web: boolean;
  /** Rows the web showed no confirm for before TC-3821, though the API requires one. */
  formerDeadEnd?: true;
}

export const RENEWAL_SENSITIVE_CASES: readonly RenewalSensitiveCase[] = [
  { name: "key.create on the secrets/ prefix", att: { [`${NETWORK}/secrets/`]: ["tinycloud.encryption/key.create"] }, server: true, web: true, formerDeadEnd: true },
  { name: "key.describe on one secret", att: { [`${NETWORK}/secrets/a`]: ["tinycloud.encryption/key.describe"] }, server: true, web: true, formerDeadEnd: true },
  { name: "every ability on the whole network", att: { [NETWORK]: ["tinycloud.encryption/*"] }, server: true, web: true, formerDeadEnd: true },
  { name: "decrypt on one secret", att: { [`${NETWORK}/secrets/a`]: ["tinycloud.encryption/decrypt"] }, server: true, web: true },
  { name: "decrypt on the secrets/ prefix", att: { [`${NETWORK}/secrets/`]: ["tinycloud.encryption/decrypt"] }, server: true, web: true },
  { name: "decrypt on a scoped secret", att: { [`${NETWORK}/secrets/scoped/agents/openai_api_key`]: ["tinycloud.encryption/decrypt"] }, server: true, web: true },
  { name: "key.create on a secrets scope prefix", att: { [`${NETWORK}/secrets/scoped/agents/`]: ["tinycloud.encryption/key.create"] }, server: true, web: true },
  { name: "decrypt on the whole network", att: { [NETWORK]: ["tinycloud.encryption/decrypt"] }, server: true, web: true },
  {
    name: "an encryption resource that does not parse",
    att: { [`urn:tinycloud:encryption:${OWNER}:Default/secrets/a`]: ["tinycloud.encryption/decrypt"] },
    server: "unreadable", web: true,
  },
  { name: "KV only", att: { [`${FIXTURE_META.ownSpace}/kv/courier/`]: ["tinycloud.kv/get", "tinycloud.kv/put"] }, server: false, web: false },
  { name: "key.create on the whole network", att: { [NETWORK]: ["tinycloud.encryption/key.create"] }, server: false, web: false },
  { name: "key.create on a key outside secrets/", att: { [`${NETWORK}/secretsish/a`]: ["tinycloud.encryption/key.create"] }, server: false, web: false },
  // The web's Once tier (D7) also confirms any decrypt; the API needs the confirm only for secrets. Asking more is safe.
  { name: "decrypt on a share key", att: { [`${NETWORK}/share/x`]: ["tinycloud.encryption/decrypt"] }, server: false, web: true },
];

/** A review-only message for a row (no signer-built statement), for the web's own parser. */
export function renewalSensitiveReviewMessage(row: RenewalSensitiveCase): string {
  const att = Object.fromEntries(Object.entries(row.att).map(([resource, abilities]) =>
    [resource, Object.fromEntries(abilities.map((ability) => [ability, [{}]]))]));
  return siweWithResources([makeRecapResource(att)]);
}
