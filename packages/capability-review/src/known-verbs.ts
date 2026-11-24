// The abilities each storage service is known to carry, shared by the
// classifier and the approval tiers. Internal: index.ts does not export it.

export const MUTATION_VERBS: ReadonlySet<string> = new Set([
  "put",
  "post",
  "write",
  "delete",
  "del",
  "admin",
  "grant",
  "revoke",
  "update",
  "create",
]);

// `delete` is the registry's deprecated alias of `del`. `sync` (change feed)
// and `retain` (offline retention attestation) are registered KV abilities.
export const KV_VERBS: ReadonlySet<string> = new Set([
  "get",
  "list",
  "metadata",
  "put",
  "del",
  "delete",
  "sync",
  "retain",
]);

// `select` is the registry's deprecated alias of `read`.
export const SQL_DATABASE_VERBS: ReadonlySet<string> = new Set(["read", "select", "write", "schema"]);

// The verbs the secrets service is expected to carry. Any grant on
// `tinycloud.secrets` (or `secrets`) with a verb outside this union is
// classified as `secret-mutation` so unknown verbs stay inside the
// secret-access count and are surfaced as sensitive rather than inheriting
// friendly read copy.
export const SECRETS_KNOWN_VERBS: ReadonlySet<string> = new Set([
  "read",
  "get",
  ...MUTATION_VERBS,
  "list",
  "metadata",
]);
