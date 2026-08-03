---
"@openkey/capability-review": patch
---

Blocker 4 follow-up: tighten the app-scoped-secret proof gate and widen near-miss detection.

Five defects in the previous Blocker 4 pass could still let a grant that
did not truly satisfy the exact-resource proof inherit friendly
"app secret" or "vault" copy:

**Defect 1 — Service exactness.** `KV_SECRET_SERVICES` admitted bare
short-form `kv` abilities. No js-sdk producer emits them, so accepting
them expanded the proof surface without a matching wire shape. The proof
gate now uses `KV_SECRET_SERVICES_PROOF` (only `tinycloud.kv`); the
loose alias set remains available for near-miss candidacy so bare `kv/*`
grants still get literal-fallback-stamped rather than escaping.

**Defect 2 — Path byte-exactness.** `findMatchingDeclaredSecret` and the
defense-in-depth branch in `buildStatement` stripped leading/trailing
slashes before comparing the grant path. A caller could send
`/vault/secrets/scoped/listen/API_KEY/` and still hit the proof gate.
Comparison is now BYTE-EXACT against the sole canonical js-sdk shape
`vault/secrets/scoped/<scope>/<name>`; slash-decorated paths fall to
near-miss stamping.

**Defect 3 — Space structural match.** `isSignerOwnedSecretsSpace`
lowercased the whole space URI, so `:SECRETS` and mixed-case `PKH`
variants passed. The match is now structural: exact lowercase literal
prefix `tinycloud:pkh:eip155:<chainId>:` and suffix `:secrets`, with
only the address hex compared case-insensitively so both EIP-55 and
lowercased forms resolve to the same identity.

**Defect 4 — Near-miss widening.** Near-miss stamping only fired for KV
and named-secrets exact grants. Wrong-scope, wrong-service paths on the
correct secret name (e.g. `secrets/scoped/other/API_KEY`,
`variables/API_KEY`, `tinycloud.sql/read` at the canonical secret path,
`tinycloud.capabilities/read` at the canonical secret path) could
escape to friendly copy. Near-miss detection now includes a
scope-independent, service-agnostic name fingerprint
(`pathContainsDeclaredSecretName`) plus a secrets-space-shape check —
ANY grant whose path references a declared secretName as a whole path
segment, or ANY grant on a secrets-shaped space that references it,
becomes a candidate and receives literal-fallback stamping when the
exact proof fails.

**Defect 5 — Resource-side short-service segment.** `splitResourceUri`
discarded the resource's short-service segment. A grant whose resource
was `<space>/sql/vault/secrets/scoped/listen/API_KEY` paired with the
ability `tinycloud.kv/get` appeared as a valid app-scoped grant because
the ability-derived service (`tinycloud.kv`) drove classification. The
parser now:

- extends `splitResourceUri` to return the stripped short-service
  segment (`kv`, `sql`, `capabilities`, …);
- exposes it as `CapabilityGrant.resourceService` (null when the wire
  carried no segment);
- emits a `malformed-space` parse warning and stamps
  `CapabilityGrant.serviceMismatch = true` whenever the ability-derived
  service disagrees with the resource-derived segment;
- includes the resource segment in the ATT grouping key so mismatched
  entries never collapse into a single grant.

`annotateAppScopedGrants` refuses to annotate any grant carrying
`serviceMismatch: true` OR whose `resourceService` (when non-null) is
not `kv`. `buildStatement` short-circuits mismatched grants to the
literal fallback so friendly copy is never rendered on a service-
mismatched wire tuple. `grantReachesSecretDataOrDecryption` counts
grants that reach secret data via EITHER the ability-derived service
OR the resource-derived segment, so a service-mismatched grant on the
secrets space remains in the top-level secret-reach count (preserving
the Blocker 2 invariant that stamped grants are still counted).

These are all demote-only: severity can only be forced up (to
`sensitive`) and copy can only be forced to the literal fallback. The
proof gate is unchanged as the single sensitive → standard demotion
path. `actionId` / `permissionId` computations are unchanged so
preview/finalize correlation and canonical four-part IDs remain byte-
identical across the pipeline.
