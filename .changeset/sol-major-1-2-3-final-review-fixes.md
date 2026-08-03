---
"@openkey/capability-review": patch
---

Sol final review (Blocker 4 follow-up, iteration 2): close three MAJOR
defects that could still let a caller earn friendly copy or under-count
sensitive reach.

**Sol MAJOR-1 — App-scoped proof must apply js-sdk manifest normalization
semantics.** The prior gate compared raw declared scope and lower-cased
declared actions:

- A manifest declaration with scope `listen--app` (double dash) would
  match a grant at either `listen--app` or `listen-app`, even though
  js-sdk `canonicalizeSecretScope` in
  `sdk-services/src/secrets/paths.ts` collapses consecutive dashes and
  produces `listen-app` — a signed grant path is ALWAYS the canonical
  form.
- A manifest declaration with action `READ` was accepted, but js-sdk
  `normalizeSecretActions` in `sdk-core/src/manifest.ts` is
  case-sensitive and would throw `ManifestValidationError` on that same
  spelling.

`findMatchingDeclaredSecret` now:

- runs `declared.scope` through a js-sdk-parity `canonicalizeSecretScopeStrict`
  helper and rejects the entry when the raw scope is not already
  canonical, empty, or resolves to a reserved value;
- runs `declared.actions` through the new
  `isRecognizedManifestSecretAction` allowlist (mirrors js-sdk's exact
  case-sensitive set: `read`, `write`, `delete`, `get`, `put`, `del`,
  `list`, `metadata`, plus the `tinycloud.kv/*` full URN forms).

`annotateAppScopedGrants` runs the same strict manifest-action check on
the matched declaration before applying the sensitive → standard
demotion. Non-canonical scopes and non-canonical spellings fail closed
to sensitive + literal fallback (`appScopeNearMiss` remains stamped
when the name fingerprint still matches).

**Sol MAJOR-2 — Resource-side service segment in grant/action IDs and
literal fallback.** Grant / action ID computation used ability-derived
`entry.service`, so a SIWE carrying both `<space>/kv/<path>` and
`<space>/sql/<path>` with a shared `tinycloud.kv/get` ability produced
two review grants whose IDs COLLIDED (the delegate route's
`computeActionKey` correctly used the WASM resource-side short segment,
so preview/finalize correlation diverged). The SQL-mismatched fallback
statement also omitted the `/sql/` resource segment, so the two grants
rendered as visually identical strings.

`parse.ts` now uses a new `effectiveServiceForId(abilityService,
resourceService)` helper. Both `permissionId` and `actionId` are built
from the resource-derived service (canonicalized to `tinycloud.<short>`)
when the wire carried a segment; ability-derived otherwise. This aligns
capability-review IDs with delegate `computeActionKey` byte-for-byte,
and distinct resource services produce distinct grant / action IDs.

`statements.ts` `resourceOf` now includes the resource-side short-service
segment in the literal fallback resource string:
`<space>/<short>/<path>` when present. The operator sees the signed
resource URI verbatim.

**Sol MAJOR-3 — Resource-side named-secret grants must count in the
secret-reach total.** `grantReachesSecretDataOrDecryption` considered
`grant.resourceService` only when it was `kv` or `sql`. A grant on the
signer secrets space with a mismatched or unknown ability (e.g.
`tinycloud.foo/read`) was correctly stamped `sensitive` +
`serviceMismatch` + `appScopeNearMiss`, but the count predicate returned
false — the top-level "N exact grants reach secret data or decryption"
callout under-counted it. The predicate now returns `true` for ANY
grant on a secrets-shaped space regardless of ability-derived or
resource-derived service, so the callout is a true upper-bound on
plausible reach into secret bytes.

Adds 14 regression tests covering non-canonical scope spellings,
non-canonical action spellings (`READ`, `Read`, `Write`, `DELETE`),
duplicate `<space>/<path>` across kv/sql resource segments producing
distinct IDs, literal-fallback rendering including the `/sql/` segment,
and the widened secret-reach predicate over unknown-service and
capabilities-service grants on the secrets space. All 167 existing +
new capability-review tests pass; `apps/web` typecheck and full monorepo
build (10/10 tasks) remain green.
