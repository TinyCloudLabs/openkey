# @openkey/capability-review

## 0.2.0

### Minor Changes

- 715b892: Consolidate the OpenKey authorization surfaces onto a single shared review
  model and add a versioned `authorizeTinyCloud()` protocol (v1) that returns
  `{ signature, address, signedMessage, selectedActionKeys, permissions }`.
  The legacy `signMessage()` remains byte-exact — OpenKey continues to sign
  the caller's original bytes for that entry point. TinyCloud consumers can
  switch to `authorizeTinyCloud()` for editable capability review flows and
  complete sessions with the returned `signedMessage`.

  SDK guarantees delivered:
  - `authorizeTinyCloud` no longer silently falls back to `request.siwe`
    when the widget omits `signedMessage`; protocol violations throw.
  - `authorizeTinyCloud` routing resolves the target key by identity before
    choosing between the managed and external branches. An explicitly
    supplied external `keyId` routes externally; an explicitly supplied
    managed `keyId` routes to the managed path; conflicting pins are
    rejected with `KEY_ID_TYPE_MISMATCH` rather than being silently
    coerced into whichever branch `lastAuth.keyType` implied.
  - External-key `authorizeTinyCloud` opens the shared widget in preview
    mode, obtains the exact bytes to sign via `/authorize-sign-preview`,
    hands them to the wallet, and finalizes with an `externalSignature`
    the server verifies against those exact bytes.
  - Iframe resize traffic is correlated by `requestId` + `protocolVersion`.
    `IframeModal.setExpectedCorrelation(requestId, protocolVersion)` binds
    the expected pair before the request is posted; incoming resizes with
    a wrong requestId, wrong protocolVersion, missing correlation, or no
    active request are dropped.

  `capability-review` guarantees delivered:
  - `splitResourceUri` returns a WASM-aligned `{ space, path }` for
    path-scoped ReCap resources; the parser matches the on-wire structure
    `<space>/<short-service>[/<sub-path>]` used by `parseRecapFromSiwe`.
  - `canonicalMultisetEqual` compares caveats by canonical-JSON multiset
    equality: object keys are sorted recursively before comparison,
    duplicates are respected, and array element order is preserved.
  - `assertBaselineSubset` enforces exact multiset equality of caveats
    for every surviving (resource, ability) pair; whole-ability and
    whole-resource removals remain allowed.
  - `classifyRecapEntry` and `buildGrants` never fall back to the signer
    address as the ownership axis. Unverified requester identity
    classifies as `cross-app-data` and `ownedBySelf` reports `null`
    rather than silently claiming own-app-data.

  What this changeset does not claim:
  - Cross-repo consumption of the js-sdk `signInWithOpenKeyResult` from
    the OpenKey test graph. That consumer's acceptance is exercised
    independently in the js-sdk repo against the exact wire shape the
    OpenKey routes emit.
  - Any change to the internal `@openkey/api` or `@openkey/web` packages
    (ignored in the release config). Route- and widget-level changes are
    described in the internal changelog and covered by their own tests.

### Patch Changes

- f8e9ad7: Fix: app-scoped secret annotation now requires exact service (tinycloud.kv), secrets space, and canonical vault path proof before demoting severity. Previously, a same-named secret on a different service or path could receive friendly copy; it now falls through to literal fallback with sensitive severity (fail-closed).

  Sol follow-up probes closed:
  - A `tinycloud.secrets/get` grant on an unrelated space at
    `secrets/scoped/listen/API_KEY` used to render "Check permissions for
    your secrets" (attention severity). It now renders the literal fallback
    ("Perform tinycloud.secrets/get on tinycloud.secrets") at sensitive
    severity — no friendly SECRETS_SERVICES copy for a grant that fails
    the exact-resource proof.
  - A `tinycloud.kv/get` grant on the signer's own secrets space at
    `unrelated/listen/API_KEY` used to render "Read data outside this app"
    (cross-app-data, attention severity). It now renders the literal
    fallback at sensitive severity — no friendly cross-app copy for a KV
    grant that references a declared secret name via a non-canonical path.

  Implementation: adds `NAMED_SECRETS_SERVICES` and
  `pathContainsDeclaredSecretFragment` in `app-scope.ts`. The near-miss
  enforcement in `annotateAppScopedGrants` now stamps any grant on a KV or
  named-secrets service whose path fingerprint references a declared
  `{scope, secretName}` entry (validated against SECRET_NAME_RE /
  SECRET_SCOPE_RE / reserved-scope filters) but fails the strict exact-
  resource proof. The fingerprint is only used for demote-only enforcement;
  it never grants annotation.

- 656c1cf: Fix Blocker 4: app-scoped-secret annotation now requires exact resource tuple proof.

  Before this change, `annotateAppScopedGrants` matched any grant whose path
  tail carried the declared secret name and scope, regardless of service or space.
  An origin-bound declaration for `API_KEY/read` on app `listen` could incorrectly
  demote a `tinycloud.secrets/get` grant on an unrelated space at path
  `secrets/scoped/listen/API_KEY` to standard severity with friendly copy.

  The fix mirrors the js-sdk canonical derivation
  (`packages/sdk-services/src/secrets/paths.ts resolveSecretPath`) and requires:
  - `grant.service` is a KV service (`tinycloud.kv` or `kv`) — never `tinycloud.secrets`
  - `grant.space` is the structurally-named secrets space
  - `grant.path` equals exactly `vault/secrets/scoped/<scope>/<name>` (the only
    shape js-sdk emits on the wire; legacy shapes are fail-closed)
  - `secretName` matches `/^[A-Z][A-Z0-9_]*$/` and `scope` matches
    `/^[a-z0-9-]+$/` excluding reserved `default`/`global`

  `buildStatement` gains matching defense-in-depth checks so friendly copy
  cannot be produced from a mismatched resource tuple even if a future annotator
  bug stamps `appScopedSecret` on a wrong-service or wrong-space grant.

  `isSecretsSpace` is now exported from `app-scope.ts` and imported by
  `statements.ts` so both surfaces use one shared predicate.

- 4beba3c: Constrain app-scoped-secret annotation to a canonical read/write/delete verb
  allowlist so an origin-bound manifest cannot widen the recognized
  named-secret action vocabulary.

  Sol MAJOR (this iteration): `annotateAppScopedGrants` in
  `packages/capability-review/src/app-scope.ts` previously accepted any
  grant whose family was `secret-read` or `secret-mutation` and any
  `(secretName, scope, actions)` triple the origin-bound manifest declared.
  An origin-bound manifest declaring `peek` on `API_KEY` therefore matched
  a `tinycloud.secrets/peek` grant, flipped its severity from `sensitive`
  to `standard`, and stamped `appScopedSecret`. `buildStatement` then took
  its early `appScopedSecret` branch — whose broad `READ_VERBS` set
  includes `peek` — and rendered `Read the app secret API_KEY` for a wire
  verb whose actual authority is not part of the read/write/delete
  vocabulary that copy implies.

  This change adds a canonical `RECOGNIZED_APP_SCOPE_SECRET_VERBS`
  allowlist (`get` / `put` / `del`, matched against both grant and
  declaration through `normalizeSecretVerb`) and applies it in two places:
  - **Primary gate** — `annotateAppScopedGrants` now refuses to annotate
    when ANY grant verb OR any declared-manifest verb falls outside the
    allowlist. Unknown verbs (`peek`, `admin`, `list`, `metadata`,
    `rotate`, or any future/novel action) leave the grant untouched:
    severity stays `sensitive`, `appScopedSecret` is never stamped, and
    `grantReachesSecretDataOrDecryption` continues to count it.
  - **Defense-in-depth** — `buildStatement`'s `appScopedSecret` branch
    re-checks every action verb against the same allowlist. Even if a
    compromised or future-buggy annotator stamped `appScopedSecret` on an
    unknown-verb grant, the friendly `Read/Update the app secret` copy
    cannot fire; the operator sees the literal fallback (`Perform
tinycloud.secrets/peek on tinycloud.secrets`) instead.

  New tests in `packages/capability-review/test/app-scope.test.ts` pin
  both gates for the `tinycloud.kv/peek` (js-sdk scoped-secret path) and
  direct `tinycloud.secrets/peek` shapes, cover mixed recognized +
  unrecognized verb sets on both grant and declaration sides, and
  regression-guard the happy path (`get` + `put` remains eligible for
  standard-severity friendly copy).

- b79ed46: Blocker 4 follow-up: tighten the app-scoped-secret proof gate and widen near-miss detection.

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

- 519b162: Fix Blocker 4 follow-up defects (Sol): exact signer-owned secrets space proof and near-miss literal fallback.

  Two defects in the original Blocker 4 pass:

  **Defect 1 (cross-signer space attack):** The pre-fix `isSecretsSpace`
  predicate was purely a shape check — it accepted the literal string
  `"secrets"` OR any space whose path contained `:secrets`. A probe signed by
  `0x1111…1111` presenting a grant on `0x2222…2222:secrets` would still pass
  the shape check and be demoted to standard severity. Nothing about the
  caller demonstrated ownership of the attacker's space.

  The fix adds `expectedSignerSecretsSpace(signer)` and
  `isSignerOwnedSecretsSpace(space, signer)` derived from the js-sdk canonical
  form (`tinycloud:pkh:eip155:<chainId>:<address>:secrets`, lowercased hex).
  `annotateAppScopedGrants` now requires `grant.space` to be exactly the
  signer's own canonical secrets space before any sensitive → standard
  transition. Matching is case-insensitive on the address hex so both EIP-55
  and lowercased forms resolve to the same identity.

  **Defect 2 (near-miss friendly-copy leak):** When a KV secret-family grant
  on a secrets-shaped space failed the exact proof (wrong owner, wrong path,
  wrong verb, no matching declared entry, …), the grant was left structurally
  classified and `buildStatement` emitted friendly KV secrets copy such as
  "View secrets stored in your vault" — dressing the ability up in reassuring
  copy the failed proof did not earn.

  The fix adds an `appScopeNearMiss` flag on `CapabilityGrant`. Any KV secret
  grant that fails the exact proof is stamped with `appScopeNearMiss: true`,
  `severity: "sensitive"`, and `metadataLabel: null`. `buildStatement`
  short-circuits any near-miss grant to the literal fallback (raw service,
  resource, and ability strings) so the operator always sees the actual wire
  verb, never friendly secret-family framing.

  The near-miss stamp is a demote-only signal: it never lowers severity, only
  elevates it and forces literal copy. Non-KV secret grants (the
  `tinycloud.secrets` service branch) are not stamped — that branch has its
  own recognized-actions allowlist and does not emit vault-shaped copy.

- 0f37192: Sol final review (post-MAJOR-1..3 continuation): close three final blockers
  Sol identified before merge readiness.

  **Sol Blocker A — Widget-side hard-coded chain ID broke ownership proof.**
  Both widget signing routes (`apps/web/src/routes/widget/sign/+page.svelte`,
  `apps/web/src/routes/widget/embed/sign/+page.svelte`) constructed the
  capability-review signer with `chainId: 1`, regardless of the chain the
  SIWE actually targeted. `expectedSignerSecretsSpace` /
  `isSignerOwnedSecretsSpace` pin the signer's canonical secrets space to
  `tinycloud:pkh:eip155:<chainId>:<address>:secrets`, so a SIWE with
  `Chain ID: 8453` and resource space
  `tinycloud:pkh:eip155:8453:<signer>:secrets` was compared against the
  chain-1 identity — the ownership proof silently passed for the wrong
  chain and the grant received standard severity with friendly
  app-scoped copy.

  Adds `parseSiweChainId(message)` to `@openkey/capability-review` and uses
  it in both widget routes. The signer is now built with the chain ID
  parsed from the SIWE bytes that will be signed; if the message has no
  parseable `Chain ID:` line (legacy `signMessage`, malformed input), the
  routes fall back to `0` so the ownership check fails closed rather than
  pretending the request was on mainnet.

  **Sol Blocker B — Non-canonical signed KV abilities earned standard
  app-scoped presentation.** The proof gate compared grant-side abilities
  via `RECOGNIZED_APP_SCOPE_SECRET_VERBS.has(normalizeSecretVerb(a.verb.toLowerCase()))`,
  so grants with `tinycloud.kv/GET` (case-folded) or `tinycloud.kv/read`
  (long-form synonym) earned standard severity despite no js-sdk producer
  emitting either shape on the wire.

  `annotateAppScopedGrants` and `findMatchingDeclaredSecret` now compare
  grant-side abilities BYTE-EXACTLY against
  `CANONICAL_APP_SCOPE_SECRET_ABILITIES` — the exact wire ability
  allowlist `{ tinycloud.kv/get, tinycloud.kv/put, tinycloud.kv/del }`.
  No case folding, no synonym normalization, no short-form aliases.
  Anything else fails the proof and downstream near-miss stamping forces
  literal-fallback rendering so the operator sees the raw ability
  verbatim.

  `normalizeSecretVerb` is retained but only for the DECLARED-side manifest
  subset check (manifests legitimately use `read`/`write`/`delete`); it
  no longer runs on grant-side ability verbs.

  **Sol Blocker C — js-sdk-canonicalized scopes escaped near-miss
  enforcement.** `pathContainsDeclaredSecretName` and
  `pathContainsDeclaredSecretFragment` skipped any declaration whose raw
  scope failed `SECRET_SCOPE_RE`. js-sdk's `canonicalizeSecretScope`
  accepts raw manifest scopes like `Listen App`, `listen app`, and
  `listen--app` and produces vault-path segment `listen-app` — so a
  manifest that legitimately declared `scope: "Listen App"` plus a
  `tinycloud.capabilities/read` grant at
  `vault/secrets/scoped/listen-app/API_KEY` produced no fingerprint and
  the wrong-service grant remained at standard severity with friendly
  "Check permissions for your secrets" copy.

  Both fingerprint helpers now canonicalize the declared scope through
  the new `canonicalizeSecretScopeForFingerprint` helper (mirrors js-sdk
  `canonicalizeSecretScope`) before comparing. The strict proof-side
  matcher (`findMatchingDeclaredSecret`) still requires the raw declared
  scope to BE its canonical form — that check remains a fail-closed
  authority gate. Only near-miss fingerprinting is widened, so same-name
  grants on wrong services or wrong paths always demote to sensitive +
  literal fallback regardless of the raw scope spelling.

  Adds 19 regression tests covering: `parseSiweChainId` across mainnet,
  Base (8453), Polygon (137), and invalid input; wrong-chain ownership
  proof (the Sol Blocker A probe); `tinycloud.kv/read` and
  `tinycloud.kv/GET` proof rejection (the Sol Blocker B probes);
  `canonicalizeSecretScopeForFingerprint` across all js-sdk-accepted
  forms; and end-to-end near-miss stamping on wrong-service /
  uppercase-scope declarations (the Sol Blocker C probe). All 186
  capability-review tests pass; `apps/web` typecheck and full monorepo
  build remain green.

- 4439c7f: Continuation-review v2 hardening on the OpenKey authorization consolidation.

  `@openkey/sdk`:
  - `authorizeTinyCloud` resolves the caller-supplied `keyId` and routes
    by the resolved key's type, not by `lastAuth.keyType` alone. An
    explicitly supplied external `keyId` routes externally; an
    explicitly supplied managed `keyId` routes to the managed path.
    Conflicting pins (`lastAuth` type disagrees with the resolved
    target-key type) are rejected with `KEY_ID_TYPE_MISMATCH`.
  - Popup close-message correlation requires exact `requestId` +
    `protocolVersion` on `openkey:close` messages for versioned flows.
    Overlapping second requests are refused; wrong-requestId close
    messages are dropped.

  `@openkey/capability-review`:
  - `assertBaselineSubset` enforces exact multiset equality on caveats
    for every surviving (resource, ability) pair. Whole-ability and
    whole-resource removal remain allowed. Every other transformation
    surfaces as `candidate-broadens-baseline` with a message citing the
    specific change.

  The internal `@openkey/api` and `@openkey/web` packages (ignored in
  the release config) received the matching server-side narrowing-splice
  helper, the preview-approval token consume path, and the widget-transport
  correlation checks. Those are documented in the internal changelog and
  covered by their own tests.

- 0d2463b: Final Sol continuation-review hardening on the OpenKey authorization
  consolidation.

  `@openkey/capability-review`:
  - `splitResourceUri` is a module-private helper in `parse.ts` that strips
    the `<short-service>` segment from a TinyCloud resource URI and returns
    a WASM-aligned `{ space, path }`. It is used by the ReCap decoder
    (`decodeRecapUri`) in `parse.ts` so the parser matches the on-wire
    structure `<space>/<short-service>[/<sub-path>]` used by WASM's
    `parseRecapFromSiwe`. `subset.ts` does not use this helper — it operates
    on the already-parsed `CapabilityReviewModel` and uses
    `canonicalMultisetEqual` for caveat-multiset comparison.
  - `canonicalMultisetEqual` compares caveats by canonical-JSON multiset
    equality: object keys are sorted recursively before comparison,
    duplicates are respected, and array element order is preserved.
    Prior code used `JSON.stringify(caveats)` and rejected structurally
    identical baselines whose keys serialized in a different order.

  `@openkey/sdk`:
  - `authorizeTinyCloud` resolves the target key before routing and
    rejects pins whose type disagrees with the resolved key. The
    external branch is entered whenever the resolved target key is
    `EXTERNAL`, regardless of what `lastAuth.keyType` is; the managed
    branch is entered whenever the resolved target key is `MANAGED`.
  - Iframe resize correlation is exercised through the parent-side
    handler for wrong `requestId`, wrong `protocolVersion`, missing
    correlation, no active request bound, and sequential-request
    rebinding.

  What this changeset does not claim:
  - Cross-repo import of the js-sdk `signInWithOpenKeyResult` from the
    OpenKey test graph. The wire-format contract is asserted from both
    sides (mirrored validator on the OpenKey side, real consumer on the
    js-sdk side against a byte-for-byte Hono-route-shaped body).
  - Any change to the internal `@openkey/api` or `@openkey/web` packages
    (ignored in the release config). Matching server-side narrowing,
    caveat-preservation, widget-transport correlation, and preview-
    approval-token changes are documented in the internal changelog and
    covered by their own tests.

- 08c58ec: Follow-up hardening on the OpenKey authorization consolidation review.

  `@openkey/sdk`:
  - `authorizeTinyCloud` falls back to `lastAuth.keyId` when the caller
    did not pass an explicit `keyId`, so the widget receives the
    connected-key context instead of rendering `Please connect first.`

  `@openkey/capability-review`:
  - `classifyRecapEntry` no longer falls back to the signer address as
    the ownership axis when `requesterAddress` is null and
    `requesterVerified` is false. Widget-issued classifications
    fail-closed to `cross-app-data` when the requester identity is
    unverifiable.

  The internal `@openkey/api` and `@openkey/web` packages (ignored in the
  release config) received matching route, widget-transport, and preview-
  approval-token changes described in the internal changelog and covered
  by their own tests.

- f31d0a3: Sol follow-up: address the 7 findings raised after the merge-readiness
  consolidation.

  Capability-review (`@openkey/capability-review`) changes visible to
  consumers:
  - `statements.buildStatement` is now action-aware. Grants classified as
    KV on account applications/spaces paths return `"View and update ..."`
    ONLY when both read and write actions are present; read-only grants
    return `"View ..."` and write-only grants return `"Update ..."`. The
    SQL statements gain the same behaviour: `"Read and update ..."` is
    produced only when read AND (write|schema) actions are present.
  - `RequesterIdentity` gains a new `appId: string | null` field. The
    widget renders it as a distinct Advanced-details row separately from
    `manifestId` — the operator can now tell "which app is this?" apart
    from "which manifest version am I looking at?". All test fixtures
    updated.
  - New `app-scope.ts` module: `annotateAppScopedGrants(model,
declaredAppScope?)` matches secret grants against a
    server-supplied, origin-bound declaration set and — only when the
    match is exact on `(secretName, scope, actions)` and the ReCap
    resource carries the same scope — sets a compact `metadataLabel`.
    Metadata is never allowed to lower `severity`; missing/mismatched
    declarations leave the grant sensitive by default.

  The substantive companion changes ride in `@openkey/api` and
  `@openkey/web` (both unpublished workspaces):
  - `apps/api/src/services/manifest-origin-fetch.ts` pins the well-known
    manifest fetch to the pre-validated public IP via an undici
    connector wrapper (defeats DNS rebinding TOCTOU) and keeps the
    5-second abort deadline active THROUGH the complete body read
    (defeats slow-trickle body stalls). The fetch now also extracts
    declared `secrets` and `permissions` entries from the fetched
    manifest so the widget can enforce the app-scoped-secret trust rule.
  - `apps/api/src/routes/delegate.ts` surfaces `declaredAppScope` on the
    `verifiedManifest` block returned by `/authorize-sign-prepare`.
  - `apps/web/src/routes/widget/sign/+page.svelte`:
    - Removes the signer-as-requester bug: `key.address` is no longer
      passed as `requesterAddressForClassifier`, and `requesterVerified`
      is no longer flipped true on `origin-bound` alone. The classifier
      now safely reports grants on the signer's spaces as cross-app when
      no verified requester identity exists.
    - Forwards the server's `verifiedManifest.declaredAppScope` into a
      new `annotateAppScopedGrants` call after `parseCapabilityReview`.
    - Renders `appId` in Advanced details as a distinct row.
    - Uses only a server origin-bound manifest name as the unlabelled
      top-level requester. Before verification, the summary shows the
      browser authority; a caller-supplied app name is confined to Advanced
      details with its unverified provenance label.
    - Compares the SIWE domain with `URL.host`, preserving non-default ports.
  - The iframe signing route follows the same requester-name and authority
    comparison rules as the popup route.
  - Popup and iframe now route every successfully parsed signing protocol
    through the shared approval component. Plain SIWE and legacy exact-byte
    requests no longer fall back to route-local review cards, while parser
    failures expose only a cancel action and cannot be signed.
  - The sealed-preview response must return canonical action keys and grouped
    permissions that exactly project the selection the user reviewed. The final
    summary and sensitive-access warning are then derived only from that sealed
    selection; removed secret/decrypt actions remain available under Edit/Reset
    but cannot survive in the top-level approval copy.
  - `apps/web/src/lib/signing-approval-parity-mounted.test.ts` domain-
    warning + Advanced-details assertions updated to match the shipped
    contract copy.

  No authority-broadening changes. Presentation labels can only refine
  display; structural severity is preserved. All fail-closed defaults
  remain intact.

- c400dc5: Sol final review (Blocker 4 follow-up, iteration 2): close three MAJOR
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

- f382c02: Address Sol's follow-up MAJOR findings on the authorization consolidation:

  Capability-review package (`@openkey/capability-review`):
  - **MAJOR-1** — `parseSecretPath` in `app-scope.ts` now recognizes the
    js-sdk production path shape `secrets/scoped/<scope>/<name>` (and its
    `vault/` variant). Previously it accepted only the legacy scope-first
    shape `<scope>/secrets/<name>`, so real production scoped-secret
    grants never matched an app declaration and the app-scope gate never
    fired. A new `normalizeSecretVerb` helper canonicalizes grant
    `get/put/del` and manifest `read/write/delete` synonyms before the
    action-subset check, so declarations expressed in either dialect
    match consistently.
  - **MAJOR-3** — `statements.ts` now recognizes the production
    encryption ability `tinycloud.encryption/network.create` (the
    compound verb produced by `verbOf` for
    `tinycloud.encryption/network.create`). Grants that combine
    `network.create` with `decrypt` now correctly select the
    contract-mandated statement `"Create a decryption network and
decrypt protected data"`; grants that carry only `network.create`
    select `"Create a decryption network"`. Previously the compound
    verb was silently ignored and the widget rendered the literal
    fallback.
  - **MAJOR-4** — `RequesterIdentity` gains two new fields per manifest
    field (`manifestName` + `manifestNameProvenance`; `manifestIdProvenance`
    alongside the existing `manifestId`). Provenance is one of
    `"verified" | "origin-bound" | "caller" | "none"`. The shared
    `SigningApproval` disclosure renders each field with its provenance
    tag so an operator can never mistake a caller-echoed
    `displayName`/`manifestId` for an OpenKey-verified value.

  Test suites now cover the js-sdk production secret path shapes, the
  verb-normalization rule, and the encryption `network.create` variants;
  15 new app-scope tests and 5 new encryption-statement tests all pass.

  The final trust-path review also makes the manifest protocol executable end
  to end: OpenKey now hashes the fetched manifest's sorted-key canonical JSON
  using the same representation as js-sdk, accepts the SDK's default-read secret
  declaration, and presents an exact origin-bound scoped-secret match as Standard
  with its secret name and scope. Global, unsigned, mismatched, or action-expanded
  secret grants remain sensitive. The sensitive-access callout now counts only
  grants that structurally reach TinyCloud secret data or decrypt protected data;
  it includes Secrets SQL while excluding unrelated unknown mutations and
  create-only encryption grants.

  API (`@openkey/api`, not published):
  - **MAJOR-4** — `/authorize-sign-prepare` no longer merges caller-
    supplied envelope `displayName` / `manifestId` into `verifiedManifest`
    while marking trust `origin-bound`. Origin-bind proves the FETCHED
    manifest matched the declared digest; the envelope's identity fields
    remain untrusted. The widget layer supplies envelope fallbacks
    separately with the `caller-supplied, unverified` provenance tag.

  Web (`@openkey/web`, not published):
  - **MAJOR-2** — `widget/embed/sign/+page.svelte` no longer sets
    `requesterAddressForClassifier = key.address.toLowerCase()` on
    origin-bound trust. `key.address` is the signer, not the requester;
    using it as the classifier's requester address caused every own-space
    grant to be labelled "own-app-data" without the shared cross-app
    attention warning. The iframe route now matches the popup:
    `requesterVerified = false` and `requesterAddress = null` unless an
    independently verified identity is supplied. It also now calls
    `annotateAppScopedGrants` with the server's origin-bound
    `declaredAppScope`, so exactly proven scoped-secret declarations from an
    origin-bound manifest surface with a compact secret/scope label and Standard
    presentation.
  - **MAJOR-4** — popup / iframe / CLI routes compute
    `manifestName{,Provenance}` and `manifestIdProvenance` alongside the
    display strings and forward them into `parseCapabilityReview`. Server
    fields count as `verified`/`origin-bound` only when trust actually
    reached that status; anything else labels the field `caller` so the
    shared component tags it "caller-supplied, unverified".
  - **MAJOR-5** — the browser-parity Playwright spec now opens the
    `<details>` disclosure before clicking the Edit button (which lives
    inside Advanced details and is not visible by default). The 22-test
    suite is now fully green.

- a55fdb0: Merge-readiness consolidation: address Sol's 6 MAJOR and 2 MINOR findings on
  the OpenKey authorization consolidation.

  Documentation-only changeset entry for `@openkey/capability-review`; the
  substantive code changes below live in `@openkey/api` and `@openkey/web`,
  which are ignored by the release config, plus in `@openkey/capability-review`
  itself where the underlying model and parser changes land.

  Capability-review package (`@openkey/capability-review`):
  - New `RequestProtocol` variant `"malformed-recap"`. Returned when the
    raw SIWE carries a `urn:recap:` resource token but the decoder
    produces zero entries. Previously such requests silently downgraded to
    `"siwe-plain"` and were signable exact-byte — dropping the caller's
    capability payload. UI routes now block the Approve button when the
    model resolves to `"malformed-recap"`.
  - New `MetadataTrustStatus` variant `"origin-bound"`. Ranks between
    `"unsigned"` and `"verified"`: the widget browser-verified the origin
    and the server fetched the app's `.well-known/openkey-manifest.json`
    and matched its canonical SHA-256 to the envelope's declared digest,
    but no cryptographic manifest signature exists. `metadata.ts`
    monotonic-rank check updated to place `origin-bound` at rank 4
    (`unsigned=3`, `verified=5`).
  - New `statements.ts` catalog: `buildStatement(grant)` returns a
    deterministic single-sentence statement for known structural shapes
    (bootstrap-kv on apps/spaces paths, bootstrap-sql on account or
    secrets space, secret-read/mutation, encryption create+decrypt, etc.).
    Generic own-app/cross-app data uses action-aware structural copy, and an
    exactly proven app-scoped secret uses its bound secret name without
    inferring product-specific meaning from the resource path.
    Unknown shapes fall back to the literal service/resource/actions text
    — never invent friendly semantics. `sensitiveCallout(n)` returns the
    exact contract copy `"N exact grants reach secret data or decryption.
You can review them below."`.
  - Literal NUL bytes in `packages/capability-review/src/{ids,parse}.ts`
    and `apps/web/tests/browser/signing-approval-parity.spec.ts` replaced
    with `"\x00"` escape sequences (same runtime value, text-safe
    source). Diffs and review tools now render these files as text.
  - `PROTOCOL_HEADLINE`/`PROTOCOL_HINT` in `copy.ts` extended with copy
    for `"malformed-recap"`.

  API (`@openkey/api`, not published):
  - `authorizationContextIssueInput` now accepts an optional
    `metadataTrust` and `verifiedManifest`. Stored on the context and
    echoed in the response so the widget renders honest provenance.
  - `/authorize-sign-prepare` now accepts optional `presentation` and
    `reportedOrigin` body fields. Envelope is size-bounded to ≤16KB
    and dropped on parse failure. When both a caller-declared digest and
    an https `reportedOrigin` are present, the route calls
    `fetchAndBindWellKnownManifest` (new `services/manifest-origin-fetch.ts`)
    which performs an SSRF-guarded GET of `/.well-known/openkey-manifest.json`:
    https-only, no redirects, private-IP-blocked, 5s timeout, 64KB cap.
    A matching canonical SHA-256 upgrades trust to `origin-bound`; any
    failure fails closed to `unsigned`. The trust decision is bound
    into the authorization context and cannot be raised in later steps.

  Web (`@openkey/web`, not published):
  - `SigningApproval` restructured per contract: sensitive callout pinned
    at top (`N exact grants reach secret data or decryption. You can
review them below.`), deterministic per-grant statements in the
    default view via `buildStatement`, and a single `<details>` labelled
    `Advanced details` containing requester, verified origin, manifest
    name/appId/digest under an honest trust label, reason (only when
    present), signing identity, categorized exact-grant list with
    Edit/Reset controls, and the full raw message as a
    `user-select: text` `<pre>` with a `Copy text` button that copies
    `model.rawMessage` verbatim. `domainWarning` renders independently
    from `originWarning` — a concrete but mismatched origin no longer
    hides the SIWE-domain mismatch. Approve is blocked when
    `model.protocol === "malformed-recap"`.
  - `widget-transport.ts` validates optional `presentation` field on
    incoming sign requests: fail-closed size cap (16KB), plain-object
    guard, and drops any envelope carrying trust/verification override
    keys (`verified`, `trust`, `metadataTrust`, `manifestVerified`,
    etc.).
  - `widget/sign/+page.svelte` and `widget/embed/sign/+page.svelte` now
    forward the SDK-supplied `presentation` and the widget's configured
    https `origin` as `reportedOrigin` to `/authorize-sign-prepare`,
    adopt the server-returned `metadataTrust` and `verifiedManifest`,
    and use them to build the review model. Trust decision is
    authoritative from the server prepare response; envelope claims
    cannot upgrade it. A `malformed-recap` model also short-circuits the
    legacy `signMessage` fallback path.
  - `delegate/+page.svelte` keeps the frozen baseline for grant
    edit/reset semantics BUT updates `reviewModel.rawMessage` whenever
    `applyPreparedDelegation` receives a new `prepared.siwe`, so the
    displayed exact bytes always match what will actually be signed.

  Test discovery:
  - Root `bunfig.toml` under `[test].ignore` excludes
    `apps/web/tests/browser/**/*.spec.ts` (Playwright suite) and
    `scripts/authorize-sign-harness.test.ts` (subprocess harness) from
    broad `bun test` walks.
  - The harness carries a defence-in-depth top-of-file guard: it exits
    early unless `OPENKEY_RUN_HARNESS=1` is set. The js-sdk cross-repo
    contract test spawns it with that env explicitly.

- a5bc820: Documentation-only changeset entry for `@openkey/capability-review`;
  the substantive code changes below live in `@openkey/web`, which is
  ignored by the release config. This entry exists so the release
  changelog references the parity contract that
  `@openkey/capability-review` consumers (the surface adapters) rely on.

  Substantive signing-approval production adapters and browser-driven
  parity coverage (Sol MAJOR-1 final continuation, iteration 2).

  The three OpenKey signing surface adapters
  (`src/lib/components/signing/{cli,popup,iframe}-signing-adapter.svelte`)
  were previously thin pass-through wrappers around
  `SigningApproval` — every route-specific behavior lived in inline
  callbacks on the route. This meant a bug in a route's approve-path
  routing (`requestPreview` vs `approveAndSign`), its selection-change
  handler (dropping `invalidatePreviewForSelectionEdit`), or its
  selection→server-key mapping (`mapReviewSelectionToActionKeys`) could
  NOT be caught by parity tests that mounted the adapters.

  Changes in `@openkey/web` (not published; ignored in release config):
  - Two transport interfaces at
    `src/lib/components/signing/signing-adapter-types.ts`:
    `CliSigningTransport` (delegate/callback + selection remap) and
    `WidgetSigningTransport` (preview vs exact-byte routing +
    selection-edit invalidation).
  - Each of the three surface adapters is now substantive: it owns its
    review-selection and editing state and implements the surface-
    specific `onApprove` / `onCancel` / `onSelectionChange` /
    `onEditingChange` wiring. Routes hand each adapter a `transport`
    implementation matching the surface's contract; nothing route-
    specific is inlined at the JSX site any more.
  - Widget transports expose whether a server-sealed preview is ready.
    The first approval prepares exact bytes; the second approval stays in
    the same shared content view and consumes those bytes. Popup and iframe
    no longer replace the categorized grants, Advanced details, manifest
    provenance, signing identity, and copyable raw message with a route-
    local final card.
  - The three production routes (`/delegate`, `/widget/sign`,
    `/widget/embed/sign`) now mount their respective adapters with the
    new transport-based API. Selection state and completion callbacks
    live inside the adapter; the routes remain responsible for building
    the initial `CapabilityReviewModel` and constructing the transport
    that reaches the surface-specific completion path.

  Parity coverage:
  - `apps/web/src/lib/signing-approval-parity-mounted.test.ts` mounts
    the EXACT three production adapter components in happy-dom,
    supplies spy transports whose shape matches the production
    transports one-for-one, and drives Space (on checkbox) and Enter/
    Space (on approve/cancel buttons) via real `KeyboardEvent`
    dispatches. Assertions confirm that (a) the shared DOM projection
    is identical across all three surfaces for the same model, and
    (b) the adapter-specific transport call is invoked with the
    correct payload after each real keyboard interaction. Dropping
    `invalidatePreview`, `onSelectionEdited`, `updateSelection`, or a
    surface's approve-path decision fails this suite.
  - `apps/web/tests/browser/signing-approval-parity.spec.ts` boots
    Chromium via Playwright, navigates to a dev-only harness route
    (`/__parity_harness`, guarded by `dev` from `$app/environment`),
    and drives every interaction via `page.keyboard.press` — real
    Tab-driven focus movement, real Enter/Space synthesis on buttons,
    native `<details>` open toggling on summary click and keyboard.
    25 tests cover the three surfaces, the widget's
    `canUseAuthorizeSign=false` fallback, its shared final-preview state,
    legacy exact-byte requests, and malformed-request fail-closed behavior.

  Legacy `apps/web/src/lib/signing-approval-parity.test.ts` is now a
  structural guardrail only: it asserts each production route imports
  and mounts the correct named adapter (no direct `<SigningApproval>`
  in a route), each adapter mounts the shared component, and each
  adapter is typed against the correct transport interface. It no
  longer parses source text to rewrite prop expressions — that
  approach was banned by the approval contract.

  What this changeset does NOT claim:
  - Cross-repo integration: the browser parity suite exercises only
    OpenKey's own adapters. The consumer-side wire-format acceptance
    and end-to-end round-trip live in the companion js-sdk changeset.
  - The shared component's authority decisions. It receives a
    presentation-only `finalPreview` state so its hint and action label
    accurately describe the sealed-byte approval; token validation and
    signing remain route/server responsibilities.
