---
"@openkey/sdk": patch
"@openkey/capability-review": patch
"@openkey/api": patch
"@openkey/web": patch
---

Sol final-continuation-review fixes on the OpenKey authorization consolidation.
Every claim below corresponds to a delivered test that fails on the prior
implementation and passes with these changes.

Requirement 1 — Canonical four-part action IDs across every producer/consumer.

The on-wire structure of a TinyCloud ReCap resource is
`<space>/<short-service>[/<sub-path>]`; the WASM `parseRecapFromSiwe` emitter
strips the `<short-service>` segment out of `entry.path`. The prior consumer
side inside `signInWithOpenKeyResult` kept the service segment INSIDE `path`
(e.g. `path="kv"` for a `<space>/kv` resource), which produced a four-part
action ID that never matched what OpenKey emits via `computeActionKey`
(which uses `entry.path` directly). Real production round-trips fell
through the `grantedFourPartIndex.get(rawKey)` lookup silently.

Delivered:
- `packages/capability-review/src/parse.ts::splitResourceUri` now strips
  the `<short-service>` segment and returns a WASM-aligned `{ space, path }`.
- The delegate router's `computeActionKey` already used the WASM entry;
  no behaviour change there, but it is now byte-for-byte consistent with
  the capability-review parser and the js-sdk consumer.
- New `packages/capability-review/test/parse.test.ts` case
  `"splits resource URI path from space for path-scoped recap entries"`
  and the updated `REAL_RECAP_SAME_ABILITY_TWO_PATHS` fixture prove the
  parser matches WASM's `entry.path` for whole-space, path-scoped, and
  repeated-space URI shapes.
- The nodeauth-e2e test's `groundedPairs` construction now walks the
  RAW ATT keys (like the real js-sdk consumer does) via a canonical
  helper, so a producer/consumer divergence fails the test loudly.

Requirement 1 (final) — Wire-format acceptance test at the HTTP boundary.

Sol's final rejection called out that the OpenKey e2e test verified
the finalize response's `selectedActionKeys` looked canonical but did
NOT prove the actual `signInWithOpenKeyResult` consumer would accept
the response. Because the OpenKey and js-sdk repos ship separately,
a direct cross-repo import inside the OpenKey test graph is
impractical. The fix runs the SAME wire-format contract from BOTH
sides:

Delivered:
- OpenKey side: new test
  `apps/api/src/__tests__/delegate-authorize-sign-nodeauth-e2e.test.ts::
  finalize body validates against a MIRROR of every
  signInWithOpenKeyResult wire-format check` calls the real Hono
  `/authorize-sign` route through the router and asserts every
  wire-format guard the SDK consumer runs: protocolVersion === 1,
  address is EIP-55 shaped, signature recovers to address, signedMessage
  is a parseable SIWE with all required header lines, selectedActionKeys
  are canonical four-part IDs with no duplicates, permissions have
  non-empty actions, every selectedActionKey resolves to a (resource,
  ability) pair in the signedMessage ATT (mirrors
  `grantedFourPartIndex.get(rawKey)`), and every permissions action
  appears in the signedMessage ATT.
- js-sdk side (companion, in js-sdk repo): new tests in
  `packages/node-sdk/src/authorization/NodeUserAuthorization.signInWithOpenKeyResult.test.ts`
  construct a finalize body BYTE-FOR-BYTE in the shape the Hono route
  emits (`{ protocolVersion, address, signature, signedMessage,
  selectedActionKeys, permissions }`) and hand it directly to the
  REAL `signInWithOpenKeyResult` (no bridge, no simulator). Both the
  unmodified round-trip AND the narrowed round-trip must complete.
- Together the two tests cover the boundary from BOTH sides using
  real production code paths.

Requirement 3 — Exact caveat semantics for surviving abilities.

Removing a whole resource or a whole ability is allowed; adding, changing,
removing, or changing the duplicate count of ANY caveat on a SURVIVING
ability is forbidden. The prior `attenuationSubsetFailure` allowed
candidate to drop caveats (multiset-subset semantics), which broadens
authority relative to the recorded baseline.

Delivered:
- `apps/api/src/services/authorization-signing.ts::attenuationSubsetFailure`
  enforces EXACT multiset equality on caveats for every surviving
  (resource, ability) pair. Whole-ability and whole-resource removal
  remain allowed; every other transformation surfaces as
  `candidate-broadens-baseline` with a message citing the specific
  change (added/removed/count-increased/count-decreased).
- Service-layer tests in
  `apps/api/src/services/authorization-signing.test.ts::caveat semantics`
  cover: identical baseline (accept), whole-ability removal (accept),
  whole-resource removal (accept), caveat removal (reject), caveat add
  (reject), caveat change (reject), duplicate-count decrease (reject),
  duplicate-count increase (reject), ability broadening (reject), and
  resource broadening (reject).
- HTTP-route regression in
  `apps/api/src/__tests__/delegate-authorize-sign-routes.test.ts` proves
  whole-ability removal succeeds end-to-end through prepare → preview
  → finalize with immutable header lines preserved.

Requirement 3 (final) — Route-level caveat preservation over the wire.

Sol's final rejection called out that the route-level tests only
asserted the top-level statement changed — they did not decode the
`urn:recap:` payload from BOTH the baseline SIWE and the finalized
`signedMessage` and prove the caveat multisets on surviving abilities
matched byte-for-byte over the actual HTTP boundary. Delivered:

- New route-level tests in
  `apps/api/src/__tests__/delegate-authorize-sign-routes.test.ts`:
  - `finalize preserves baseline caveat multisets (byte-for-byte) on
    retained abilities across the HTTP route` decodes the ATT map from
    both the baseline SIWE and the finalized signedMessage via the
    same base64url decoder the SDK consumer walks, and asserts
    multiset equality on every surviving (resource, ability) pair.
  - `finalize preserves baseline caveat duplicate counts on retained
    abilities` asserts array-length equality per surviving ability so
    a bug that quietly added a caveat that coincidentally matched a
    baseline caveat would still fail.
  - `full-selection round-trip preserves the entire baseline ATT map
    byte-for-byte on the HTTP route` asserts structural identity of
    the ATT map (resource set, ability set per resource, caveat
    multiset per ability) when no narrowing was requested.

MINOR — Multiset caveat comparison in the shared subset validator.

Delivered:
- `packages/capability-review/src/subset.ts::canonicalMultisetEqual`
  compares caveats by canonical-JSON multiset equality: object keys
  are sorted recursively before comparison, and duplicates are
  respected. Prior code used `JSON.stringify(caveats)` which rejected
  two structurally identical baselines whose keys serialized in a
  different order.
- New tests in `packages/capability-review/test/subset.test.ts` cover
  canonicalMultisetEqual (empty, key-order-insensitive, sequence-
  position-insensitive, duplicate-count-sensitive, content-sensitive,
  nested-object-key-order-insensitive, array-element-order-sensitive)
  and `assertBaselineSubset` (accepts key-reordered caveats, rejects
  dropped/duplicate-count-changed/swapped caveats).

Requirement 4 — CLI/popup/iframe parity via mounted accessible DOM.

Sol's final rejection called out that the prior parity test mounted
three IDENTICAL synthetic wrappers via a shared factory — equality was
trivially true regardless of what the production surfaces did. If any
of the three surfaces silently diverged in its `<SigningApproval .../>`
invocation, the test would not have noticed. Delivered:

- `apps/web/src/lib/signing-approval-parity.test.ts` now derives EACH
  wrapper from the ACTUAL production `+page.svelte` source:
  1. Reads `apps/web/src/routes/delegate/+page.svelte`,
     `apps/web/src/routes/widget/sign/+page.svelte`, and
     `apps/web/src/routes/widget/embed/sign/+page.svelte`.
  2. Extracts the LITERAL `<SigningApproval .../>` block from each.
  3. Rewrites the extracted mount into a per-surface Svelte wrapper
     that mounts the shared SigningApproval SSR module with the
     EXTRACTED prop expressions (value props bind to `$props()`;
     callback identifiers stub to a shared no-op).
  4. SSR-renders each wrapper with the same fixture model+selection
     and extracts a normalized accessibility projection (roles,
     aria-label, aria-checked, aria-expanded, aria-modal, tabindex,
     buttons, semantic tags, text nodes).
  5. Asserts every surface's projection matches.
- Extra structural cross-checks:
  - Every surface passes `model` + `selection` props.
  - No surface injects visible text INSIDE the SigningApproval mount
    (self-closing form or empty children only — comments allowed).
- Keyboard-accessibility affordance test verifies `aria-modal=true`
  on the dialog, `aria-label` on named regions, `text="Approve"`/
  `text="Cancel"` on the action buttons, and `<input>` presence for
  per-action checkboxes in editing mode.
- Narrowed-selection test proves `checked` reflection on the derived
  wrapper responds correctly to selection changes — a surface that
  failed to bind `selection` would fail here.

Requirement 5 — Iframe resize traffic correlated by requestId + protocolVersion.

Widget-side:
- `apps/web/src/lib/widget-transport.ts::emitResize` includes the
  active `requestId` alongside `protocolVersion` on every resize
  message. `emitResize` is a no-op when no sign request is in flight,
  so a widget cannot emit an uncorrelated resize.

Parent-side (`@openkey/sdk`):
- `IframeModal.setExpectedCorrelation(requestId, protocolVersion)` binds
  the expected correlation before the request is posted into the
  iframe. Every incoming resize is validated via
  `validateIframeResize` — wrong requestId, wrong protocolVersion,
  missing correlation, invalid height, and no-active-request cases are
  all dropped.

Requirement 5 (final) — Fallback resize on the embed sign page.

Sol's final rejection called out that the embed sign page's LEGACY
fallback resize (used when the shared transport failed to construct —
wildcard-origin compat path) still emitted `{ type: 'openkey:resize',
height, protocolVersion: 1 }` with NO requestId, letting a stray
sibling frame's resize be accepted. Delivered:

- `apps/web/src/routes/widget/embed/sign/+page.svelte` fallback branch
  now emits `{ type: 'openkey:resize', height, protocolVersion:
  messageProtocolVersion, requestId: currentRequestId }`. When no
  active request is bound (bootstrap), the branch short-circuits
  rather than emitting an uncorrelated resize.
- New tests in `apps/web/src/lib/iframe-resize-correlation.test.ts`:
  - Source-level assertion that the pre-fix payload literal is gone.
  - Source-level assertion that the fallback references
    `currentRequestId` and `messageProtocolVersion`.
  - Source-level assertion that the "no active request → return"
    guard exists in the fallback branch.
  - Pre-existing wildcard-origin guard is preserved.
- Extended parent-side tests in `packages/sdk/src/index.test.ts`
  cover: wrong requestId dropped, wrong protocolVersion dropped,
  missing requestId dropped (the exact pre-fix payload shape), no
  active request bound → dropped, and sequential-request rebinding
  (old requestId rejected after rebind).

Requirement 4 (final external routing) — MAJOR-4.

Sol's final rejection called out that the SDK's `authorizeTinyCloud`
routing check for external keys required
`this.lastAuth?.keyId === explicitKeyId && ... === 'EXTERNAL'`. If
a caller passed an `explicitKeyId` that did not string-match
`lastAuth.keyId` (address vs internal id form; casing drift), the
external branch was NOT taken and the managed widget path was
invoked — which then called `/authorize-sign` without an
externalSignature and errored on server-side signing (the private
material is in the browser wallet, not on the OpenKey server).

Delivered:
- `packages/sdk/src/index.ts::shouldRouteAuthorizeTinyCloudExternal`
  — a pure exported helper that decides routing from the ACTIVE
  session's keyType alone. A user cannot be authenticated with two
  different active session keys at once, so `lastAuth.keyType` is
  definitive: EXTERNAL → external branch, MANAGED → managed branch,
  null → managed (widget renders a connect flow first).
- `authorizeTinyCloud` uses the helper for its routing decision.
- New tests in `packages/sdk/src/index.test.ts` cover every branch:
  external session with no explicit keyId, external session with
  matching explicit keyId, external session with DIFFERENT explicit
  keyId (the exact case Sol rejected), managed session with explicit
  keyId, managed session with no explicit keyId, and null/empty
  lastAuth.

What these changesets do NOT claim:
- Byte-for-byte parity across every DOM attribute of live production
  `+page.svelte` renders (SvelteKit runtime globals are outside the
  test harness); parity is enforced by projection over the SSR-rendered
  shared component mounted via per-surface wrappers DERIVED from the
  production sources, plus static import + prop-passing checks on each
  surface page.
- Multi-round narrowing of caveats. The pipeline reuses baseline caveats
  when regenerating a narrowed SIWE, so through the HTTP API the
  caveat multiset is guaranteed by construction — the caveat-drift
  rejection paths are exercised at the service layer where a candidate
  attenuation can be injected directly, and the wire-level
  preservation is exercised end-to-end through the HTTP routes.
- Direct cross-repo import of the js-sdk `signInWithOpenKeyResult` from
  the OpenKey test graph (separate repos, separate package managers,
  separate WASM builds). Instead a MIRROR of every wire-format
  validator is asserted from the OpenKey side, and a matching test on
  the js-sdk side hands a byte-for-byte Hono-route-shaped finalize body
  to the REAL `signInWithOpenKeyResult` consumer.
