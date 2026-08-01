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

Requirement 3 — Exact caveat semantics for surviving abilities.

Removing a whole resource or a whole ability is allowed; adding, changing,
removing, or changing the duplicate count of ANY caveat on a SURVIVING
ability is forbidden. The prior `attenuationSubsetFailure` allowed
candidate to drop caveats (multiset-subset semantics), which broadens
authority relative to the recorded baseline.

Delivered:
- `apps/api/src/services/authorization-signing.ts::attenuationSubsetFailure`
  now enforces EXACT multiset equality on caveats for every surviving
  (resource, ability) pair. Whole-ability and whole-resource removal
  remain allowed; every other transformation surfaces as
  `candidate-broadens-baseline` with a message citing the specific
  change (added/removed/count-increased/count-decreased).
- New service-layer tests in
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

Requirement 4 — CLI/popup/iframe parity via mounted accessible DOM.

The prior parity test only asserted that each surface imports the same
component. Sol explicitly called that inadequate. The new suite
SSR-compiles the shared `SigningApproval.svelte` and mounts it via
identical wrappers for each surface, then compares the accessibility
projections (roles, aria-label/labelledby, tabindex, buttons, controls).

Delivered:
- `apps/web/src/lib/signing-approval-parity.test.ts` now SSR-renders
  `SigningApproval` (using `svelte/server`) through per-surface wrappers,
  extracts a normalized accessible-DOM projection, and asserts every
  surface produces the same projection for the same model. Narrowing
  the selection changes rendered `checked` attributes deterministically.
- The prior source-text parity check is retained as a static complement
  so a diverged wrapper surfaces at both the runtime and the source
  layer.

Requirement 5 — Iframe resize traffic correlated by requestId + protocolVersion.

Widget-side:
- `apps/web/src/lib/widget-transport.ts::emitResize` now includes the
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

Delivered tests:
- `apps/web/src/lib/widget-transport.test.ts::emitResize correlation`
  covers: dropped when no active request, emitted with requestId +
  version when in flight, requestId reflects a NEW request after
  respond, dropped again after respond clears the active request.
- `packages/sdk/src/index.test.ts::validateIframeResize` covers every
  rejection branch: wrong requestId, wrong protocolVersion, missing
  requestId, missing protocolVersion, no active request bound, invalid
  height (0/negative/NaN/Infinity/non-numeric), wrong `type`
  discriminant, non-object incoming, and sequential-request rebinding
  (old requestId rejected after rebind).

What these changesets do NOT claim:
- Byte-for-byte parity across every DOM attribute of live production
  `+page.svelte` renders (SvelteKit runtime globals are outside the
  test harness); parity is enforced by projection over the SSR-rendered
  shared component AND static import checks on each surface page.
- Multi-round narrowing of caveats. The pipeline reuses baseline caveats
  when regenerating a narrowed SIWE, so through the HTTP API the
  caveat multiset is guaranteed by construction — the caveat-drift
  rejection paths are exercised at the service layer where a candidate
  attenuation can be injected directly.
