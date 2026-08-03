---
"@openkey/capability-review": patch
---

Sol follow-up: address the 7 findings raised after the merge-readiness
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
