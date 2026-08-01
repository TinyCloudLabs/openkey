---
"@openkey/sdk": patch
"@openkey/capability-review": patch
"@openkey/api": patch
"@openkey/web": patch
---

Sol continuation-review v2 fixes on the OpenKey authorization consolidation.

Critical:
- Real production SIWEs — every `NodeUserAuthorization.prepareSessionForSigning()`
  output carries a non-empty "I further authorize..." ReCap statement — are
  now narrowable through `/api/delegate/authorize-sign-preview` and
  `/api/delegate/authorize-sign`. The prior implementation rejected every
  such SIWE with `immutable_fields_not_preservable` because the guard
  refused to regenerate when `statement`, `notBefore`, `requestId`, or
  `nonRecapResources` was non-empty. New helper
  `narrowSiwePreservingImmutable` regenerates the SIWE via WASM
  `prepareSession` for the narrowed abilities and splices ONLY the
  ReCap-derived statement + `- urn:recap:` lines back into the ORIGINAL
  SIWE bytes. Every immutable header field (URI, Version, Chain ID, Nonce,
  Issued At, Expiration Time, Not Before, Request ID, non-ReCap resources)
  survives byte-for-byte.

Major:
- Baseline abilities digest at `/api/delegate/authorize-sign-prepare` now
  digests the FULL ReCap attenuation INCLUDING caveat multisets, via
  `digestFullRecapAttenuation`. The finalize step compares the
  regenerated candidate's attenuation against this baseline for a strict
  subset check (`attenuationSubsetFailure`) — dropping a caveat is
  forbidden because caveats narrow authority. The prior tautological
  check compared two derivations of the same caveat-stripped `entries`.
- External-key `authorizeTinyCloud` no longer bypasses the shared review
  UI or auto-selects everything. The SDK now opens the widget in
  `externalSign: true` mode; the widget renders the SAME SigningApproval
  component the managed flow uses, calls prepare + preview, and — on
  approval — hands back the preview payload
  (`authorizationContextToken`, `previewApprovalToken`, `signedMessage`,
  `selectedActionIds`, `address`). The SDK then invokes the wallet on
  the previewed bytes and finalizes `/authorize-sign` with the resulting
  `externalSignature`. An explicitly-supplied EXTERNAL keyId now routes
  to the external path even when `lastAuth` is not EXTERNAL.
- Popup close-message correlation: the SDK popup listener requires
  exact `requestId` + `protocolVersion` on `openkey:close` messages for
  versioned flows. The widget transport tracks the active request ID
  and drops close messages whose requestId does not match, refusing
  overlapping second requests. New widget-transport tests cover
  wrong-requestId close, correlated close, missing-protocolVersion
  close, and overlapping-request rejection.
- `classifyRecapEntry` and `buildGrants` NEVER fall back to the signer
  address as the ownership axis. `trustedOwnershipAxis` is set only from
  a VERIFIED requester identity; unverified requester classifies as
  `cross-app-data` and `ownedBySelf` reports `null` (unknown) rather
  than `true`. This closes the SigningApproval cross-app-warning bypass
  where a signer whose wallet owned the target space silently suppressed
  the warning.
- Cross-surface parity test suite: `signing-approval-parity.test.ts`
  asserts that all three authorization surfaces (`/delegate/+page.svelte`,
  `/widget/sign/+page.svelte`, `/widget/embed/sign/+page.svelte`) import
  the single `SigningApproval` component, derive the model via
  `parseCapabilityReview`, use `defaultSelection`, pass the same props,
  and do not implement their own permission-list markup.
- Real OpenKey ↔ NodeUserAuthorization round-trip test
  (`delegate-authorize-sign-nodeauth-e2e.test.ts`) invokes the ACTUAL
  Hono router with a SIWE produced by the same WASM emitter
  `NodeUserAuthorization.prepareSessionForSigning()` uses, walks the
  full prepare → preview → finalize pipeline, asserts the wire shape
  `signInWithOpenKeyResult` validates against (protocolVersion,
  canonical 4-part `selectedActionKeys`, grouped `permissions`, signature
  verification), and proves narrowing removes exactly the selected
  actions with every immutable header field preserved.
