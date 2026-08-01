---
"@openkey/sdk": patch
"@openkey/capability-review": patch
"@openkey/api": patch
"@openkey/web": patch
---

Address Sol continuation-review rejection blockers on the OpenKey
authorization consolidation.

Critical:
- `/api/delegate/authorize-sign-preview` now returns a single-use,
  short-lived `previewApprovalToken` that seals the exact
  `selectedActionIds` and the exact `signedMessage` bytes the preview
  evaluated. `/api/delegate/authorize-sign` REQUIRES this token and
  refuses to sign when either the selection or the candidate bytes drift
  from the sealed values. Both widget routes (popup + iframe) and the
  SDK external-wallet flow now round-trip the token.
- `consumeAuthorizationContext` enforces that `selectedActionIds` at
  /complete is a subset of the `initialSelectionActionIds` bound at
  /prepare, not just the full baseline. CLI-driven flows can no longer
  re-add capabilities that the user narrowed away earlier.

Major:
- SDK `authorizeTinyCloud` now falls back to `lastAuth.keyId` when the
  caller did not pass an explicit `keyId`, so the widget receives the
  connected-key context instead of rendering `Please connect first.`
  `NodeUserAuthorization.signInWithOpenKey` accepts and forwards an
  `openkeyKeyId` option through the bridge.
- `extractImmutableSiweFields` and `diffImmutableSiweFields` in
  `sdk-core` now cover `expirationTime`, `notBefore`, `requestId`,
  `statement`, and non-ReCap resources so any drift on those fields
  fails the SDK's immutable-fields check.
- `signInWithOpenKeyResult` now requires the returned `permissions`
  array to equal the signed authority for every resource/action pair,
  including structurally-required capabilities. Missing entries and
  extras both fail (was: only non-required coverage was required).
- `unauthorizedRecapCapabilities` requires strict normalized caveat
  multiset equality between child and parent. Dropping alternatives
  from a disjunction, adding restrictions to an unrestricted parent,
  and any lexical caveat change all reject. Formal attenuation may
  relax this later.
- `classifyRecapEntry` no longer falls back to the signer address as
  the ownership axis when `requesterAddress` is null and
  `requesterVerified` is false. Widget-issued classifications now
  fail-closed to `cross-app-data` when the requester identity is
  unverifiable (rather than silently claiming own-app-data).
- Widget transport runtime-validates the sign-request payload
  (`message`, `keyId`, `jwk`, `host`, `sessionToken`) and correlates
  `openkey:close` to the same protocol version, so a stray message
  cannot tear down or hijack the widget.
- Delegate `/authorize-sign-preview` widget flow keeps a stable
  baseline review model built from the FIRST prepared SIWE and treats
  `reviewSelection` as the effective subset. Re-preparing after a
  narrowing no longer drops removed optional actions from the review
  UI.
- New route-level HTTP tests exercise `/authorize-sign-prepare`,
  `/authorize-sign-preview`, and `/authorize-sign` end to end (missing
  preview approval, preview round-trip, user-mismatch rejection,
  response envelope wire format).
