---
"@openkey/sdk": minor
"@openkey/capability-review": minor
---

Consolidate the OpenKey authorization surfaces onto a single shared review
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
