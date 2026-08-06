# @openkey/sdk

## 0.10.0

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

- 9039854: Add organization-scoped managed-account registration, lifecycle, entitlement,
  and webhook management contracts.
- 6850fb9: Add the OpenKeyNostr browser API for managed identity discovery and consent-based event signing.

### Patch Changes

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

## 0.9.0

### Minor Changes

- 85c6417: Expose `getSessionToken()` and `tinycloudSigningOptions()` so apps can construct a TinyCloud auto-sign signing strategy against `POST /api/delegate/sign` with bearer authentication.

## 0.8.8

### Patch Changes

- f478606: Allow embedded OpenKey registration popups to escape the SDK iframe sandbox.
- Updated dependencies [f478606]
  - @openkey/core@0.8.8

## 0.8.7

### Patch Changes

- 7369be3: Remove backdrop blur from SDK modal scrims to avoid translucent background rendering artifacts under native overlays.

## 0.8.6

### Patch Changes

- e09589d: Allow SDK-created iframes to use clipboard writes so embedded OpenKey copy buttons can work.

## 0.8.5

### Patch Changes

- Updated dependencies [fe323ae]
  - @openkey/core@0.8.5

## 0.8.0

### Minor Changes

- 44bdb60: Rename OpenKeyEIP1193Provider to OpenKeyProvider. The old name is kept as a deprecated alias for backwards compatibility.

## 0.7.2

### Patch Changes

- 90f5787: Fix sequential signMessage requests failing with USER_CANCELLED

  When a dapp called signMessage twice in sequence (e.g., vault unlock deriving two keys), the second request was rejected with USER_CANCELLED. The openkey:close message from the first sign widget iframe was being received by the second modal's message handler. Added event.source checks to IframeModal and popup message handlers so each only processes messages from its own iframe/popup window.

## 0.7.1

### Patch Changes

- b87511e: Fix workspace:\* dependencies leaking to npm — resolve to concrete versions before publish
- Updated dependencies [b87511e]
  - @openkey/core@0.7.1

## 0.7.0

### Patch Changes

- bfa5806: Extract shared PKCE, OAuth URL building, token exchange, and error handling into @openkey/core. Refactor @openkey/sdk and @openkey/sdk-react-native to use @openkey/core instead of duplicated internal implementations. No public API changes to existing SDKs.
- Updated dependencies [bfa5806]
  - @openkey/core@0.7.0

## 0.6.0

### Minor Changes

- ef37d13: Support direct EOA wallet connect in non-OAuth flows. When an EOA wallet is detected (EIP-6963 or window.ethereum), the connect widget shows a muted "or use an external wallet" option below the passkey sign-in button. Selecting it routes back to the SDK's wallet picker, bypassing OpenKey authentication entirely.

## 0.5.2

### Patch Changes

- 97cfdd3: Show error toast when popup is blocked by the browser

## 0.5.1

### Patch Changes

- 2cc7e60: Fix OAuth host derivation for localhost: skip `api.` prefix for localhost/127.0.0.1 since the OAuth API is behind the same proxy in local development.

## 0.5.0

### Minor Changes

- 418e6f0: Add oauthHost config option for separate OAuth endpoint resolution. Defaults to deriving from host by prefixing 'api.' to the hostname.
- 3ba5a47: Delegate registration to popup when in iframe embed mode

  Google OAuth sends `X-Frame-Options: DENY`, preventing sign-in with Google inside an iframe. The embed connect widget now delegates registration to the parent SDK, which opens a popup window for the full registration flow (email/Google + passkey). After completion, the session token is relayed back to the iframe via postMessage.

## 0.4.0

### Minor Changes

- db03d51: Delegate registration to popup when in iframe embed mode

  Google OAuth sends `X-Frame-Options: DENY`, preventing sign-in with Google inside an iframe. The embed connect widget now delegates registration to the parent SDK, which opens a popup window for the full registration flow (email/Google + passkey). After completion, the session token is relayed back to the iframe via postMessage.

## 0.3.0

### Minor Changes

- 2b5a9d6: Add cookieless passkey authentication for iframe embed mode. Proxy endpoints replace cookie-based challenge storage with token-based flow, and bearer plugin enables session persistence without third-party cookies.

## 0.2.1

### Patch Changes

- 5ccc896: Fix iframe modal sizing and update to light theme: remove 700px height cap, use scrollHeight for accurate resize reporting, match modal card background to embed content, remove dark mode overrides

## 0.2.0

### Minor Changes

- a61310d: Add iframe modal as default UI mode, replacing popups.
  - Add `IframeModal` with responsive layout (centered card on desktop, bottom sheet on mobile)
  - Add `WalletPicker` component for parent-side wallet discovery delegation
  - Add `mode` config (`'iframe' | 'popup' | 'redirect'`) with per-operation override
  - Auto-fallback to popup when iframe is blocked by CSP
  - Add embed widget routes (`/widget/embed/connect`, `/widget/embed/sign`, `/widget/embed/sign-typed-data`)
  - Remove `usePopup` config option

## 0.1.0

### Minor Changes

- 6bec495: Fix external wallet linking and signing flow
  - Fix package.json exports map (ESM → index.mjs, CJS → index.js)
  - Add EIP-6963 wallet discovery to link-wallet widget for wallet selection
  - Navigate back to connect page after linking so auth resolves with keyType
  - Use eth_requestAccounts in findWalletProvider to authorize in app context
  - External keys now route signing directly to the user's wallet instead of OpenKey popup

## 0.0.2

### Patch Changes

- afd48ad: Add comprehensive README documentation with usage examples, API reference, and integration guides for ethers.js and TinyCloud.
