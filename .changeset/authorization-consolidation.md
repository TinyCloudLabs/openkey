---
"@openkey/sdk": minor
"@openkey/capability-review": minor
"@openkey/api": patch
"@openkey/web": patch
---

Add versioned `authorizeTinyCloud()` protocol (v1) that returns
`{ signature, address, signedMessage, selectedActionKeys, permissions }`.
The legacy `signMessage()` remains byte-exact — OpenKey continues to sign
the caller's original bytes. TinyCloud consumers should switch to
`authorizeTinyCloud()` for editable capability review flows and complete
sessions with the returned `signedMessage`.

Additional hardening:
- New `POST /api/delegate/authorize-sign` endpoint regenerates a narrowed
  SIWE server-side and signs those exact bytes. Widget popup + iframe now
  route editable requests through it so the returned `signedMessage`,
  `selectedActionKeys`, and `permissions` are guaranteed to describe the
  bytes that were actually signed (fixes a bug where a user could deselect
  permissions but the original broad SIWE was still signed).
- `/api/delegate/complete` versioned callers must include an
  `authorizationContextToken` and their `selectedActionIds` must EXACTLY
  match the actions encoded in the signed SIWE (subset or superset both
  rejected). Immutable SIWE field extraction now covers URI, version,
  Not Before, Request ID, statement, and non-recap resources.
- Both widget routes (`/widget/sign` and `/widget/embed/sign`) now enforce
  strict origin + source validation and refuse versioned requests under a
  wildcard origin. The capability-review model is built only after the key
  has loaded (fixes zero-address bug during initial render).
- `capability-review` classifier now distinguishes own-app-data vs
  cross-app-data based on whether the space owner matches a VERIFIED
  requester identity (falling back to attention-level severity when
  requester metadata is unverifiable). App/product identity labels
  require verified manifest metadata bound to the request — the
  classifier does NOT special-case any product name (Listen, Chat,
  Feed, Cycle, etc.) via path prefix.
- SDK `authorizeTinyCloud` no longer silently falls back to
  `request.siwe` when the widget omits `signedMessage` — protocol
  violations now throw.
- Widget signing pages now enforce a distinct final approval step: the
  user MUST review the exact server-returned bytes from
  `/api/delegate/authorize-sign-preview` before `/authorize-sign` is
  invoked. Editing selection invalidates the preview. Overlapping
  transport requests are refused with a `USER_CANCELLED`-style error
  so a second `openkey:sign:request` cannot hijack the in-flight
  approval (per-request state is immutable once sealed).
- `/api/delegate/authorize-sign` now enforces `candidateAbilitiesDigest`
  against the bound baseline so store corruption or bound-SIWE swap
  during consume are hard failures.
- `capability-review` preserves ReCap caveats end-to-end. Actions
  carrying meaningful (non-vacuous) caveats are marked non-editable in
  the UI. `/authorize-sign` refuses to narrow when meaningful caveats
  are present (the WASM emitter drops them; regenerating would broaden
  authority). Note: earlier drafts of this changeset claimed the
  subset validator allowed only "removed caveats"-as-broadening; the
  actual delivered semantic is stricter — see
  `sol-final-continuation-fixes.md`, which enforces EXACT multiset
  equality of caveats for every surviving (resource, ability) pair.
- SDK `authorizeTinyCloud` branches to a preview→wallet-sign→finalize
  flow when the last-connected key is EXTERNAL. The wallet signs the
  server-emitted preview bytes; finalize verifies the signature against
  those exact bytes and refuses any drift.
- SDK iframe resize channel now requires `protocolVersion: 1` — legacy
  unversioned resize messages are dropped so a stray sibling frame
  cannot mutate iframe dimensions.
- Widget page requester metadata now surfaces real `domainWarning`
  (SIWE domain vs origin hostname mismatch) and `originWarning`
  (wildcard origin) rather than hard-coding both to false. Verified
  requester metadata is intentionally left unset (fail-closed
  cross-app classification) until the widget resolves signed manifests.
