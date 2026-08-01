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
  cross-app-data based on whether the space owner matches the signer, and
  recognizes real app path families (Listen, Chat, Feed, Cycle health,
  Metadata, Credentials).
- SDK `authorizeTinyCloud` no longer silently falls back to
  `request.siwe` when the widget omits `signedMessage` — protocol
  violations now throw.
