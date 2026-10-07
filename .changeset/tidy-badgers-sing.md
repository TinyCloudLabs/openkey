---
"@openkey/sdk-react-native": minor
"@openkey/core": patch
---

`BrowserOpener` now returns the auth-session result instead of `void`. An
opener that resolves `{ type: 'success', url }` (the shape of
expo-web-browser's `openAuthSessionAsync`) has its `url` fed into
`handleCallback()` by the SDK itself; `{ type: 'cancel' | 'dismiss' | 'locked' }`
settles the pending `signIn()` with `USER_CANCELLED` immediately instead of
waiting out the 5-minute timeout; a thrown error rejects `signIn()`. A legacy
opener that resolves `void` still works through the deep-link
`handleCallback(url)` path. `handleCallback` now validates `iss` (RFC 9207)
and `state` and rejects `STATE_MISMATCH` on either mismatch, rejects
`ACCESS_DENIED` on `error=access_denied`, and `SERVER` on any other `error=`.
New `OpenKeyErrorCode` values `ACCESS_DENIED` and `SERVER` were added to
`@openkey/core` for this.

The expected issuer is `config.issuer`, defaulting to
`https://api.openkey.so/api/auth` — the OpenKey authorization server,
never derived from `host` (which stays the app/API origin).

`signIn()` scopes are configurable via `scopes` (default unchanged:
`openid email keys offline_access`), and `resource` is now opt-in — it is
**no longer sent by default** (previously it defaulted to `host`, which made
access tokens JWTs with the host as audience; callers relying on that must
pass `resource` explicitly). `signOut()`'s `accessToken` argument is now
optional.

New `delegation` config enables the TinyCloud native-delegation protocol
from `@openkey/core`: RFC 8414 discovery, PAR with an Ed25519 session key,
and `OpenKey-Session-Proof` proofs on code exchange, renewal and
revocation. `signIn()` resolves with `tokens.delegation` set, and
`renew()` rotates the refresh token (persisted via the injected
`OpenKeySecureStore`, plus once after `RENEWAL_CONFLICT` reloads) before
resolving. `renew()` is single-flight keyed on options — identical calls
share the in-flight renewal, different `permissionsSubset`/`siweNonce`
queue behind it (subsets compare in normalized form, so one with and
without `tinycloud.capabilities/read` share a call). A `permissionsSubset`
renew never narrows the stored approved set. Delegation mode requires a
`verifyDelegation` callback — the spec requires the SDK to check `siwe` +
`signature` against `delegationHeader`/`delegationCid`, and the client
fails closed without it. Storage writes are strict and serialized with
`signOut()`'s wipe: a failed persist rejects with
`OpenKeyNativeError('NETWORK')` carrying `rotatedRefreshToken`. Terminal
renew/exchange errors (`INVALID_GRANT`, `CONSENT_REQUIRED`,
`ACCESS_DENIED`, `SPACE_UNAVAILABLE`) wipe the session they apply to
before rethrowing and persist nothing; a rotated refresh token on such an
error is revoked best-effort. A failed `signIn()` (`ACCESS_DENIED`,
`USER_CANCELLED`, `STATE_MISMATCH`, a failed exchange) never wipes an
existing stored session. `signOut()` signs the user out immediately: a
successful or terminally failed revoke wipes the session and resolves,
while a transient revoke failure moves the session key and refresh token
to a pending-revoke record and rejects with the typed error. Only
`NETWORK` and `TEMPORARILY_UNAVAILABLE` (after the internal retry) are
transient; every other revoke error, including `SERVER`, is terminal.
Pending revokes are retried on the next `signOut()`, on construction and
on `signIn()`, and dropped once they succeed or fail terminally. A failed
secure-store write or wipe also rejects. A `signOut()` during an in-flight
`renew()` or code exchange makes it discard its result and reject
`NOT_SIGNED_IN` instead of persisting over the wiped session (an orphaned
exchange grant is revoked best-effort). A delegation returned by sign-in
that is already inside the renewal lead window is renewed before
`signIn()` resolves — if that renew fails non-terminally the error
surfaces but the fresh session stays persisted. `refreshToken()` throws
`UNAVAILABLE` in delegation mode (the provider refresh grant is refused
for native clients). Delegation-mode errors surface as
`OpenKeyNativeError`.
