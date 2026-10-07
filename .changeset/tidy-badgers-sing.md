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
revocation. `signIn()` resolves with `tokens.delegation` set, and a
single-flight `renew()` rotates the refresh token (persisted via the
injected `OpenKeySecureStore`, plus once after `RENEWAL_CONFLICT` reloads)
before resolving. Delegation mode requires a `verifyDelegation` callback —
the spec requires the SDK to check `siwe` + `signature` against
`delegationHeader`/`delegationCid`, and the client fails closed without it.
Storage writes are strict: a failed persist rejects with
`OpenKeyNativeError('NETWORK')` carrying `rotatedRefreshToken`, and a failed
credential wipe makes `signOut()` reject. A `signOut()` during an in-flight
`renew()` makes that renew discard its result and reject `NOT_SIGNED_IN`;
`refreshToken()` throws `UNAVAILABLE` in delegation mode (the provider
refresh grant is refused for native clients). Delegation-mode errors
surface as `OpenKeyNativeError`.
