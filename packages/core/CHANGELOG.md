# @openkey/core

## 0.12.0-beta.0

### Minor Changes

- 5b993e2: Add the platform-agnostic native TinyCloud delegation module (`native-delegation.ts`): validated RFC 8414 discovery, PAR and authorize-URL builders for `tinycloud_delegation` authorization details, Ed25519 session keypairs with `did:key` and JWK serializations, the `OpenKey-Session-Proof` compact JWS signer, RFC 9207 `iss`/`state`/`error` callback parsing, token/renew/revoke clients with injectable fetch and delegation response validation, and the `OpenKeyNativeError` code set.

### Patch Changes

- 5b993e2: Expose an optional token-exchange callback that lets native SDKs durably record an issued refresh token before delegation validation, and add a distinct `STORAGE` native error code for local secure-store failures.
- 5b993e2: `BrowserOpener` now returns the auth-session result instead of `void`. An
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
  `OpenKeyNativeError('STORAGE')` without `rotatedRefreshToken` — the SDK
  cannot take the token back, so it revokes the grant (a pending revoke if
  that fails transiently; if the pending-revoke write fails too, the revoke
  attempt is all it can do). Terminal renew/exchange errors
  (`INVALID_GRANT`, `CONSENT_REQUIRED`, `ACCESS_DENIED`,
  `SPACE_UNAVAILABLE`) wipe the session they apply to before rethrowing and
  persist nothing; the grant of a rotated refresh token on such an error is
  abandoned (below). A failed `signIn()` (`ACCESS_DENIED`, `USER_CANCELLED`,
  `STATE_MISMATCH`, a failed exchange) never wipes an existing stored
  session. `signOut()` signs the user out immediately: a successful or
  terminally failed revoke wipes the session and resolves, while a transient
  revoke failure moves the session key and refresh token to a pending-revoke
  record and rejects with the typed error. Only `NETWORK`,
  `TEMPORARILY_UNAVAILABLE` (after the internal retry), any HTTP 5xx from
  the revoke endpoint or server discovery, and HTTP 429 are transient; every
  other revoke error, including any other 4xx, is terminal. Pending revokes
  are retried on the next `signOut()`, on construction and on `signIn()`,
  and dropped once they succeed or fail terminally, once the refresh token
  has expired (7 days, or the grant's absolute expiry if sooner), or after
  20 attempts. A failed server discovery is never cached. A failed
  secure-store write or wipe also rejects. A `signOut()` during an in-flight
  `signIn()` (including discovery and PAR), `renew()` or code exchange makes
  it discard its result and reject `NOT_SIGNED_IN` instead of persisting
  over the wiped session (the orphaned grant is abandoned), and the user
  reads as signed out from the moment it starts. Session storage is a
  compare-and-set model with no in-memory cache: every write or removal of
  the stored session (sign-in save, renew save, immediate renew,
  rotated-token recovery, terminal wipe, sign-out removal) states the
  session it expects to be current and writes nothing when that no longer
  holds. `signOut()` signs out whatever session is current, never removes a
  newer one it did not revoke, and rejects with `STORAGE` without removing
  anything when the record can't be read. A `signIn()` started during a
  `signOut()` saves after it. The storage queue is shared by every
  `OpenKeyRN` that uses the same store object, and `OpenKeySecureStore`
  gains an optional atomic `compareAndSet(key, expected, next)`; when a
  store provides it, every write lands only if the value is unchanged, so
  separate store objects or processes sharing a backend stay consistent.
  Apps should otherwise use one store object (ideally the `getOpenKeyRN()`
  singleton) per backend. An error carries `rotatedRefreshToken` only while
  that token is live and not abandoned: a `NOT_SIGNED_IN` refusal, a
  terminal outcome and an error whose recovery save failed carry none,
  because the token was abandoned (revoked, or a pending revoke). Every
  secure-store read or write failure is `STORAGE`; `NETWORK` is reserved for
  real network errors. When local state can't be saved, `STORAGE` is what's
  reported: a failed rotated-token recovery save rejects with `STORAGE` (the
  original error as its `cause`), and `signOut()` rejects with `STORAGE`
  (the revoke error as its `cause`) when a pending-revoke or session write
  fails. No abandoned live grants: every grant the SDK lets go of without
  storing it — the session a `signIn()` replaces, a superseded renew's or
  sign-in's token, an orphaned exchange, a terminal outcome's rotated token,
  a token whose secure-store write failed — is revoked, or kept as a bounded
  pending revoke when the revoke fails transiently. A `signIn()` that has
  not stored its session yet (e.g. a cancelled one) never affects an
  in-flight `renew()`. A delegation returned by sign-in that is already
  inside the renewal lead window is renewed before `signIn()` resolves — if
  that renew fails non-terminally the error surfaces but the fresh session
  stays persisted. `refreshToken()` throws `UNAVAILABLE` in delegation mode
  (the provider refresh grant is refused for native clients).
  Delegation-mode errors surface as `OpenKeyNativeError`.

  `@openkey/core` adds the `STORAGE` native error code (after `NETWORK` in
  `OpenKeyNativeErrorCode`) for local secure-store failures.

## 0.8.8

### Patch Changes

- f478606: Allow embedded OpenKey registration popups to escape the SDK iframe sandbox.

## 0.8.5

### Patch Changes

- fe323ae: Update TypeScript to v6, zod to v4, commander to v14, adapter-cloudflare to v7

## 0.7.1

### Patch Changes

- b87511e: Fix workspace:\* dependencies leaking to npm — resolve to concrete versions before publish

## 0.7.0

### Minor Changes

- bfa5806: Extract shared PKCE, OAuth URL building, token exchange, and error handling into @openkey/core. Refactor @openkey/sdk and @openkey/sdk-react-native to use @openkey/core instead of duplicated internal implementations. No public API changes to existing SDKs.
