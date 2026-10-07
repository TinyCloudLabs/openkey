# @openkey/sdk-react-native

A React Native OAuth 2.1 + PKCE client for [OpenKey](https://openkey.so). Authenticates users via the system browser (ASWebAuthenticationSession on iOS, Chrome Custom Tabs on Android) -- not a WebView.

Lightweight and headless -- no UI components, just the auth flow.

## Installation

```bash
bun add @openkey/sdk-react-native
```

### Peer Dependencies

- `react-native >= 0.70.0`
- A system browser library:
  - [expo-web-browser](https://docs.expo.dev/versions/latest/sdk/webbrowser/) (Expo projects)
  - [react-native-inappbrowser-rebridge](https://github.com/nickkraakman/react-native-inappbrowser-rebridge) (bare RN)
- Optional SHA-256 polyfill for older Hermes runtimes:
  - [expo-crypto](https://docs.expo.dev/versions/latest/sdk/crypto/)
  - [react-native-quick-crypto](https://github.com/nickkraakman/react-native-quick-crypto)

## Quick Start

```typescript
import { OpenKeyRN } from '@openkey/sdk-react-native';
import * as WebBrowser from 'expo-web-browser';

const openkey = new OpenKeyRN({
  host: 'https://openkey.so',
  clientId: 'your-client-id',
  redirectUri: 'myapp://auth/callback',
  // openAuthSessionAsync already returns {type: 'success', url} /
  // {type: 'cancel'} / {type: 'dismiss'} — return it as-is.
  openBrowser: (url, redirectUri) =>
    WebBrowser.openAuthSessionAsync(url, redirectUri),
});

// Start sign-in (opens system browser). Resolves with the tokens,
// rejects USER_CANCELLED when the sheet is dismissed, ACCESS_DENIED
// when the user denies consent.
const tokens = await openkey.signIn();
console.log(tokens.accessToken);

// Refresh tokens
const newTokens = await openkey.refreshToken(tokens.refreshToken!);

// Sign out
await openkey.signOut(tokens.accessToken);
```

## The `openBrowser` contract

`openBrowser(url, redirectUri)` may resolve to:

| Result | SDK behavior |
|---|---|
| `{ type: 'success', url }` | The SDK feeds `url` into `handleCallback()` itself and runs the token exchange. |
| `{ type: 'cancel' }`, `{ type: 'dismiss' }`, `{ type: 'locked' }` | The pending `signIn()` rejects with `USER_CANCELLED` immediately. |
| `void` (legacy) | The SDK waits for a deep-link `handleCallback(url)` call or the `timeoutMs` timeout — the old behavior. |
| throw / reject | `signIn()` rejects: `OpenKeyError`/`OpenKeyNativeError` pass through, anything else becomes `UNKNOWN`. |

`expo-web-browser`'s `openAuthSessionAsync` returns exactly the result shape
above, so pass its promise through (including the `url` on `success`) — do
not map it to `void` unless you plan to deliver callbacks through deep
links yourself. Bare-RN wrappers such as
`react-native-inappbrowser-rebridge` that don't report a callback URL can
keep resolving `void` and relying on `Linking` + `handleCallback()`.

## Deep Link Setup

Your app must be configured to receive the redirect URI as a deep link.
You still want this configured even with a `success`-returning opener:
it keeps legacy openers working and covers callbacks delivered outside
the auth session.

### iOS (Info.plist)

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLSchemes</key>
    <array>
      <string>myapp</string>
    </array>
  </dict>
</array>
```

### Android (AndroidManifest.xml)

```xml
<intent-filter>
  <action android:name="android.intent.action.VIEW" />
  <category android:name="android.intent.category.DEFAULT" />
  <category android:name="android.intent.category.BROWSABLE" />
  <data android:scheme="myapp" android:host="auth" android:pathPrefix="/callback" />
</intent-filter>
```

## API Reference

### `new OpenKeyRN(config)`

Create an OAuth client instance.

```typescript
const openkey = new OpenKeyRN({
  host: 'https://openkey.so',       // OpenKey server URL
  clientId: 'your-client-id',       // OAuth client ID
  redirectUri: 'myapp://auth/callback', // Deep link redirect URI
  openBrowser: (url, redirectUri) => ..., // Required: opens URL in system browser
  sha256: (input) => ...,           // Optional: custom SHA-256 for PKCE
  timeoutMs: 300_000,               // Optional: sign-in timeout (default 5 min)
  issuer: 'https://api.openkey.so/api/auth', // Optional: expected `iss` + discovery issuer (this is the default; never derived from host — override for staging/self-hosted)
  scopes: ['openid', 'email', 'keys', 'offline_access'], // Optional: requested scopes (this is the default)
  resource: 'https://api.example.com', // Optional: RFC 8707 audience; access tokens become JWTs. Not sent by default.
  delegation: { ... },              // Optional: TinyCloud native-delegation mode (below)
});
```

### `openkey.signIn()`

Start the OAuth 2.0 Authorization Code + PKCE flow. Opens the system browser and resolves when the opener reports `{type: 'success', url}` or `handleCallback()` receives the redirect.

```typescript
const tokens = await openkey.signIn();
```

Every callback must carry `iss` equal to the configured issuer (RFC 9207)
— which defaults to `https://api.openkey.so/api/auth`, the OpenKey
authorization server, and is never derived from `host` — plus a `state`
matching the pending request; a mismatch rejects `signIn()` with
`STATE_MISMATCH`. A callback with `error=access_denied` rejects with
`ACCESS_DENIED`, any other `error` with `SERVER`, and `{type: 'cancel' |
'dismiss' | 'locked'}` results reject with `USER_CANCELLED`.

### `openkey.handleCallback(url)`

Handle an incoming deep link redirect. Call this from your app's URL/deep link handler when your opener resolves `void`. Returns `true` if the URL's `state` matched a pending sign-in flow, `false` otherwise — a callback whose `state` belongs to no pending flow is ignored, never attributed to another flow.

```typescript
const handled: boolean = openkey.handleCallback(incomingUrl);
```

### `openkey.refreshToken(refreshToken)`

Exchange a refresh token for new tokens (plain mode only — in delegation
mode the provider refresh grant is refused; `refreshToken()` throws
`UNAVAILABLE`, use `renew()` instead).

```typescript
const newTokens = await openkey.refreshToken(tokens.refreshToken!);
```

### `openkey.signOut(accessToken?)`

Clear pending sign-in flows, revoke the delegation grant (delegation mode), wipe the stored session, and revoke `accessToken` through the legacy revoke endpoint when given. The user is signed out as soon as `signOut()` starts: `renew()` rejects `NOT_SIGNED_IN`. A revoke failure is transient only when it is `NETWORK` (including an unreachable discovery endpoint), `TEMPORARILY_UNAVAILABLE` still failing after the internal retry, any HTTP 5xx from the revoke endpoint or server discovery, or HTTP 429 — a server outage or rate limit never wipes credentials while the grant may still be active. Every other revoke error (`INVALID_GRANT`, `CONSENT_REQUIRED`, `ACCESS_DENIED`, `SPACE_UNAVAILABLE`, any other 4xx, …) is terminal, since retrying won't change it. If the server revoke succeeds or fails terminally, the session is wiped and `signOut()` resolves. A transient revoke failure replaces the stored session with a *pending revoke* entry that holds the session key, the refresh token, an attempt count and the refresh token's expiry, and `signOut()` rejects with the typed error — the grant may still be active. The SDK retries pending revokes on the next `signOut()`, when an `OpenKeyRN` is constructed, and on `signIn()`. An entry is dropped once its revoke succeeds or fails terminally, once its refresh token has expired (7 days after issue, or the grant's absolute expiry if that is sooner), or after 20 attempts. A failed server discovery is never cached, so the next call retries it. `signOut()` also rejects, with `STORAGE`, if the secure-store read, write or wipe fails.

```typescript
await openkey.signOut(tokens.accessToken);
```

## TinyCloud delegation mode

When `config.delegation` is set, `signIn()` runs the TinyCloud
native-delegation protocol from `@openkey/core`: RFC 8414 discovery, a
pushed authorization request carrying an Ed25519 session key, session
proofs (`OpenKey-Session-Proof`) on code exchange, renewal and revocation.
`signIn()` resolves with `tokens.delegation` set (the validated
`tinycloud_delegation` payload), and `renew()` becomes available.

```typescript
import * as SecureStore from 'expo-secure-store';

const openkey = new OpenKeyRN({
  host: 'https://openkey.so',
  clientId: 'your-native-client-id',
  redirectUri: 'myapp://openkey/callback',
  openBrowser: (url, redirectUri) =>
    WebBrowser.openAuthSessionAsync(url, redirectUri),
  delegation: {
    tinycloudHost: 'https://tee.node.tinycloud.xyz',
    permissions: [
      {
        service: 'tinycloud.kv',
        space: 'applications',
        path: 'com.example.myapp/threads/',
        actions: ['tinycloud.kv/get', 'tinycloud.kv/put'],
      },
      // tinycloud.capabilities/read is added automatically.
    ],
    storage: {
      get: (k) => SecureStore.getItemAsync(k),
      set: (k, v) => SecureStore.setItemAsync(k, v),
      remove: (k) => SecureStore.deleteItemAsync(k),
    },
    // Required — the SDK verifies every returned delegation before
    // accepting it: the spec requires the session SIWE bytes (`siwe`) and
    // `signature` to reproduce `delegationHeader` and `delegationCid`.
    // Implement with the TinyCloud session SDK, e.g.:
    //   verifyDelegation: (d) => tinycloudSession.verifyDelegation(
    //         siwe: d.siwe!,
    //         signature: d.signature!,
    //         delegationHeader: d.delegationHeader!,
    //         delegationCid: d.delegationCid!,
    //       ),
    // Must reject/throw on failure; the SDK fails closed without it.
    verifyDelegation: (delegation) => myTinyCloudVerify(delegation),
    ttlSeconds: 3600,        // Optional; clamped to the client ceiling.
    siweNonce: undefined,    // Optional app-bound SIWE nonce.
  },
});

const result = await openkey.signIn();
// result.accessToken, result.refreshToken, result.delegation

// Later — before result.delegation.expiresAt:
const renewed = await openkey.renew();
// renewed.refreshToken (rotated), renewed.delegation

await openkey.signOut(); // revokes the grant and wipes stored credentials
```

In delegation mode `config.scopes` are appended to the mandatory
`openid offline_access tinycloud:delegation` set on the PAR.

The `storage` interface (`OpenKeySecureStore`) is where the SDK keeps the
Ed25519 session private JWK and the rotated refresh token — back it with
Expo SecureStore, react-native-keychain, or encrypted MMKV. Persistence is
strict: every secure-store read or write failure surfaces as
`OpenKeyNativeError('STORAGE')` (`NETWORK` is only for real network
errors). If a write fails, `signIn()`/`renew()` reject with `STORAGE`
carrying **no** `rotatedRefreshToken`: the SDK has no API to take a token
back, so instead of handing it to the caller it revokes the grant (see
*No abandoned live grants* below), and the user signs in again.
`signOut()` rejects with `STORAGE` if the credential wipe itself fails.

`renew()` is single-flight keyed on its options: concurrent calls with the
same `siweNonce` and an equivalent `permissionsSubset` (compared after
`tinycloud.capabilities/read` is prepended) share one renewal, while a call
with different options is queued behind the in-flight one so two renewals
never race the same refresh token. `permissionsSubset` narrows only that
renewal's delegation: the stored approved set is never narrowed, so a later
plain `renew()` asks for the full approved set again. It persists the rotated refresh token
before resolving, reloads the stored token and retries once on
`RENEWAL_CONFLICT`, and waits `Retry-After` (handled inside
`@openkey/core`) on `RENEWAL_TOO_SOON` / `TEMPORARILY_UNAVAILABLE`. Every
renewed delegation passes through `verifyDelegation` before it is
accepted — a verification failure rejects `renew()` as `SERVER` after
persisting the rotated token, which then rides the error as
`rotatedRefreshToken`; if that save fails, the grant is abandoned and the
error carries no token. Terminal errors (`INVALID_GRANT`, `CONSENT_REQUIRED`,
`ACCESS_DENIED`, `SPACE_UNAVAILABLE`) wipe the local session before
rethrowing: the grant is dead, so that's a local sign-out. A terminal
outcome persists nothing — the grant of a rotated refresh token on the
error (for example `hosting: "failed"`) is abandoned instead (see below),
and the error carries no token. If `signIn()` returns a delegation already inside the spec's renewal lead window, it is
renewed before `signIn()` resolves — you always receive a delegation
with a full TTL; if that immediate renew fails non-terminally, the error
is surfaced but the just-issued session stays persisted, so the app can
retry `renew()`. A `signIn()` that fails before its session is persisted
(`ACCESS_DENIED`, `USER_CANCELLED`, `STATE_MISMATCH`, a failed or terminal
code exchange) leaves an existing stored session untouched.
A `signOut()` while a `signIn()` (including its discovery and PAR), a
`renew()` or a code exchange is in flight makes it discard its result and
reject with `NOT_SIGNED_IN` instead of persisting over the wiped session
(the orphaned grant is abandoned, see below).

#### Session storage model

The stored session is identified by its session id (the session public
key, fresh for every sign-in). There is no in-memory copy: every
`renew()` reads the record from `storage` first, and every write or
removal is a compare-and-set, serialized with all other storage access by
every `OpenKeyRN` that uses the same store object (see *Sharing storage*):

- a `signIn()` saves over whatever is stored, unless a `signOut()` has
  started since the `signIn()` did; a `signIn()` started *during* a
  `signOut()` saves after it finishes;
- `renew()`, the immediate renew after sign-in, the rotated-token recovery
  writes and terminal wipes only write or remove the record while it still
  holds *their* session. If another session replaced it, they write nothing,
  abandon their rotated grant, and reject with `NOT_SIGNED_IN` (which
  carries no `rotatedRefreshToken`: the token was abandoned, not handed
  back);
- `signOut()` signs out whatever session is current. It removes the record
  only if it still holds the session and token just revoked. If a different
  session was stored meanwhile (only possible from another `OpenKeyRN`
  sharing the same backend), that session is revoked and removed too. If
  the record can't be read, `signOut()` removes nothing and rejects with
  `STORAGE`.

A `signIn()` that has not yet stored its session (for example one the
user cancels) does not affect an in-flight `renew()`.

**No abandoned live grants.** Every grant the SDK lets go of without
storing it is revoked, and if that revoke fails transiently it goes into
the pending-revoke record (the same bounded entry `signOut()` uses). That
covers the session a `signIn()` replaces (revoked after the new session
is saved), a superseded renew's or sign-in's token, an orphaned code
exchange, a terminal outcome's rotated token, and a token whose
secure-store write failed. The rule for errors: an error carries
`rotatedRefreshToken` only while that token is live and not abandoned —
after a terminal outcome, a refused save or a failed write, it is not on
the error.

The one limit: if the secure store also fails to write the pending-revoke
entry, nothing durable can be recorded. The SDK has then already sent the
revoke (core retries a 503 once), and that best-effort attempt is all it
can do — if it failed transiently, the grant stays live until the user
signs in again or it expires.

#### Sharing storage

Use **one store object per storage backend** — ideally one `OpenKeyRN`
through the `getOpenKeyRN()` singleton. The storage queue that makes
every read-decide-write atomic is shared by all `OpenKeyRN` instances
that use the *same store object*, so several instances (or hot-reloaded
copies) over one store object stay consistent.

`get`/`set`/`remove` are not atomic across *different* store objects, or
across processes (an app extension, a second JS runtime) writing the same
backend. Without help, two writers there can lose each other's updates:
one instance reads the old session, another saves a new sign-in, and the
first then writes over it — so a `signIn()` can silently disappear, or a
rotated token can be overwritten by an older one, and the user has to sign
in again. If your backend can compare-and-set atomically, implement the
optional `compareAndSet(key, expected, next)` on `OpenKeySecureStore`:

```typescript
storage: {
  get, set, remove,
  // Replace the value only if it is still `expected` (null = absent);
  // `next` null removes it. Must be atomic in the backend.
  compareAndSet: (key, expected, next) => myBackend.cas(key, expected, next),
},
```

The SDK then writes only if the value is still the one it read, and
re-checks otherwise, so separate store objects and processes stay safe
too.

Delegation-mode errors are `OpenKeyNativeError` (`code`,
`status`, `retryAfterSeconds`, `rotatedRefreshToken`); plain-mode errors
stay `OpenKeyError`.

### `getOpenKeyRN(config?)`

Singleton helper. Returns an existing instance or creates one with the provided config.

```typescript
import { getOpenKeyRN } from '@openkey/sdk-react-native';

// First call: creates the instance
const openkey = getOpenKeyRN({ host: '...', clientId: '...', ... });

// Later calls: returns the same instance
const openkey = getOpenKeyRN();
```

## Types

### `OpenKeyRNFullConfig`

```typescript
interface OpenKeyRNFullConfig {
  host: string;                // OpenKey server URL
  clientId: string;            // OAuth client ID
  redirectUri: string;         // Deep link redirect URI
  openBrowser: BrowserOpener;  // Function to open URL in system browser
  issuer?: string;             // Expected callback `iss` + discovery issuer (default https://api.openkey.so/api/auth; never derived from host)
  scopes?: string[];           // Requested scopes (default 'openid email keys offline_access')
  resource?: string;           // RFC 8707 resource indicator (not sent by default)
  delegation?: OpenKeyRNDelegationConfig; // TinyCloud delegation mode
  sha256?: SHA256Fn;           // Custom SHA-256 implementation
  timeoutMs?: number;          // Sign-in timeout in ms (default: 300000)
}
```

### `OpenKeyRNAuthTokens`

```typescript
interface OpenKeyRNAuthTokens {
  accessToken: string;                // OAuth access token
  idToken: string;                    // OpenID Connect ID token ('' in delegation mode)
  refreshToken?: string;              // Refresh token (if granted)
  expiresIn: number;                  // Token lifetime in seconds
  delegation?: TinyCloudDelegation;   // Set in delegation mode
}
```

### `BrowserResult`

```typescript
type BrowserResult =
  | { type: 'success'; url: string }
  | { type: 'cancel' | 'dismiss' | 'locked' };
```

### `OpenKeyError`

```typescript
class OpenKeyError extends Error {
  code: OpenKeyErrorCode;
  message: string;
}
```

### PKCE Utilities

Low-level PKCE helpers, exported for advanced use cases:

- `generateCodeVerifier()` -- random code verifier string
- `generateCodeChallenge(verifier, sha256?)` -- S256 code challenge
- `generateState()` -- random state parameter
- `base64UrlEncode(buffer)` -- base64url encoding

## Error Handling

Plain-mode errors are `OpenKeyError` with a typed code:

| Code | Description |
|------|-------------|
| `USER_CANCELLED` | User dismissed/cancelled the browser session |
| `ACCESS_DENIED` | Callback carried `error=access_denied` (user denied consent) |
| `TIMEOUT` | Auth flow timed out (default 5 min) |
| `STATE_MISMATCH` | Callback `state` or `iss` didn't match the request |
| `SERVER` | Callback or endpoint returned a non-`access_denied` OAuth error |
| `NETWORK_ERROR` | Network request failed |
| `UNKNOWN` | Unexpected error |

Delegation-mode protocol errors are `OpenKeyNativeError` (codes in the
[delegation spec](https://github.com/TinyCloudLabs/openkey/blob/main/docs/native-tinycloud-delegation.md): `USER_CANCELLED`, `ACCESS_DENIED`, `STATE_MISMATCH`, `CONSENT_REQUIRED`, `INVALID_GRANT`, `RENEWAL_CONFLICT`, `RENEWAL_TOO_SOON`, `SPACE_UNAVAILABLE`, `TEMPORARILY_UNAVAILABLE`, `NETWORK`, `STORAGE`, `SERVER`, `NOT_SIGNED_IN`, `UNAVAILABLE`). `STORAGE` is a failed read or write of the injected secure store; `NETWORK` is a failed request.

```typescript
import { OpenKeyError } from '@openkey/sdk-react-native';

try {
  const tokens = await openkey.signIn();
} catch (error) {
  if (error instanceof OpenKeyError) {
    switch (error.code) {
      case 'USER_CANCELLED':
        // User closed the browser
        break;
      case 'ACCESS_DENIED':
        // User denied consent
        break;
      case 'TIMEOUT':
        // Flow timed out
        break;
      case 'NETWORK_ERROR':
        // Network issue
        break;
    }
  }
}
```

## Security

- **PKCE** (Proof Key for Code Exchange) prevents authorization code interception
- **System browser** ensures credentials never pass through app code
- **No WebView** -- immune to credential harvesting attacks
- **State + iss** parameters validated on every callback
- **Session proofs** bind every delegation credential to an on-device Ed25519 key
- **Tokens returned to caller** -- the SDK does not store OAuth tokens; your app controls persistence (delegation mode persists only its session record through your `storage`)

## Links

- [OpenKey Website](https://openkey.so)
- [GitHub](https://github.com/TinyCloudLabs/openkey)
- [Browser SDK](https://www.npmjs.com/package/@openkey/sdk)

## License

MIT
