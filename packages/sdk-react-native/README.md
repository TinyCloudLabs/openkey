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
  issuer: 'https://api.openkey.so/api/auth', // Optional: expected `iss` (default `${host}/api/auth`)
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
and a `state` matching the pending request; a mismatch rejects `signIn()`
with `STATE_MISMATCH`. A callback with `error=access_denied` rejects with
`ACCESS_DENIED`, any other `error` with `SERVER`, and `{type: 'cancel' |
'dismiss' | 'locked'}` results reject with `USER_CANCELLED`.

### `openkey.handleCallback(url)`

Handle an incoming deep link redirect. Call this from your app's URL/deep link handler when your opener resolves `void`. Returns `true` if the URL matched a pending sign-in flow, `false` otherwise.

```typescript
const handled: boolean = openkey.handleCallback(incomingUrl);
```

### `openkey.refreshToken(refreshToken)`

Exchange a refresh token for new tokens.

```typescript
const newTokens = await openkey.refreshToken(tokens.refreshToken!);
```

### `openkey.signOut(accessToken?)`

Clear pending sign-in flows, revoke the delegation grant (delegation mode), and revoke `accessToken` through the legacy revoke endpoint when given.

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
best-effort: the in-memory session still works until restart if a write
fails.

`renew()` is single-flight, persists the rotated refresh token before
resolving, reloads the stored token and retries once on
`RENEWAL_CONFLICT`, and waits `Retry-After` (handled inside
`@openkey/core`) on `RENEWAL_TOO_SOON` / `TEMPORARILY_UNAVAILABLE`.

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
  issuer?: string;             // Expected callback `iss` (default `${host}/api/auth`)
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
[delegation spec](https://github.com/TinyCloudLabs/openkey/blob/main/docs/native-tinycloud-delegation.md): `USER_CANCELLED`, `ACCESS_DENIED`, `STATE_MISMATCH`, `CONSENT_REQUIRED`, `INVALID_GRANT`, `RENEWAL_CONFLICT`, `RENEWAL_TOO_SOON`, `SPACE_UNAVAILABLE`, `TEMPORARILY_UNAVAILABLE`, `NETWORK`, `SERVER`, `NOT_SIGNED_IN`, `UNAVAILABLE`).

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
