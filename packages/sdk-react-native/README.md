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
  openBrowser: (url) =>
    WebBrowser.openAuthSessionAsync(url, 'myapp://auth/callback').then(() => {}),
});

// Start sign-in (opens system browser)
const tokens = await openkey.signIn();
console.log(tokens.accessToken);

// Handle deep link callback (in your deep link handler)
openkey.handleCallback(incomingUrl);

// Refresh tokens
const newTokens = await openkey.refreshToken(tokens.refreshToken!);

// Sign out
await openkey.signOut(tokens.accessToken);
```

## Deep Link Setup

Your app must be configured to receive the redirect URI as a deep link.

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
  openBrowser: (url) => ...,        // Required: opens URL in system browser
  sha256: (input) => ...,           // Optional: custom SHA-256 for PKCE
  timeoutMs: 300_000,               // Optional: sign-in timeout (default 5 min)
});
```

### `openkey.signIn()`

Start the OAuth 2.0 Authorization Code + PKCE flow. Opens the system browser and returns a promise that resolves when `handleCallback()` receives the redirect.

```typescript
const tokens: AuthTokens = await openkey.signIn();
```

### `openkey.handleCallback(url)`

Handle an incoming deep link redirect. Call this from your app's URL/deep link handler. Returns `true` if the URL matched a pending sign-in flow, `false` otherwise.

```typescript
const handled: boolean = openkey.handleCallback(incomingUrl);
```

### `openkey.refreshToken(refreshToken)`

Exchange a refresh token for new tokens.

```typescript
const newTokens: AuthTokens = await openkey.refreshToken(tokens.refreshToken!);
```

### `openkey.signOut(accessToken)`

Revoke an access token and clear all pending sign-in flows.

```typescript
await openkey.signOut(tokens.accessToken);
```

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
  host: string;              // OpenKey server URL
  clientId: string;          // OAuth client ID
  redirectUri: string;       // Deep link redirect URI
  openBrowser: BrowserOpener; // Function to open URL in system browser
  sha256?: SHA256Fn;         // Custom SHA-256 implementation
  timeoutMs?: number;        // Sign-in timeout in ms (default: 300000)
}
```

### `AuthTokens`

```typescript
interface AuthTokens {
  accessToken: string;       // OAuth access token
  idToken: string;           // OpenID Connect ID token
  refreshToken?: string;     // Refresh token (if granted)
  expiresIn: number;         // Token lifetime in seconds
}
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

All errors are thrown as `OpenKeyError` with a typed error code:

| Code | Description |
|------|-------------|
| `USER_CANCELLED` | User dismissed the browser |
| `TIMEOUT` | Auth flow timed out (default 5 min) |
| `STATE_MISMATCH` | CSRF state validation failed |
| `NETWORK_ERROR` | Network request failed |
| `UNKNOWN` | Unexpected error |

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
- **State parameter** prevents CSRF attacks
- **Tokens returned to caller** -- the SDK does not store tokens; your app controls persistence

## Links

- [OpenKey Website](https://openkey.so)
- [GitHub](https://github.com/TinyCloudLabs/openkey)
- [Browser SDK](https://www.npmjs.com/package/@openkey/sdk)

## License

MIT
