# @openkey/sdk-capacitor

Capacitor 8 sign-in for an OpenKey native client with a TinyCloud delegation. The package uses `@openkey/core` for OAuth, PKCE, session proofs, and error mapping. iOS uses `ASWebAuthenticationSession`; Android uses Custom Tabs.

## Register and install

Ask an OpenKey admin to register a **native**, **public** client with token endpoint authentication `none` and enable `tinycloud:delegation` with a capability ceiling and TinyCloud host. Register an exact redirect URI. A private-use redirect needs a host and path, for example `xyz.tinycloud.exo://openkey/callback`; an HTTPS claimed redirect is also supported. A scheme-only URI is refused. Android private schemes can be claimed by another app, so use a claimed HTTPS redirect for production when available.

```sh
npm install @openkey/sdk-capacitor @capacitor/core@^8 @tinycloud/web-sdk@^2.11 @tinycloud/sdk-core
npx cap sync
```

For Android, set the plugin's manifest placeholders in the app module's `defaultConfig`:

```gradle
manifestPlaceholders += [openkeyRedirectScheme: 'xyz.tinycloud.exo', openkeyRedirectHost: 'openkey']
```

The plugin activity matches `/callback`. Keep any unrelated OAuth intent filters on the app's main activity. The plugin supports Swift Package Manager, including Capacitor's `ios/App/CapApp-SPM` layout. Run `cap sync ios` after installing it.

For an HTTPS redirect, set Android's placeholders to `https` and the claimed host, configure Android Digital Asset Links, and associate the same domain with the iOS app using `webcredentials:`. HTTPS callbacks use Apple's callback matcher and require iOS 17.4 or later; earlier iOS versions return `UNAVAILABLE` for that redirect.

## Sign in and hand off to TinyCloud

```ts
import { OpenKeyNative } from '@openkey/sdk-capacitor';
import { activateSessionWithHost } from '@tinycloud/sdk-core';
import { TinyCloudWeb } from '@tinycloud/web-sdk';

const openkey = new OpenKeyNative({
  clientId: 'exo-native',
  redirectUri: 'xyz.tinycloud.exo://openkey/callback',
  issuer: 'https://api.openkey.so/api/auth',
  tinycloudHost: 'https://tee.node.tinycloud.xyz',
  ephemeralSession: true,
});

const session = await openkey.signIn({
  capabilities: [
    { service: 'tinycloud.kv', space: 'applications', path: 'xyz.tinycloud.tinychat/threads/', actions: ['tinycloud.kv/get', 'tinycloud.kv/put'] },
  ],
  siweNonce: backendNonce,
});

const storage = openkey.sessionStorageAdapter();
const address = session.delegation.address!;
const chainId = session.delegation.chainId!;
const provider = {
  request: async ({ method }: { method: string }) => {
    if (method === 'eth_accounts' || method === 'eth_requestAccounts') return [address];
    if (method === 'eth_chainId') return `0x${chainId.toString(16)}`;
    throw new Error('Wallet signing is unavailable in a delegated session');
  },
};
const tcw = new TinyCloudWeb({
  provider, sessionStorage: storage,
  tinycloudHosts: [session.delegation.tinycloudHost],
  autoDiscoverLocalNode: false,
});

async function handoff(next: typeof session) {
  const { delegation, sessionKey } = next;
  await storage.save(delegation.address!, {
    address: delegation.address!, chainId: delegation.chainId!,
    sessionKey: JSON.stringify(sessionKey.privateJwk),
    siwe: delegation.siwe!, signature: delegation.signature!,
    tinycloudSession: {
      delegationHeader: delegation.delegationHeader!,
      delegationCid: delegation.delegationCid!,
      spaceId: delegation.spaceId!,
      verificationMethod: delegation.verificationMethod,
    },
    expiresAt: new Date(delegation.expiresAt).toISOString(),
    createdAt: new Date().toISOString(), version: '1',
    tinycloudHosts: [delegation.tinycloudHost],
  });
  const activation = await activateSessionWithHost(delegation.tinycloudHost, delegation.delegationHeader!);
  if (!activation.activated?.includes(delegation.spaceId!)) throw new Error('Space activation failed');
  const restored = await tcw.restoreSession(delegation.address);
  if (restored.status !== 'restored') throw new Error('TinyCloud restore failed');
}
await handoff(session);
```

The app should compare `delegation.tinycloudHost` with its configured node, then verify its backend session before exposing data. `current()` reads the stored OpenKey session offline. To restore TinyCloud after an app restart, call `storage.load(address)` once so its synchronous `exists()` and `activeAddress()` cache is populated, then call `tcw.restoreSession(address)`.

## Renew and sign out

```ts
const renewed = await openkey.renew({ siweNonce: freshBackendNonce });
await handoff(renewed); // save, activate, then swap on the live TinyCloudWeb instance
await openkey.signOut();
```

`renew()` is single-flight and saves a rotated refresh token before returning. On `renewal_conflict` it reloads secure storage and retries once if another call stored a newer token. OpenKey's `Retry-After` handling for 429 and 503 lives in core. `signOut()` calls the TinyCloud revoke endpoint and removes local state even if revoke fails. Catch `OpenKeyNativeError` and use its `code` (`USER_CANCELLED`, `ACCESS_DENIED`, `STATE_MISMATCH`, etc.); do not log the raw error object because it can carry `rotatedRefreshToken`.

## Security

The session private JWK and refresh token are stored in iOS Keychain generic passwords with `AfterFirstUnlockThisDeviceOnly` and iCloud synchronization disabled. Android stores AES-GCM ciphertext in SharedPreferences with a non-exportable Android Keystore key. The JWK is necessarily present in JS memory while TinyCloud WASM signs requests. `NativeSessionStorage` never uses localStorage. A device or JS runtime compromise can still expose an active session. Native access tokens are not refreshed; renewal rotates only the TinyCloud delegation refresh token. A lost renew response can require a new sign-in.
