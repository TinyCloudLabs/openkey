# @openkey/sdk-capacitor

Capacitor 8 sign-in for an OpenKey native client with a TinyCloud delegation. The package uses `@openkey/core` for OAuth, PKCE, session proofs, and error mapping. iOS uses `ASWebAuthenticationSession`; Android uses Custom Tabs.

## Register and install

Ask an OpenKey admin to register a **native**, **public** client with token endpoint authentication `none` and enable `tinycloud:delegation` with a capability ceiling and TinyCloud host. Register an exact redirect URI. For Android, use a private-use scheme with a host and `/callback` path, for example `xyz.tinycloud.exo://openkey/callback`. A scheme-only URI is refused. Android private schemes can be claimed by another app; the plugin checks the pending redirect and state before accepting one. HTTPS redirects are supported on iOS 17.4+ with a claimed domain, but this package does not ship an Android App Link filter.

```sh
npm install @openkey/sdk-capacitor @capacitor/core@^8 @tinycloud/web-sdk@^2.11 @tinycloud/sdk-core
npx cap sync
```

For Android, set the plugin's manifest placeholders in the app module's `defaultConfig`:

```gradle
manifestPlaceholders += [openkeyRedirectScheme: 'xyz.tinycloud.exo', openkeyRedirectHost: 'openkey']
```

The plugin activity matches `/callback`. Keep any unrelated OAuth intent filters on the app's main activity. The plugin supports Swift Package Manager, including Capacitor's `ios/App/CapApp-SPM` layout. Run `cap sync ios` after installing it.

For an iOS HTTPS redirect, associate the domain with the app using `webcredentials:`. Apple's callback matcher requires iOS 17.4 or later; earlier versions return `UNAVAILABLE`.

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

// Keep this instance at module scope and reuse it for sign-in, renewal, and sign-out.

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

The app should compare `delegation.tinycloudHost` with its configured node, then verify its backend session before exposing data. `current()` reads the stored OpenKey session offline. To restore TinyCloud after an app restart, call `storage.load(address)` once so its synchronous `exists()` and `activeAddress()` cache is populated, then call `tcw.restoreSession(address)`. The adapter accepts saves only for the current OpenKey session key; a delayed handoff from before sign-out or a new sign-in fails.

Multiple `OpenKeyNative` instances using the same Capacitor plugin and client share one storage queue and session epoch. If an app injects distinct plugin wrappers over one secure-store backend, pass the same `storageIdentity` object to each constructor. Use one identity object per backend; the queue coordinates instances within one JS process.

## Renew and sign out

```ts
const renewed = await openkey.renew({ siweNonce: freshBackendNonce });
await handoff(renewed); // save, activate, then swap on the live TinyCloudWeb instance
await openkey.signOut();
```

`renew()` is single-flight for equivalent normalized permissions and the same SIWE nonce; different options run in order. A capability subset applies to that renewal only; a later plain `renew()` uses the original approved set. It saves a rotated refresh token before returning. On `renewal_conflict` it reloads secure storage and retries once if another call stored a newer token. Terminal renew errors clear the local session without persisting a rotated token; the SDK tries to revoke that grant. OpenKey's `Retry-After` handling for 429 and 503 lives in core. If immediate renewal after exchange fails, `signIn()` rejects and clears the initial session so `current()` cannot restore a sign-in reported as failed.

`signOut()` hides the session immediately, revokes the TinyCloud grant, and clears OpenKey and TinyCloud session storage. It rechecks the stored session before removal and revokes a replacement if one arrived during the prior revoke. If secure storage cannot be read, sign-out rejects with `STORAGE` and leaves the unread session in place; it becomes usable again when storage recovers. A readable but corrupt record can be removed. Renew and sign-in writes also check the stored session identity before replacing it. A terminal revoke failure still resolves. Network failures, temporary unavailability, HTTP 5xx, and HTTP 429 reject with a typed error and retain the session key and refresh token in a separate encrypted pending-revoke record. The SDK retries that record at initialization, before sign-in, and on the next sign-out. Each record stores an attempt count and expiry; it is deleted after success, a terminal response, 20 failed attempts, or refresh-token expiry (issue or rotation time plus seven days, capped at five minutes after `renewableUntil`). The SDK also tries to revoke grants abandoned by a replacement sign-in, a superseded renewal, an orphaned exchange, or a terminal renewal; transient failures for these go into the pending-revoke record. Corrupt pending-revoke records are removed. `current()` and the TinyCloud storage adapter return no signed-out session while a revoke is pending. A failed new sign-in attempt does not remove an existing session or interrupt its renewal. `NOT_SIGNED_IN` refusals omit a token once the grant has been abandoned. Catch `OpenKeyNativeError` and use its `code` (`USER_CANCELLED`, `ACCESS_DENIED`, `STATE_MISMATCH`, `STORAGE`, etc.); never log the raw error object because it can carry `rotatedRefreshToken`.

Before exchanging a code, the SDK stores an exchange intent containing its session key. It stores the returned refresh token on that intent before validating the delegation. On startup, an unfinished intent with a token is revoked or moved to pending revoke; one without a token is dropped. A committed session clears its matching intent without revocation. As with any client-only journal, a process kill between receipt of the HTTP response and the secure-store write of its token cannot be recovered without a server lookup by the session key.

## Security

The session private JWK and refresh token are stored in iOS Keychain generic passwords with `AfterFirstUnlockThisDeviceOnly` and iCloud synchronization disabled. Android stores AES-GCM ciphertext in the `openkey_secure_store` SharedPreferences file with a non-exportable Android Keystore key. Android apps with backup enabled must exclude `sharedpref/openkey_secure_store.xml` from both legacy `fullBackupContent` and Android 12+ `dataExtractionRules` for cloud backup and device transfer, or disable backup for the app. In each backup rules file use `<exclude domain="sharedpref" path="openkey_secure_store.xml" />` (under both `<cloud-backup>` and `<device-transfer>` for `dataExtractionRules`). A restored ciphertext cannot be decrypted with a different device's key. The JWK is necessarily present in JS memory while TinyCloud WASM signs requests. `NativeSessionStorage` never uses localStorage. A device or JS runtime compromise can still expose an active session. Native access tokens are not refreshed; renewal rotates only the TinyCloud delegation refresh token. A lost renew response can require a new sign-in.
