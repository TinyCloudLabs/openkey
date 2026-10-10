# @openkey/sdk-capacitor

## 0.1.0-beta.2

### Patch Changes

- 4751443: Accept `@tinycloud/web-sdk` 3.x: the peer range is now `^2.11.0 || ^3.1.0`. The package is built and tested against web-sdk 3.1.0; the shipped code is unchanged and 2.11 apps keep working.

## 0.1.0-beta.1

### Patch Changes

- cf7073f: Fix the Android build in host apps that already have the Kotlin Gradle plugin on their buildscript classpath: the plugin now uses the host's `kotlin_version` (default 2.1.0 when the host sets none) instead of requesting `org.jetbrains.kotlin.android` 2.1.0 itself, which failed with "plugin is already on the classpath with an unknown version".

## 0.1.0-beta.0

### Minor Changes

- 5b993e2: Add the Capacitor 8 native sign-in SDK with iOS and Android secure storage, TinyCloud delegation verification, renewal, revocation, and a secure TinyCloud session storage adapter. First release starts at 0.1.0.

  Transient revoke failures leave a secure pending-revoke entry with the key, token, attempt count, and expiry for bounded automatic retry. Network failures, temporary unavailability, HTTP 5xx, and 429 remain retryable; other errors settle the entry. Failed discovery is retried on the next call. Terminal renewal outcomes clear the session and best-effort revoke rotated grants; failed new sign-in attempts preserve an existing session and its in-flight renewal. Equivalent normalized permission subsets share one renewal flight.

  Queued session writes and sign-out removal now compare the stored session identity before changing it. Sign-out revokes a replacement session that arrives during an earlier revoke. Corrupt pending-revoke records are cleared, and retry expiry uses refresh-token issue or rotation time plus seven days, capped at `renewableUntil` plus five minutes.

  A secure-store read failure during sign-out leaves the unread session in place and rejects, so it can be used when storage recovers. Abandoned grants from replacement sign-ins, superseded renewals, orphaned exchanges, and terminal renewals are revoked best-effort; transient failures are retained for pending-revoke retry.

  Instances sharing a native store now share their queue and epoch by store identity and client key prefix. Exchange intents record issued tokens before delegation validation so startup can revoke grants left by an interrupted sign-in. Secure-store read, write, and remove failures use the distinct `STORAGE` code. Failed renew writes abandon the rotated grant and return `STORAGE` without a token; every error drops `rotatedRefreshToken` once that grant is revoked or pending.
