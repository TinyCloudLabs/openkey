---
"@openkey/api": patch
---

An Apple reviewer's refresh token ends on the source session's deadline second even when the clock ticks into the next second during the native code exchange. The refresh lifetime and the access lifetime are taken from the same second, so a native renew in the last second of the source session succeeds.

Details: TC-3828
