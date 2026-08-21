---
"@openkey/sdk": patch
---

Capture and verify the previous Better Auth session without refreshing it
before reporting a successful OpenKey sign-out, and cancel every concurrent
widget flow so stale authentication responses cannot restore signed-out SDK
state.
