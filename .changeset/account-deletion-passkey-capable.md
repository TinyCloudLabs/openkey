---
"@openkey/web": patch
---

Account deletion says when a passkey can't confirm the deletion (`passkey_not_step_up_capable`, TC-1198) instead of offering a retry that would fail the same way.
