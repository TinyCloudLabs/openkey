---
"@openkey/web": patch
---

The popup and iframe prepare the current permission selection in the background. One Approve action uses its current, unexpired preview token; edits and expiry fetch a new preview while leaving the selection editable. Raw signing text stays in Advanced details, and the existing API token, exact-byte checks and external-wallet handoff are unchanged.

The pending action reads Getting ready..., then Approve. After a recoverable preview or signing error, the owner can choose Try again to request a new preview; retries do not repeat automatically. Preview metadata errors use plain check messages.

Details: TC-2198
