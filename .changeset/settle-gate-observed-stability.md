---
"@openkey/web": patch
---

In a v1 embed, Approve waits for the frame size and the button to settle, up to the existing time limit. A resize after Approve is enabled starts the check again.

Details: TC-3185
