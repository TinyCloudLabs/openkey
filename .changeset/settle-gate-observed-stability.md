---
"@openkey/web": patch
---

In a v1 embed, Approve is now enabled only after the frame size and the Approve button have been observed unchanged for several animation frames, and a resize after it is enabled disables it again, so a slow host no longer leaves Approve enabled while the button is still moving.
