---
"@openkey/web": patch
---

In a v1 embed (an SDK that sends no layout-ready message, such as `@openkey/sdk` 0.12), Approve is no longer enabled while the SDK modal is still animating the frame's height. The SDK opens the frame at 400px and transitions it to its content height over 200 ms inside a centred card, so Approve moved under the click (a 184px change moves it 92px). Approve now waits until the frame's own size has been unchanged for 300 ms, and never longer than 1.5 s from the first display or from each new resize. v2 embeds and the popup are unchanged. No wording or screen change.
