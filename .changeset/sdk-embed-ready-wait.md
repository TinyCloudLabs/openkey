---
"@openkey/sdk": patch
---

An embedded flow no longer opens a popup just because the OpenKey frame is slow. When the frame reports that its page is loading (`openkey:loading`), the SDK waits up to 15 seconds from opening it for `openkey:ready`, instead of 3. A frame that sends nothing in 3 seconds still falls back to a popup. The console warning now gives the real cause: a Content Security Policy violation the page reported for the frame, a frame that started loading but was not ready in 15 seconds, or no message at all in 3 seconds.

Details: TC-4438
