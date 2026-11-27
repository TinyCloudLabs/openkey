---
"@openkey/sdk": patch
---

An embedded flow no longer opens a popup just because the OpenKey frame is slow. The popup holds a different OpenKey session than the frame, so switching made people sign in twice, and a sign-out there left the frame signed in.

- A frame that sends nothing within 3 seconds, on an instance where no frame has loaded before, is taken as blocked. The flow falls back to a popup as before.
- Once a frame has reported that its page is loading (`openkey:loading`), or an earlier flow on the same `OpenKey` instance ran embedded, the SDK never opens a popup by itself. If the frame is not ready after 15 seconds, the card shows "Open in a new window" with the line "You may need to sign in again there." A popup opens only when the user clicks it. Until then the card waits for ready, for the user to close it, or for the 5-minute `TIMEOUT`. An app WebView, which cannot open a popup, gets no offer.
- The console warning gives the real cause: a Content Security Policy violation the page reported for the frame, a frame that started loading but was not ready, or no message at all.

Details: TC-4438
