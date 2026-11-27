---
"@openkey/sdk": patch
---

An embedded flow opens a popup by itself only when the page reports that its Content Security Policy blocked the OpenKey frame, and then it does so at once.

- A frame that stays silent is now treated like a slow one, with no popup at 3 seconds. After 15 seconds the card offers "Open in a new window", and the user chooses. A block the page does not report, such as one from a browser extension, now waits 15 seconds and needs that click.
- Once a flow on an `OpenKey` instance runs in a popup (a fallback, the user's choice, or `mode: 'popup'`), later `'iframe'` flows on that instance open a popup directly, inside the app's call. An app session therefore never mixes the frame's and the popup's OpenKey sessions. `setupAccount()` does not switch the instance. A page reload starts embedded again.

Details: TC-4438
