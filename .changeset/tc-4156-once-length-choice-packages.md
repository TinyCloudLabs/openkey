---
"@openkey/sdk": patch
"@openkey/capability-review": patch
---

An approval for access that can open all your secrets or all your encrypted data starts at 1 hour. Under "How long" the owner picks "1 hour" or the length the app asked for, for example "7 days (what the app asked)". When the server limits the length, that option reads "7 days (the longest allowed)". The longer length applies only once the owner picks it, and the length shown is the length signed. A request for 1 hour or less shows no choice. A line under the choice says what the access can open: "This access can open all your encrypted data.", "This access can open all your secrets." or "This access can open a wide range of your data." The choice appears on the sign-in popup, the embedded sign-in and the approval link page. Removing the broad access and adding it back sets the length to 1 hour. `@openkey/capability-review` exports `grantOnceReach` and the `OnceReach` type. `@openkey/sdk` drops the `APPROVAL_EXPIRY.onceStart` string.

Details: TC-4156
