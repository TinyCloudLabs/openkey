---
"@openkey/web": patch
---

When the server refuses a sign-in for good (a 400 or 403 with `app_key_grant_refused`, `key_delete_not_grantable` or `invalid_siwe_recap`), the sign page now tells the app: its request is rejected with the server's words (error code `UNKNOWN`, same shape as the SIWE-origin refusal), the page keeps those words on screen in place of Approve, and Approve is off, because retrying the same request cannot succeed. Before, the page only showed the text locally and the app's request stayed pending until its own timeout. A network or server error is not a refusal: it still shows the error and leaves Approve available. Covers both the popup (`/widget/sign`) and the embedded (`/widget/embed/sign`) page.
