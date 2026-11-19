---
"@openkey/web": patch
---

After a Google or Apple sign-in through the popup, the page that opened it now re-reads its session. Before, the popup signed in inside its own window and the opener kept the signed-out answer it had read earlier, so a first-time Google user on an approval link ("Sign in to review the requested access") stayed on the signed-out card until they reloaded. Done once, in the popup helper (`signInWithSocialPopup`), so the register page, the login page and embedded sign-in all get it. No wording or screen change.
