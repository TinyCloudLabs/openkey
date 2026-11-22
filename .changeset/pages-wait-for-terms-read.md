---
"@openkey/web": patch
---

A window's page is held behind a loading state until the account's Terms status is read, so the page makes no account call before the read resolves. The connect pop-up loads keys after the account has agreed to the Terms, including after a sign-in made on the pop-up.

Details: TC-3766
