---
"@openkey/api": minor
---

Add disabled-by-default Sign in with Apple server support. Apple identities use signed, verified email claims and `(apple, sub)` rather than unsigned callback email; new accounts need confirmation and existing users need email-code step-up to link. Native ID-token sign-in stays disabled. Apple refresh tokens are encrypted with the issuing client ID, and confirmed social accounts get a mailbox notice and first email-code sign-in review.
