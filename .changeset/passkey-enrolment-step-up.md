---
"@openkey/api": minor
"@openkey/web": minor
---

Adding or removing a passkey now needs a fresh step-up on the current session (TC-1198). A session alone gets 403 `PASSKEY_STEP_UP_REQUIRED` from Better Auth's `generate-register-options`, `verify-registration` and `delete-passkey` routes and from the embed proxy, with the accepted `methods` in the body.
- To enrol, the session needs a fresh assertion by a passkey that counts for step-up, a `passkey_register` email code, or its own creation by a verified email code or a confirmed sign-up within five minutes. Email proofs are single use.
- To remove a passkey that counts, the session needs a passkey assertion. To remove one that does not count, a `passkey_remove` email code also works.

Each passkey records how it was enrolled (`enrolledVia`, `enrolledStepUpAt`) and whether it counts for step-up (`countsForStepUp`). A passkey enrolled by email counts only if the user has no passkey that counts. Passkey freshness for account deletion now accepts only a passkey that counts, and each session records which passkey (`lastPasskeyId`) gave it freshness. Users whose only passkeys don't count delete their account with an email code.

Add `POST /api/account/step-up/passkey/{options,verify}`. It verifies an assertion by a passkey that counts and stamps the current cookie session instead of creating a new one. `GET /api/account` returns `user.stepUpPasskeys`.

Settings, sign-in, sign-up and recovery show an email-code or passkey dialog when the API asks for a step-up, then retry. An API without this change never asks, so nothing changes there.

Adds migration `20261110_0002_passkey_enrolment_provenance`. Every existing passkey is marked `legacy` and counts for step-up.
