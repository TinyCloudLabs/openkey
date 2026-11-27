---
"@openkey/sdk": minor
---

`setupAccount()` opens OpenKey's account setup page, where the owner sets their TinyCloud account up on TinyCloud hosting with one approval. It resolves with `{ outcome: 'published' | 'present' }` and rejects with `USER_CANCELLED`, `POPUP_BLOCKED`, `ACCOUNT_SETUP_FAILED` or `ACCOUNT_SETUP_UNAVAILABLE` (with `setupUrl`). A sign request refused after the owner set the account up from the sign widget's "Finish setup" card rejects with `ACCOUNT_SETUP_COMPLETED`: the app repeats its request without hosting the account's spaces.

Details: TC-4344
