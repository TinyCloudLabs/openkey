---
"@openkey/web": patch
---

The signing-key refusal in the iframe and popup now offers a way on besides Back to app. When no key of the signed-in account fits the request, Sign out is the main action: the next account signs in and the same request continues. When the key or key list could not be read, Try again reads it again. Back to app after a failed read now tells the app `USER_CANCELLED` instead of `NO_KEY`, so the app keeps its connection; a key the account lacks still answers `NO_KEY`. A SIWE-shaped message whose signer address cannot be read fits no key. The leftover "Please connect first to sign messages." screen is replaced by a loading state with Cancel. In the popup, a key read with one session is never used after another session takes over, and Sign out finishes before key selection restarts.

Details: TC-2281
