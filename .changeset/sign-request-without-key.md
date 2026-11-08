---
"@openkey/web": patch
"@openkey/sdk": patch
---

A sign request that names no key (the app did not call `connect()` first, or passed no `keyId`) no longer ends on "Please connect first to sign messages." with only Cancel. After the owner signs in, in the iframe or the popup, OpenKey uses the account's only key that can sign the request, or offers the account's keys to choose from when several can. When none can, it says so and offers Sign out, to switch to the right account. A SIWE fits only the key whose address it names. Archived keys and linked wallets are never picked. The owner still reviews and approves the exact message on the same screen as for a named key. A named key or key list that cannot be loaded offers Try again. Cancelling when no key can sign rejects `signMessage()` with the `NO_KEY` error code instead of `USER_CANCELLED`.

Details: TC-2281
