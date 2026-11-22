---
"@openkey/api": minor
"@openkey/web": minor
---

One secret's own key (TC-3800). A delegation may name `urn:tinycloud:encryption:<owner>:default/secrets/<name>` or `…:default/secrets/scoped/<scope>/<name>` for `tinycloud.encryption/decrypt` and `tinycloud.encryption/key.create`, in the signer's own account only: the owner must be the signer's canonical (EIP-55) address and every path part must match `[a-z0-9][a-z0-9._-]{0,63}`. Another path under `default/secrets/` is refused with "permissions[i].path names an invalid secret key; it must be default/secrets/<name> or default/secrets/scoped/<scope>/<name>, each part matching [a-z0-9][a-z0-9._-]{0,63}". `key.create` stays refused everywhere else. `/device` still refuses secrets.

The review names the secret: "Read the secret NAME" (from the KV path the request pairs with the key, otherwise the key's own name), and "Create a key for the new secret NAME." with "It can't read any of your secrets." under it. A request that can open every secret gets the all-secrets card: "Let {site} read and add all your secrets?", "Let {site} read all your secrets?" or "Let {site} open all your encrypted data?", with "this app" and "OpenKey can't confirm which site asked." where no site is verified. On the warning screen it replaces the whole-network card; on a link or the command line it sits above the summary.

A signed approval request (`/a/…`) may be lengthened past its suggested start up to the lifetime its requester signed, unless it can open all secrets or all encrypted data (that start stays the most). A request that decrypts secrets (a secret's own key, a prefix under `secrets/`, or a whole network) lasts 7 days at most, whatever it signed: the page offers no more and the API refuses a longer expiry. A request for a secret's own key says "This request starts at {start}, as the app asked. You can choose up to {max}." or, when it starts at its maximum, "This request lasts {max}, as the app asked. That's the most it can be."
