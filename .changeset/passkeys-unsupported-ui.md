---
"@openkey/web": patch
---

When a client opens OpenKey with `passkeys=false`, the sign-in screens (embedded and popup connect, sign, sign-typed-data and Nostr widgets, and the email login page they link to) hide the passkey sign-in button, skip the "create a passkey" prompt after email sign-in, and replace the passkey-based Register and Recover links with a note that email sign-in creates and recovers accounts. Email and Google sign-in are unchanged. Without the parameter nothing changes.
