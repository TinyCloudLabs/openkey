---
"@openkey/api": patch
---

An approved sign-in through `POST /api/delegate/authorize-sign` sets up the signer's TinyCloud account, as `POST /api/keys/:id/sign` does. A brand-new account that signs in through the versioned sign-in is set up before the signature is returned, so its first space operation works. It uses the same setup, wait limit and Auto-Sign setting. A failed or slow setup never holds back the signature; it is logged and retried in the background.
