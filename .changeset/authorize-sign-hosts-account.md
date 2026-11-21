---
"@openkey/api": patch
---

An approved sign-in through `POST /api/delegate/authorize-sign` sets up the signer's TinyCloud account, as `POST /api/keys/:id/sign` does (TC-3633). A brand-new account that signs in through the versioned sign-in is hosted before the signature is returned, so its first space operation works. It uses the same setup, the same wait limit and the same Auto-Sign and kill-switch rules. A failed or slow setup never withholds the signature; it is logged and retried in the background.
