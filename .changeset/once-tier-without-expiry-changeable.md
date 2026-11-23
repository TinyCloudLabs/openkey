---
"@openkey/api": patch
"@openkey/web": patch
---

A sign-in in the one-hour tier offers the expiry control regardless of `expiryChangeable`. The tier covers whole-network decrypt, broad encryption prefixes, whole-vault reads and unparseable secret or encryption permissions.

A one-time approval defaults to one hour when the app asks for longer and the owner supplies no expiry. An owner pick is capped at seven days for every request in the tier. A chosen renewal uses the app's window when the owner supplies no expiry. Grants outside the tier follow their existing lifetime rules.

Details: TC-3966
