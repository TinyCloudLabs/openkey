---
"@openkey/web": patch
---

The sign-in page for a device request never relays an encryption grant: a device approval that includes `tinycloud.encryption` is refused.

Details: TC-3703
