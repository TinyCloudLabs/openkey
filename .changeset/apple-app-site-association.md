---
"@openkey/web": patch
---

openkey.so serves `/.well-known/apple-app-site-association` as `application/json` with a `webcredentials` entry for TinyCloud Home (`R4QVKA785H.xyz.tinycloud.home`). An iOS build that adds the `webcredentials:openkey.so` associated domain can then use openkey.so passkeys and HTTPS sign-in callbacks; until then it has no effect (TC-1188, TC-520).
