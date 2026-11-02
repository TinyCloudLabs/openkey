---
"@openkey/api": patch
---

The SIWE origin guard (TC-1486) accepts Exo's macOS app. Tauri serves Exo at the fixed custom-scheme origin `tauri://localhost`, which URL parsing treats as an opaque `null` origin, so every sign-in from the macOS app was refused with `invalid-origin`. That exact origin is now checked as host `localhost`: the message must name the domain `localhost` and a `did:`/`ucan:` URI. Other domains, web URIs, other custom schemes and look-alike spellings are still refused. Windows (`http://tauri.localhost`) already passed.
