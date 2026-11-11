---
"@openkey/web": patch
---

Target legacy Sign replies to the requesting window's browser origin. Ignore opaque request origins. Wildcard bootstrap now needs an HTTP(S) ancestor or referrer origin: custom wildcard popups after a sign-in redirect, and no-referrer embeds without ancestor metadata, may not receive ready. SDK callers pass a concrete origin and retain their existing bootstrap.
