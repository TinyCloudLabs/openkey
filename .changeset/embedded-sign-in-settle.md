---
"@openkey/web": patch
---

The embedded sign-in shows its choices once the provider list is known, or after one second. When the list arrives in that time the Google and Apple rows are part of the first paint, so Passkey does not move under a tap. A list that arrives after one second adds its rows when it arrives.

Details: TC-4235
