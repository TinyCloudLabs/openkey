---
"@openkey/web": patch
"@openkey/api": patch
---

The native-app consent page no longer labels every app "Unverified app". OpenKey has no app-verification process, so the label was a fixed placeholder; the page shows the app's name, icon and organization. The consent preview no longer carries a hardcoded `client.verified: false`.
