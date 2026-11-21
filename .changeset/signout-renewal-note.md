---
"@openkey/api": patch
"@openkey/web": patch
---

OpenKey's sign-out says that other apps keep renewing. In an app, it reads: "Signing out ends this app’s sign-in and its renewal. Other apps you allowed to stay signed in keep renewing. To stop them, choose Stop renewal under Renewing permissions in OpenKey settings." On the dashboard it reads: "Apps you allowed to stay signed in keep renewing after you sign out." It shows only when a renewal survives that sign-out. The list of renewing permissions (`GET /api/account/renewal-leases`) tells each lease apart with a new `endsOnSignOut` field.
