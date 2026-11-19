---
"@openkey/api": minor
---

An account that has not accepted the current Terms can read what the ways out need (TC-3232): `GET /api/account`, `GET /api/account/tinycloud-apps` and `GET /api/account/renewal-leases` no longer answer `terms_required`. They are own-account reads; disconnecting apps, stopping renewals and deleting the account were already open before acceptance.
