---
"@openkey/web": minor
---

Settings has a "Delete account" flow at `/dashboard/settings/delete-account` (TC-2721, App Store 5.1.1(v)). It explains what deletion destroys, asks for the typed confirmation `DELETE MY ACCOUNT`, then a fresh step-up on the current session: a passkey for a user with a step-up passkey, else a deletion-purpose email code. It ends on a result screen. A relay address that Apple has stopped forwarding to is told to turn forwarding back on. The Settings entry stays hidden until `GET /api/account` reports `emailUndeliverable` (the deletion step-up, #458). Until the API reports `stepUpPasskeys` (TC-1198), the passkey path says it is unavailable.
