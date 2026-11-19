---
"@openkey/api": minor
"@openkey/db": minor
"@openkey/web": minor
---

Accounts choose when an approval asks for a passkey: every approval, only sensitive access (the default), or never (TC-3442). `User.passkeyApprovalMode` (`ALWAYS`, `SENSITIVE`, `NEVER`; additive migration, default `SENSITIVE`) applies only while the account has a passkey that counts for step-up. `GET /api/account/passkey-approval` returns the stored and effective mode; `PATCH` changes it, and a change to fewer prompts needs a passkey assertion for the new mode from `POST /api/account/passkey-approval/options`. Settings shows the three choices. The service that issues and checks approval passkey challenges, bound to one request, single use and valid five minutes, is added for the signing routes; none of them uses it yet.
