---
"@openkey/api": patch
"@openkey/db": patch
---

`POST /api/account/terms/accept` accepts the embedded frame’s session token from the OpenKey origin. It records surface `embed` only for a session created by a sign-in in the last 10 minutes and answers 403 `terms_step_up` for an older session or a reviewer session. A token request that names a surface or client is refused with 400. Each embed acceptance keeps its session id, the proof (`session_created`) and its time, the request origin and the embedding origin the frame reports. The migration adds these five nullable columns to `terms_acceptance` and nothing else.

Details: TC-3766
