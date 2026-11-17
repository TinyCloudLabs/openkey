---
"@openkey/api": patch
---

The refusal of decrypt or key.create outside `apps/` from a site that is not first-party (TC-2247) now has its own sentence, "This site isn't allowed to request that access.", instead of "This website doesn't list the key this app asked for, so OpenKey didn't approve it." (which was about `apps/` key listings and told the owner nothing here). The response code is unchanged (403 `app_key_grant_refused`); internally the refusal has its own reason, `encryption_outside_apps`.
