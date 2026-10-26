---
"@openkey/api": patch
---

Cap web sign-in sessions at 30 days from sign-in. A session that is used regularly still renews for 7 days at a time, but no renewal moves its expiry past 30 days after the sign-in that created it. Details: TC-2101
