---
"@openkey/api": patch
---

Native delegation approval no longer trusts a cached bootstrap `complete` row over the node. When the node's activation lists the applications space as not hosted and no hosting plan was shown, approval marks the cached row not-complete, reopens the request and answers 409 `preparation_superseded`. The consent page prepares again, and that prepare shows the hosting plan.

Details: TC-2616
