---
"@openkey/api": patch
"@openkey/web": patch
---

Accept explicit decrypt requests for one canonical owner `default/share/<shareId>` encryption key through delegation create, prepare and signing. Preserve the exact named-key resource in the signed ReCap and retain existing whole-network behavior. No node or SDK authority semantics change. Details: TC-1424
