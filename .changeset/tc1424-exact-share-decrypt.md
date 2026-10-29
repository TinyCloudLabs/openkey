---
"@openkey/api": patch
"@openkey/capability-review": patch
---

Accept explicit decrypt requests for one canonical owner `default/share/<shareId>` encryption key through delegation create, prepare and signing. Preserve the exact named-key resource in the signed ReCap and retain existing whole-network behavior. The approval line for this exact-share request is "Open this shared file". No node or SDK authority semantics change. Details: TC-1424
