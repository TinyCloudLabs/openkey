---
"@openkey/api": patch
"@openkey/web": patch
---

Accept explicit decrypt requests for the canonical owner's `default/share/` encryption-key prefix or one exact `default/share/<shareId>` key through delegation create, prepare and signing. Preserve the complete named-key resource and decrypt-only action in the signed ReCap; retain whole-network behavior and existing signing gates. No node or SDK authority semantics change. Details: TC-1424
