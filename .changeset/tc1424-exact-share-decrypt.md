---
"@openkey/api": patch
---

Accept explicit decrypt for the canonical owner's exact `default/share/<shareId>` named key. Keep owner `share/` prefixes on every valid network; refuse noncanonical owner bytes and network names longer than 64 characters only for named resources, preserving existing bare-network behavior. Preserve the exact resource and decrypt-only action in prepared and signed ReCaps. No node or SDK authority semantics change. Details: TC-1424
