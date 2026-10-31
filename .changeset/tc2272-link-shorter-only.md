---
"@openkey/api": patch
"@openkey/web": patch
---

A `/delegate` link is shorter-only: the time a user picks on the approval screen can be at most the link's own `expiry` (after the 30-day link clamp), and the API refuses a longer one (`expiry_exceeds_link`), because a CLI that built the link refuses a longer delegation and saves nothing (OPENKEY_EXPIRY_EXCEEDED). A link that carries `expiryChangeable=true` keeps the uncapped pick, for CLIs that accept a changed expiry. Signed CLI approval requests and device approvals are unchanged (shorter only, bounded by their own windows). Details: TC-2272
