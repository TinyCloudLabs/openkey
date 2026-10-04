---
"@openkey/api": patch
---

`/api/delegate/authorize-sign` checks context bindings, preview approval, selection, narrowing, regenerated SIWE, and external signatures before atomically consuming its single-use authorization context and preview approval together. Refused requests leave both tokens usable for a corrected retry; of concurrent sign attempts only one can sign, and replays are refused. Managed signing failures after consumption still require a fresh approval.
