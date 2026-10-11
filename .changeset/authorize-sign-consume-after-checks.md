---
"@openkey/api": patch
---

`/api/delegate/authorize-sign` checks context bindings, preview approval, selection, narrowing, regenerated SIWE, and external signatures before atomically consuming its single-use authorization context and preview approval together. Refused requests leave both tokens usable for a corrected retry; of concurrent sign attempts only one can sign, and replays are refused. Managed signing failures after consumption still require a fresh approval.

An empty selection with required capabilities still returns `required-action-missing`, and unknown action IDs still return `action-not-in-baseline`; the remaining precedence change is that an empty selection without required capabilities returns `empty_selection` before preview-approval validation.
Expired authorization contexts now return `context-expired` instead of `context-not-found`, and expired preview approvals return `preview-approval-expired` instead of `preview-approval-not-found` on checked routes; a context expiring between check and consume remains stored until the next prune but cannot sign.
