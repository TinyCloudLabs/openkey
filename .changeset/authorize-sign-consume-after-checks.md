---
"@openkey/api": patch
---

`/api/delegate/authorize-sign` checks context bindings, preview approval, selection, narrowing, regenerated SIWE, and external signatures before atomically consuming its single-use authorization context and preview approval together. Refused requests leave both tokens usable for a corrected retry; of concurrent sign attempts only one can sign, and replays are refused. Managed signing failures after consumption still require a fresh approval.

An empty selection with required capabilities still returns `required-action-missing`, and unknown action IDs still return `action-not-in-baseline`. Context binding failures now take precedence over `empty_selection`; when no actions are required, `empty_selection` precedes preview-approval validation. An expired context now returns `context-expired` instead of `context-not-found` on `/authorize-sign`, `/authorize-sign-preview`, the managed approval, and versioned `/complete`; an expired preview approval returns `preview-approval-expired` instead of `preview-approval-not-found` on `/authorize-sign`. A context expiring between check and consume remains stored until the next prune but cannot sign.
