---
"@openkey/capability-review": patch
---

An undo request for `tinycloud.delegation/revoke` on the signer's own space now reads "Remove access you gave" in the approval list instead of "Unknown action: tinycloud.delegation/revoke", and stays marked Sensitive. The label is the whole row: the request names a space, not the app or link, so there is no target to show. A revoke on another user's space, or mixed with another delegation verb, keeps the literal "Unknown action" wording. A revoke on another user's space no longer reads "View another user's connected access".

Details: TC-2232
