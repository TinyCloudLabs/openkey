---
"@openkey/web": patch
---

The approval page reads the code from a failed device approval, says "Wait a moment" only for conflicts that waiting can clear, and shows the permission-request refusal for `delegation_prepare_failed` and `signed_exceeds_request`.

Details: TC-3441
