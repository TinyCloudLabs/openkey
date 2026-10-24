---
"@openkey/api": patch
---

`POST /api/delegate` builds its approval baseline with the device transaction when the request carries a `deviceTransactionId`, the same way `/api/delegate/prepare` and `/api/delegate/complete` do. A device request for the default decrypt entry (`tinycloud.encryption`, space `default`, empty path) is approved for a managed key. A request without a `deviceTransactionId` keeps the ordinary baseline. Details: TC-1953.
