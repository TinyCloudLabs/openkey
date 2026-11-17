---
"@openkey/api": patch
"@openkey/web": patch
---

Device sign-in can no longer ask to decrypt your whole default encryption network (TC-3204). One approved device request used to let the requester open every file you've shared, including files you share later. A device request can now ask to decrypt only exact shared files (`tinycloud.encryption`, space `default`, path `share/<id>`), at most 4 per request. `POST /api/device-authorizations` refuses the empty path, the `share/` prefix, any other key or prefix, and `apps/` keys with `invalid_scope`. `/api/delegate` with a `deviceTransactionId` refuses any other encryption entry with `invalid_permissions`. A pending device request that still carries the old empty-path entry can't be approved. The /device and /delegate consent show "Open this shared file" for one file, or "Open {n} shared files" for several, marked Sensitive.
