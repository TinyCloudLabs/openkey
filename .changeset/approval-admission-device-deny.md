---
"@openkey/api": patch
---

An approval request is admitted once, before signing starts: expiry is checked at admission, one `approving` marker (a 30-second lease) holds off a second approval and a deny while it is saved, and approve and deny each settle a request exactly once. A deny during an approval in flight answers 409 `approval_in_progress`. Device authorizations can be declined with `POST /api/device-authorizations/:id/deny` (signed-in, OpenKey origin for bearer tokens); the device's poll then answers `access_denied` (400). Details: TC-2615
