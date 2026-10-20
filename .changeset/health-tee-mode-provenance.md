---
"@openkey/api": patch
---

Replace `/health`'s ambiguous `tee` field with `tee_mode`, which describes the configured dstack or local mock client path, and `os_image: "unknown"` because the API has no independently trusted guest OS-image identity. JSON-body consumers must migrate from `tee` to `tee_mode`; `production` is not an OS-hardening or attestation claim. Readiness status codes and the not-ready response are unchanged.
