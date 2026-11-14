---
"@openkey/web": patch
---

The sign pages treat `https://tinycloud.one` as first-party too, matching the signing route: a request from it for decrypt or key creation outside `apps/` is no longer refused up front. Look-alike hosts such as `https://tinycloud.one.evil.example` are still refused before Approve. Details: TC-2928
