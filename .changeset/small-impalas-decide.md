---
---

Infra only (TC-513): the production dstack-ingress now publishes `api.openkey.so` as a CNAME to `gateway.<gateway base domain>` instead of `_.<gateway base domain>`, which Android's resolver rejects. No package ships.
