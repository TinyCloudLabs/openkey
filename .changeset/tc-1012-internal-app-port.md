---
---

Infra only (TC-1012): the production `api` service no longer publishes port 3001, so the Phala gateway cannot serve it directly and all traffic goes through the dstack-ingress at `api.openkey.so`. The deploy workflow now fails if the raw gateway port answers. No package ships.
