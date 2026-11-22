---
"@openkey/api": minor
"@openkey/web": minor
"@openkey/db": minor
---

Apps can request a change to a person's TinyCloud location registry record through OpenKey's dedicated consent flow instead of raw message signing.

New endpoints: `POST /api/registry-change/prepare`, `POST /api/registry-change/undo/prepare`, `POST /api/registry-change/publish`, and `GET /api/registry-change/history`. New consent screens: `/widget/registry-change` (popup) and `/widget/embed/registry-change` (embed). New table: `registry_change_history` (migration `20261122_0003_registry_change_history`).

Details: TC-3893
