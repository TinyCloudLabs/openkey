---
"@openkey/api": patch
---

`GET /api/secrets` and the counts in `GET /api/secrets/status` list the key names under `vault/secrets/` and decrypt no value. The secrets session signs for kv on `vault/secrets/` and for `network.create` on the account's default encryption network, and holds no decrypt grant, so it cannot open a sealed value. `POST /api/secrets/enable` makes the default encryption network when the account has none, so the first secret of a new account can be written. Each listed secret carries `createdAt` as an empty string, because the creation time sits inside the sealed value; `POST` and `PUT` return the time of the write.

Details: TC-3284
