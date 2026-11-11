---
"@openkey/api": minor
---

Native delegation ceilings can now match TinyCloud Home's web sign-in (TC-2720): `kv.root` admits the whole applications-space KV, `sql.prefixes` admits `<appId>/<name>/` database prefixes, `sql.foreignDatabases` names exact databases in other app folders, and `hooks` admits `tinycloud.hooks/subscribe` on SQL paths already in the ceiling. PAR and renewal accept the matching requests. `register-oauth-client.yml` can replace an existing client's ceiling and prints it before and after. Existing ceilings are unchanged.
