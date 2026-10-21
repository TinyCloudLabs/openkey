---
"@openkey/capability-review": patch
---

Consent review now gives `tinycloud.sql/schema` its own statement row instead of folding it into "Update application data". Schema-only grants read "Create, change and delete this app's tables" (or the matching other-user, account, application-data, and secret-catalog wording). A SQL grant that mixes schema with read or write yields two rows from the new `buildStatements()`: the read/update row and the schema row. Secret Manager's catalog grant keeps "View and manage your secret catalog" and adds "Create, change and delete tables in your secret catalog". `buildStatement()` returns one row and, for a mixed schema grant, the literal fallback instead of dropping schema, so callers must render every row from `buildStatements()`.
