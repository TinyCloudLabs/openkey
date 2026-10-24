---
"@openkey/api": patch
---

The `register-oauth-client` workflow and `scripts/ci-register-oauth-client.ts` accept a full native delegation ceiling for an existing native `client_id`. The value goes through the same validator as the admin PATCH and replaces the stored ceiling. The run prints the BEFORE and AFTER ceiling and the entry diff; a value that removes entries or reduces limits needs `allow_narrow` / `--allow-narrow`. The script writes only with `--apply`; the workflow passes it only when `dry_run` is `false`, and every other value is a dry run (TC-1990).
