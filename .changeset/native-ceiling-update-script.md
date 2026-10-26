---
"@openkey/api": patch
---

The `register-oauth-client` workflow and `scripts/ci-register-oauth-client.ts` accept a native delegation ceiling for an existing native `client_id`. The value goes through the same validator as the admin PATCH and replaces the stored `tinycloudNativeDelegation`; `appId` and `siweDomain` are kept from the stored ceiling, a supplied value must equal the stored one (a no-op), and a different value is refused. The run prints the BEFORE and AFTER ceiling and the entry diff; a value that removes entries or reduces limits needs `allow_narrow` / `--allow-narrow`, and no flag allows a change of `appId`, `siweDomain` or `tinycloudHost`. The script writes only with `--apply`; the workflow passes it only when `dry_run` is `false`, and every other value is a dry run. The workflow job runs in the `production` environment and waits for its required reviewer (TC-1990).
