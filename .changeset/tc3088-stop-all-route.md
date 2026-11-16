---
"@openkey/api": patch
---

Operators can stop every live renewal lease on demand (TC-3088): `POST /api/internal/renewal-leases/stop-all` is a dry run unless the body is `{"apply": true}`, needs `OPENKEY_RENEWAL_STOP_TOKEN` (a token for this route only; the route answers 503 while it is unset) and an `X-Operator` label, and answers counts only (`stopped`, `failed`, `skippedExternal`). It uses the same revocation as Settings "Stop renewal", skips leases an external wallet signed and reports them, can be run again safely, and writes one `renewal_lease_stop_all_run` log line per run. Renewal leases are now made only for accounts whose key OpenKey holds: ticking renewal on an account that signs with an external wallet is refused (`renewal_external_wallet`) and nothing is approved, until a wallet-signed lease can be stopped by the operator kill.
