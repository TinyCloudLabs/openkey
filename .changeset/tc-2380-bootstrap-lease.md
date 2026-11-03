---
"@openkey/api": patch
---

TC-2380: TinyCloud setup leases and run bounds. The background sweep now also marks a setup left `in_progress` with an expired lease as `failed` (code `tinycloud_bootstrap_lease_expired` when it had none); this never unseals a key or starts a run. Each setup run is bounded: it ends at 180 s (`tinycloud_bootstrap_deadline`), when its lease is taken over, and its lease is never extended past 210 s from the claim. The sweep claim also requires a sealed key, and `TINYCLOUD_BOOTSTRAP_SWEEP` is re-read for every row. An approval whose fresh node check lists the requested space as not hosted now hosts it even when the stored state is `complete`. New sweep log event `tinycloud_bootstrap_sweep_reaped` and a `reaped` count on the tick log.
