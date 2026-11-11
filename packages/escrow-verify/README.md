# Escrow holder verification

`verifyEscrowForHolder(bundle, pins)` verifies an export before a holder opens
or releases a share. It returns the verified canonical header hash for recovery.
Trusted service measurement, KMS-root and holder-key pins are supplied separately
from the export bundle.

The verifier uses exact-pinned `@phala/dcap-qvl` 0.7.0 with the library's Intel
root, live collateral from `https://pccs.phala.network`, the current wall clock,
and an UpToDate-only TCB policy. It verifies header REPORTDATA binding, RTMR3
event replay, boot app/compose identity, pinned image and system measurements,
both GetKey signature links, and the holder's recipient key. The signed GetKey
purpose is always the empty string for the two v1 transforms. Runtime event
replay follows the existing witness issuer verifier's v1/v2 encoding.

Tests verify a public upstream Intel-rooted quote fixture at its historical
validation time and reject signature tampering and expired collateral. Synthetic
policy tests execute real GetKey signatures and event replay with an injected
DCAP result; production exposes no verification-injection parameter.
