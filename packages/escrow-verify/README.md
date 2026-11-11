# Escrow holder verification

`verifyEscrowForHolder(bundle, holderId, holderPublicKey)` verifies an export before a holder opens
or releases a share. It returns the verified canonical header hash for recovery.
Service measurements are selected from committed per-service allowlists by
composeHash. The KMS root is a committed constant. Unconfigured trust or an
unlisted release is rejected. Only holder identity and its own public key are
caller inputs; release/KMS pin changes go through reviewed commits.

The verifier uses exact-pinned `@phala/dcap-qvl` 0.7.0 with the library's Intel
root, live collateral from `https://pccs.phala.network`, the current wall clock,
and an UpToDate-only TCB policy. It verifies header REPORTDATA binding, RTMR3
event replay, boot app/compose identity, pinned image and system measurements,
both GetKey signature links, and the holder's recipient key. The signed GetKey
purpose is always the empty string for the two v1 transforms. Runtime event
replay accepts only v1. A createdAt more than five minutes in the future is
rejected; expiresAt applies to export approval, not later holder release.

Tests verify a public upstream Intel-rooted quote fixture at its historical
validation time and reject signature tampering and expired collateral. Synthetic
policy tests execute real GetKey signatures and event replay with an injected
DCAP result; production exposes no verification-injection parameter.

GetKey signature malleability does not alter signer identity; signature bytes
are never used as identifiers. Holder release is authorized by its separate
recovery ceremony. The verifier's test/typecheck commands build the workspace
TEE dependency first.
