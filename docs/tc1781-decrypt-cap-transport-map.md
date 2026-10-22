# TC-1781 decrypt lifetime: non-device transport map

Base: origin/main `3cdfa5ad4578fc75dc00103c8c5d387b028c40fd`.
Legend: VERIFIED = read in code at this base. INFERENCE = not observed in code or tests. NOT PROVEN = not determined yet.
"Decrypt reachable" means a request on this path can carry a `tinycloud.encryption/decrypt` entry, judged from code. It is not a claim that a test exercised it.

| # | Path (apps/api/src) | Signs or authorizes | Decrypt reachable | Policy before sign (today) | Current cap | Status |
|---|---|---|---|---|---|---|
| T1 | `routes/delegate.ts` `POST /` token branch; sign at :1519 `signManagedKey(bound.originalSiwe)` | SIWE delegation | YES: `prepareDelegationSession` emits decrypt via `rawAbilities` (`services/delegate-session.ts:449`, default network) and raw encryption entries (`:341-358`) | NO | 7 d default (:314), 30 d max (:323) | VERIFIED |
| T2 | `routes/delegate.ts` `POST /` legacy branch; sign at :1624 `signManagedKey(preparedResult.prepared.siwe)` | SIWE delegation | YES, as T1 | NO | as T1 | VERIFIED |
| T3 | `routes/delegate.ts` `POST /prepare` (:1709-1878) | none; returns unsigned SIWE | YES: SIWE built here | n/a | as T1 | VERIFIED for "no signature"; persistence side effects NOT PROVEN |
| T4 | `routes/delegate.ts` `POST /complete` (:1888; `validatePermissions` :1961) | none server-side; activates a client-signed SIWE | YES | NO | none | VERIFIED for the route shape; decrypt reach follows from T3 input |
| T5 | `routes/delegate.ts` `POST /sign`, `oauth-manage-key` branch (:820-888; sign :863) | `signManagedKey` after `validateTinyCloudManageKeyRequest` (:861) | INFERENCE: the message must be in the `applications` space (:859). Decrypt entries are in other spaces, so the validator is expected to refuse them. Not tested | NO lifetime check beyond `tinycloud-manage-key-policy.ts` | 1 h window (`MAX_SESSION_TTL_MS`, `services/tinycloud-manage-key-policy.ts:15`) | VERIFIED code, reach INFERENCE |
| T6 | `routes/delegate.ts` `POST /sign`, `coordinationos-oauth` branch (:890-1037; sign :1014-1017 `signWithManagedPrivateKey`) | SIWE (sign-in) | YES by construction: `evaluateCoordinationosSessionRequest` (`services/coordinationos-session-policy.ts:314-470`) requires one `urn:recap:` resource (:390-393) and no caveats (:394), and never inspects action names | NO | none on actions; SIWE expiry check not fully read (:404-470) | VERIFIED reach by absence; lifetime NOT PROVEN |
| T7 | `routes/delegate.ts` `POST /sign`, managed-key tail (:1040-1142; `parsePreparedRecap` :1114; `evaluateBootstrapSigningScope` :1122; sign :1135) | SIWE | NOT EXPECTED: decrypt only admitted when a matching `rawAbilities` entry exists (`routes/delegate-autosign.ts:166-222`). Tests show only `tinycloud.encryption/network.create` in the allowlist (`delegate-autosign.test.ts:340-342`, `:684-685`). Allowlist source not located | allowlist check runs before sign; no lifetime | allowlist | VERIFIED gate, reach INFERENCE |
| T8 | `routes/delegate.ts` `POST /host` (:1151-1215; sign :1203) | SIWE over `generateHostSIWEMessage` (peerId) | NO: host SIWE carries no recap [INFERENCE, `generateHostSIWEMessage` not read] | NO | none | INFERENCE |
| T9 | `routes/delegate.ts` `POST /authorize-sign` (:2687-3122; sign :3097 `signManagedKey(signedMessage)`) | SIWE from bound context | YES if the bound SIWE carries decrypt (context filled by T10) | NO | none | VERIFIED sign point; reach follows T10 |
| T10 | `routes/delegate.ts` `POST /authorize-sign-prepare` (:2276-2658) | none; stores signing context | YES | n/a | none | VERIFIED for "no signature"; store side effect NOT PROVEN in full |
| T11 | `routes/delegate.ts` `POST /authorize-sign-preview` (:3141-3341) | none (preview) | YES, shown to user | n/a | none | INFERENCE (read-only not fully verified) |
| T12 | `routes/keys.ts` `POST /:keyId/sign` (:275-343) | `account.signMessage` :331-333 | YES, proven by absence: only `checkSignableMessage` origin check (:298, `services/siwe-origin.ts:172`); no recap or action inspection | NO; `ensureTinyCloudBootstrapForApprovedSign` runs at :325 before sign | none | VERIFIED |
| T13 | `routes/keys.ts` `POST /:keyId/sign-typed-data` (:346-399) | EIP-712 typed data | NOT EXPECTED: not a SIWE recap | n/a | n/a | INFERENCE |
| T14 | `routes/nostr-keys.ts` `POST /:keyId/sign-event` (:224; sign :335) | Nostr event | NOT EXPECTED | n/a | n/a | INFERENCE, not read |
| T15 | `routes/native-delegation-consent.ts` (`permitted()` :38-41; prepare :42-47; sign :238; host sign :257) | delegation | NO: `services/native-delegation/par.ts:101` rejects any service other than kv, sql, capabilities; `par.ts:81` requires space `applications` | n/a | ceiling `maxDelegationTtlSeconds`, `grantLifetimeSeconds` | VERIFIED unreachable |
| T16 | `services/native-delegation/renew-revoke.ts` (:263-273) | delegation renewal | NO: permissions come from `validatePermissions` (`par.ts:77-110`), same validator as T15 | n/a | ceiling | VERIFIED unreachable for rows written by the validator; legacy rows NOT PROVEN |
| T17 | `services/tinycloud-bootstrap.ts` `createBootstrapSession` (:778-805; `abilitiesFromRequest` :831-839; sign :802), `createHostDelegation` (:807-822) | SIWE | NOT EXPECTED: abilities come from `step.request` (manifest, not traced). Only `network.create` appears in tests. `:268-269` checks `NETWORK_CREATE_ACTION` for the default network | fixed 60 min (:789-790), no policy | 60 min fixed | VERIFIED expiry; reach NOT PROVEN (manifest source not read) |
| T18 | `services/device-authorization.ts` | device grant | YES | YES: `assertDecryptLifetime` :515-519, `DECRYPT_ENTRY_MAX_LIFETIME_SECONDS` :23, decrypt-alone :441-443, :483 | 3600 s, alone | VERIFIED; not modified by this change |

Other paths not in the table: `services/managed-key-signing.ts:13-20` is a generic signer with no policy of its own. `services/tinycloud-bootstrap-sweep.ts:108` calls `ensureTinyCloudBootstrap`. `routes/delegate-autosign.ts` admits raw encryption only for `space === 'encryption'` with matching `rawAbilities` (:187-190, :259-262, :307-311). `routes/delegation-codes.ts` NOT READ.

## Client-side reach (external repos, read at local checkouts; not re-verified against main)

- CLI default login manifest: `packages/cli/src/auth/owner-key.ts:59-66` (checkout `js-sdk-tc1466`) has kv, sql, and capabilities only. No decrypt. VERIFIED in that checkout.
- Share sign-in manifest: `share/src/share/openkey-session.ts:194` bundles `{ service: "tinycloud.encryption", actions: ["decrypt", "network.create"], skipPrefix: true }` with `sessionExpirationMs: 60*60*1000` (`:211`). Decrypt and network.create share one entry. VERIFIED in the share checkout. How `skipPrefix` short names expand is NOT PROVEN.
- Listen, Secret Manager, js-sdk web and node: post to `/api/delegate/sign` (`packages/client/src/openkey.ts:125`, `packages/web-sdk/src/openkey-session.ts:21`, `packages/node-sdk/src/TinyCloudNode.ts:374`). Which branch the SDK selects for decrypt requests: NOT PROVEN.

## Paths NOT PROVEN

- T5 whether decrypt can reach `validateTinyCloudManageKeyRequest`
- T6 SIWE expiry beyond `coordinationos-session-policy.ts:404`
- T7 bootstrap allowlist source
- T8 `generateHostSIWEMessage` contents
- T10 and T11 side effects
- T13, T14 (not SIWE)
- T17 `step.request` manifest source
- SDK branch selection for decrypt
