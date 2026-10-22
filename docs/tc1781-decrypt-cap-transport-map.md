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

## Guard status and NOT COVERED reasons

Rows A–O: line numbers at `b665471`. Rows P–S: line numbers at `03032dc`. "killed" means a mutation of that guard made a test fail. "survived" means no test failed. Each guard stays in place as defence in depth.

| Guard | Location | Result | Reason |
|---|---|---|---|
| A | `routes/delegate.ts` 1531–1536 | killed | |
| B | `routes/delegate.ts` 1630–1637 | killed | |
| C | `routes/delegate.ts` 1661–1667 | survived | Backstop behind B. B is the check that runs first on this path. |
| D | `routes/delegate.ts` 1804–1808 | killed | |
| E | `routes/delegate.ts` 1825–1831 | survived | Backstop behind D. D is the check that runs first on this path. |
| F | `routes/delegate.ts` 2098–2099 | killed | |
| G | `routes/delegate.ts` 852 (manage-key OAuth `/sign`) | killed | |
| H | `routes/delegate.ts` 968–973 | survived | NOT COVERED. CoordinationOS policy allows only `tinycloud.kv` (`services/coordinationos-session-policy.ts:159`), so no decrypt resource is admitted. |
| I | `routes/delegate.ts` 1149–1152 | survived | NOT COVERED. The shipped manifest has no decrypt raw ability. `routes/delegate-autosign.ts` 300–325 accepts `tinycloud.encryption` only when a bootstrap candidate's `rawAbilities` match. |
| J | `routes/delegate.ts` 1222–1223 (`/host`) | survived | NOT COVERED. `/host` takes no permission input, so a decrypt resource cannot reach the host SIWE. |
| K | `routes/delegate.ts` 3140–3141 | killed | |
| L | `routes/delegate.ts` 2459–2460 | killed | |
| M | `routes/keys.ts` 307–308 | killed | |
| N | `services/tinycloud-bootstrap.ts` 803–804 | unreachable | NOT COVERED. Unreachable with the shipped manifest. |
| O | `services/tinycloud-bootstrap.ts` 823–824 | unreachable | NOT COVERED. Unreachable with the shipped manifest. |
| P | `routes/delegate.ts` 1657 (`POST /`, admit opt-in) | killed | `decryptStepupAdmitEnabled() &&` forced to `false &&`. `bun test src/__tests__/delegate-decrypt-lifetime-routes.test.ts`: 2 fail, 51 pass, of 53. |
| Q | `routes/delegate.ts` 1836 (`POST /prepare`, admit opt-in) | killed | Same forced false. Routes test: 5 fail, 48 pass, of 53. |
| R | `routes/delegate-session.ts` 606 (`admitLoneDecrypt`) | killed | Line 606 forced to `false;`. Routes test: 9 fail, 44 pass, of 53. |
| S | `services/decrypt-lifetime-policy.ts` 82 (startup warning) | killed | `if (enforce && !admit) {` forced to `if (false) {`. `bun test src/__tests__/decrypt-lifetime-policy.test.ts`: 1 fail, 48 pass, of 49. |

## Lone own-network decrypt admission (flag ON only)

A request whose only entry is a raw `tinycloud.encryption` decrypt on the approving account's own `:default` network is admitted when its explicit lifetime is at most 3600 s. The opt-in (`loneOwnDefaultDecrypt`) is set per route on `POST /` and `POST /prepare`. Native-delegation callers (`routes/native-delegation-consent.ts:43`, `services/native-delegation/renew-revoke.ts:269`) pass no opt-in and are unchanged.

- The owner is resolved server-side from the signer (`defaultEncryptionNetworkUrn`). No caller-supplied owner or network is read. The prefix is forced to `default` for the admitted shape only.
- Device transactions (`deviceTransactionId` present) are excluded on both `/` and `/prepare`. `/` also runs `deviceDelegationWindowError`, so the exclusion is enforced at the opt-in. `services/device-authorization.ts` and its tests are unchanged.
- The predicate reuses `isRawEncryptionPermission`, which canonicalises service names. A `service: 'encryption'` form is admitted under the same rule.
- A device-shaped lone default decrypt already succeeds at base (see the golden table). Only the raw own-network shape needed admission.
- A named network, a named key, or a second entry is refused as today.
- The consent text for the single decrypt row is asserted against the output of `parseCapabilityReview` and `buildStatements` in `@openkey/capability-review`. The copy is unchanged.
- Explicit lifetime is required. `body.expiry` must be present and at most 3600 s. A request with no expiry, or above 3600 s, is not admitted. Under enforce ON it gets the fixed refusal from the pre-check.
- A bundled decrypt with `network.create` in the same request is not admitted under admit ON. The routes test `a bundled decrypt with network.create is not admitted and keeps the single-space refusal` asserts 400 with `permissions must belong to a single space`.

## Turn-on order

1. `DECRYPT_STEPUP_ADMIT=on`. Additive: only the lone own-network shape at one hour is admitted.
2. Clients move: every decrypt request carries an explicit `expiry` of at most 3600 s, and no decrypt shares an entry with another action.
3. `DECRYPT_LIFETIME_ENFORCE_NON_DEVICE=on`. The cap.

`DECRYPT_LIFETIME_ENFORCE_NON_DEVICE=on` without `DECRYPT_STEPUP_ADMIT=on` logs `WARNING: DECRYPT_LIFETIME_ENFORCE_NON_DEVICE=on without DECRYPT_STEPUP_ADMIT=on; lone own-network decrypt requests are refused`. Startup logs both flag states once per process (`decryptLifetimeFlagLines`, `logDecryptLifetimeFlagOnce`).

## Flag-OFF golden table

`apps/api/src/__tests__/fixtures/delegate-flag-off-golden.json` holds responses recorded from origin/main `3cdfa5a` with both flags unset. The recorder was a throwaway copy of the test and is not committed. `delegate-flag-off-golden.test.ts` replays the same requests on this branch with both flags unset and compares the serialised, normalised responses to the table with `toBe` on `JSON.stringify`. Normalisation: `Authorization` header to `<authorization>`; `Nonce: …` to `Nonce: <nonce>`; ISO timestamps to `<iso>`; `0x` plus 130 hex characters to `<sig>`; UUIDs to `<uuid>`; `oks_…` to `oks_<token>`; `bafk…` to `<cid>`.

Covered: `POST /prepare` (lone device default decrypt, lone own-network raw decrypt, foreign-network and named-key raw decrypt, device plus own-network, kv plus raw decrypt, and kv only, at the expiries listed in the test), `POST /` with a managed key, and `POST /complete`. The fixture holds 17 recorded responses. Not covered by the golden test: `POST /sign`, `POST /host`, `POST /authorize-sign-prepare`, `POST /authorize-sign`, `keys.ts` sign, and bootstrap. Guard table mapping, checked: G is manage-key `/sign` (killed), J is `/host` (NOT COVERED), M is `keys.ts` sign (killed), N and O are bootstrap (unreachable). The rows for `/authorize-sign-prepare` and `/authorize-sign` are not mapped in this table. The golden comparison covers recorded responses only; it is not a whole-server byte-level proof.

## /complete fail-closed (ruling 4)

`decryptRefusalForSignedSiwe` (`routes/delegate-session.ts` ~:278) returns `null` before parsing when the flag is OFF. The refusal for an unparseable SIWE that contains `urn:recap:` is therefore ON-only. OFF behaviour is unchanged and covered by the golden table. Under ON, a SIWE without `urn:recap:` passes through.

## Test isolation

`delegate-decrypt-lifetime-routes.test.ts` stubs `routes/device-delegation-window` (`deviceDelegationWindowError` returns `null`) in its own `mockModules` call, after the `@openkey/tee` mock. Other route tests replace the `routes/device-authorization` binding, and bun caches it across files, so the device window check threw `assertDelegationWindow is not a function` in the full run. The stub covers only the window check. The device-transaction test asserts the opt-in exclusion; the window check is covered by `delegate-device-window-routes.test.ts`.

## Client-side reach (external repos, read at local checkouts; not re-verified against main)

- CLI default login manifest: `packages/cli/src/auth/owner-key.ts:59-66` (checkout `js-sdk-tc1466`) has kv, sql, and capabilities only. No decrypt. VERIFIED in that checkout.
- Share sign-in manifest: `share/src/share/openkey-session.ts:194` bundles `{ service: "tinycloud.encryption", actions: ["decrypt", "network.create"], skipPrefix: true }` with `sessionExpirationMs: 60*60*1000` (`:211`). Decrypt and network.create share one entry. VERIFIED in the share checkout. How `skipPrefix` short names expand is NOT PROVEN.
- Under enforce ON, the Share entry above is refused. Its decrypt action shares an entry with `network.create`, which fails the single-action check at `services/decrypt-lifetime-policy.ts:121`. Share must put decrypt in its own entry with an explicit expiry of at most 3600 s before enforce is turned on. Share's change is not part of this branch.
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
