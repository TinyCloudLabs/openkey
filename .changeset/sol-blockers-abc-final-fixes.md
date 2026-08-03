---
"@openkey/capability-review": patch
"@openkey/web": patch
---

Sol final review (post-MAJOR-1..3 continuation): close three final blockers
Sol identified before merge readiness.

**Sol Blocker A — Widget-side hard-coded chain ID broke ownership proof.**
Both widget signing routes (`apps/web/src/routes/widget/sign/+page.svelte`,
`apps/web/src/routes/widget/embed/sign/+page.svelte`) constructed the
capability-review signer with `chainId: 1`, regardless of the chain the
SIWE actually targeted. `expectedSignerSecretsSpace` /
`isSignerOwnedSecretsSpace` pin the signer's canonical secrets space to
`tinycloud:pkh:eip155:<chainId>:<address>:secrets`, so a SIWE with
`Chain ID: 8453` and resource space
`tinycloud:pkh:eip155:8453:<signer>:secrets` was compared against the
chain-1 identity — the ownership proof silently passed for the wrong
chain and the grant received standard severity with friendly
app-scoped copy.

Adds `parseSiweChainId(message)` to `@openkey/capability-review` and uses
it in both widget routes. The signer is now built with the chain ID
parsed from the SIWE bytes that will be signed; if the message has no
parseable `Chain ID:` line (legacy `signMessage`, malformed input), the
routes fall back to `0` so the ownership check fails closed rather than
pretending the request was on mainnet.

**Sol Blocker B — Non-canonical signed KV abilities earned standard
app-scoped presentation.** The proof gate compared grant-side abilities
via `RECOGNIZED_APP_SCOPE_SECRET_VERBS.has(normalizeSecretVerb(a.verb.toLowerCase()))`,
so grants with `tinycloud.kv/GET` (case-folded) or `tinycloud.kv/read`
(long-form synonym) earned standard severity despite no js-sdk producer
emitting either shape on the wire.

`annotateAppScopedGrants` and `findMatchingDeclaredSecret` now compare
grant-side abilities BYTE-EXACTLY against
`CANONICAL_APP_SCOPE_SECRET_ABILITIES` — the exact wire ability
allowlist `{ tinycloud.kv/get, tinycloud.kv/put, tinycloud.kv/del }`.
No case folding, no synonym normalization, no short-form aliases.
Anything else fails the proof and downstream near-miss stamping forces
literal-fallback rendering so the operator sees the raw ability
verbatim.

`normalizeSecretVerb` is retained but only for the DECLARED-side manifest
subset check (manifests legitimately use `read`/`write`/`delete`); it
no longer runs on grant-side ability verbs.

**Sol Blocker C — js-sdk-canonicalized scopes escaped near-miss
enforcement.** `pathContainsDeclaredSecretName` and
`pathContainsDeclaredSecretFragment` skipped any declaration whose raw
scope failed `SECRET_SCOPE_RE`. js-sdk's `canonicalizeSecretScope`
accepts raw manifest scopes like `Listen App`, ` listen app `, and
`listen--app` and produces vault-path segment `listen-app` — so a
manifest that legitimately declared `scope: "Listen App"` plus a
`tinycloud.capabilities/read` grant at
`vault/secrets/scoped/listen-app/API_KEY` produced no fingerprint and
the wrong-service grant remained at standard severity with friendly
"Check permissions for your secrets" copy.

Both fingerprint helpers now canonicalize the declared scope through
the new `canonicalizeSecretScopeForFingerprint` helper (mirrors js-sdk
`canonicalizeSecretScope`) before comparing. The strict proof-side
matcher (`findMatchingDeclaredSecret`) still requires the raw declared
scope to BE its canonical form — that check remains a fail-closed
authority gate. Only near-miss fingerprinting is widened, so same-name
grants on wrong services or wrong paths always demote to sensitive +
literal fallback regardless of the raw scope spelling.

Adds 19 regression tests covering: `parseSiweChainId` across mainnet,
Base (8453), Polygon (137), and invalid input; wrong-chain ownership
proof (the Sol Blocker A probe); `tinycloud.kv/read` and
`tinycloud.kv/GET` proof rejection (the Sol Blocker B probes);
`canonicalizeSecretScopeForFingerprint` across all js-sdk-accepted
forms; and end-to-end near-miss stamping on wrong-service /
uppercase-scope declarations (the Sol Blocker C probe). All 186
capability-review tests pass; `apps/web` typecheck and full monorepo
build remain green.
