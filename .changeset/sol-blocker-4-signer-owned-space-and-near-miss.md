---
"@openkey/capability-review": patch
---

Fix Blocker 4 follow-up defects (Sol): exact signer-owned secrets space proof and near-miss literal fallback.

Two defects in the original Blocker 4 pass:

**Defect 1 (cross-signer space attack):** The pre-fix `isSecretsSpace`
predicate was purely a shape check — it accepted the literal string
`"secrets"` OR any space whose path contained `:secrets`. A probe signed by
`0x1111…1111` presenting a grant on `0x2222…2222:secrets` would still pass
the shape check and be demoted to standard severity. Nothing about the
caller demonstrated ownership of the attacker's space.

The fix adds `expectedSignerSecretsSpace(signer)` and
`isSignerOwnedSecretsSpace(space, signer)` derived from the js-sdk canonical
form (`tinycloud:pkh:eip155:<chainId>:<address>:secrets`, lowercased hex).
`annotateAppScopedGrants` now requires `grant.space` to be exactly the
signer's own canonical secrets space before any sensitive → standard
transition. Matching is case-insensitive on the address hex so both EIP-55
and lowercased forms resolve to the same identity.

**Defect 2 (near-miss friendly-copy leak):** When a KV secret-family grant
on a secrets-shaped space failed the exact proof (wrong owner, wrong path,
wrong verb, no matching declared entry, …), the grant was left structurally
classified and `buildStatement` emitted friendly KV secrets copy such as
"View secrets stored in your vault" — dressing the ability up in reassuring
copy the failed proof did not earn.

The fix adds an `appScopeNearMiss` flag on `CapabilityGrant`. Any KV secret
grant that fails the exact proof is stamped with `appScopeNearMiss: true`,
`severity: "sensitive"`, and `metadataLabel: null`. `buildStatement`
short-circuits any near-miss grant to the literal fallback (raw service,
resource, and ability strings) so the operator always sees the actual wire
verb, never friendly secret-family framing.

The near-miss stamp is a demote-only signal: it never lowers severity, only
elevates it and forces literal copy. Non-KV secret grants (the
`tinycloud.secrets` service branch) are not stamped — that branch has its
own recognized-actions allowlist and does not emit vault-shaped copy.
