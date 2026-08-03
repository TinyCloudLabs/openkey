---
"@openkey/capability-review": patch
---

Fix Blocker 4: app-scoped-secret annotation now requires exact resource tuple proof.

Before this change, `annotateAppScopedGrants` matched any grant whose path
tail carried the declared secret name and scope, regardless of service or space.
An origin-bound declaration for `API_KEY/read` on app `listen` could incorrectly
demote a `tinycloud.secrets/get` grant on an unrelated space at path
`secrets/scoped/listen/API_KEY` to standard severity with friendly copy.

The fix mirrors the js-sdk canonical derivation
(`packages/sdk-services/src/secrets/paths.ts resolveSecretPath`) and requires:
- `grant.service` is a KV service (`tinycloud.kv` or `kv`) — never `tinycloud.secrets`
- `grant.space` is the structurally-named secrets space
- `grant.path` equals exactly `vault/secrets/scoped/<scope>/<name>` (the only
  shape js-sdk emits on the wire; legacy shapes are fail-closed)
- `secretName` matches `/^[A-Z][A-Z0-9_]*$/` and `scope` matches
  `/^[a-z0-9-]+$/` excluding reserved `default`/`global`

`buildStatement` gains matching defense-in-depth checks so friendly copy
cannot be produced from a mismatched resource tuple even if a future annotator
bug stamps `appScopedSecret` on a wrong-service or wrong-space grant.

`isSecretsSpace` is now exported from `app-scope.ts` and imported by
`statements.ts` so both surfaces use one shared predicate.
