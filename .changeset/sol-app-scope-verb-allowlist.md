---
"@openkey/capability-review": patch
---

Constrain app-scoped-secret annotation to a canonical read/write/delete verb
allowlist so an origin-bound manifest cannot widen the recognized
named-secret action vocabulary.

Sol MAJOR (this iteration): `annotateAppScopedGrants` in
`packages/capability-review/src/app-scope.ts` previously accepted any
grant whose family was `secret-read` or `secret-mutation` and any
`(secretName, scope, actions)` triple the origin-bound manifest declared.
An origin-bound manifest declaring `peek` on `API_KEY` therefore matched
a `tinycloud.secrets/peek` grant, flipped its severity from `sensitive`
to `standard`, and stamped `appScopedSecret`. `buildStatement` then took
its early `appScopedSecret` branch — whose broad `READ_VERBS` set
includes `peek` — and rendered `Read the app secret API_KEY` for a wire
verb whose actual authority is not part of the read/write/delete
vocabulary that copy implies.

This change adds a canonical `RECOGNIZED_APP_SCOPE_SECRET_VERBS`
allowlist (`get` / `put` / `del`, matched against both grant and
declaration through `normalizeSecretVerb`) and applies it in two places:

- **Primary gate** — `annotateAppScopedGrants` now refuses to annotate
  when ANY grant verb OR any declared-manifest verb falls outside the
  allowlist. Unknown verbs (`peek`, `admin`, `list`, `metadata`,
  `rotate`, or any future/novel action) leave the grant untouched:
  severity stays `sensitive`, `appScopedSecret` is never stamped, and
  `grantReachesSecretDataOrDecryption` continues to count it.
- **Defense-in-depth** — `buildStatement`'s `appScopedSecret` branch
  re-checks every action verb against the same allowlist. Even if a
  compromised or future-buggy annotator stamped `appScopedSecret` on an
  unknown-verb grant, the friendly `Read/Update the app secret` copy
  cannot fire; the operator sees the literal fallback (`Perform
  tinycloud.secrets/peek on tinycloud.secrets`) instead.

New tests in `packages/capability-review/test/app-scope.test.ts` pin
both gates for the `tinycloud.kv/peek` (js-sdk scoped-secret path) and
direct `tinycloud.secrets/peek` shapes, cover mixed recognized +
unrecognized verb sets on both grant and declaration sides, and
regression-guard the happy path (`get` + `put` remains eligible for
standard-severity friendly copy).
