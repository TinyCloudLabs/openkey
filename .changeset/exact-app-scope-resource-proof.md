---
"@openkey/capability-review": patch
---

Fix: app-scoped secret annotation now requires exact service (tinycloud.kv), secrets space, and canonical vault path proof before demoting severity. Previously, a same-named secret on a different service or path could receive friendly copy; it now falls through to literal fallback with sensitive severity (fail-closed).

Sol follow-up probes closed:

- A `tinycloud.secrets/get` grant on an unrelated space at
  `secrets/scoped/listen/API_KEY` used to render "Check permissions for
  your secrets" (attention severity). It now renders the literal fallback
  ("Perform tinycloud.secrets/get on tinycloud.secrets") at sensitive
  severity — no friendly SECRETS_SERVICES copy for a grant that fails
  the exact-resource proof.

- A `tinycloud.kv/get` grant on the signer's own secrets space at
  `unrelated/listen/API_KEY` used to render "Read data outside this app"
  (cross-app-data, attention severity). It now renders the literal
  fallback at sensitive severity — no friendly cross-app copy for a KV
  grant that references a declared secret name via a non-canonical path.

Implementation: adds `NAMED_SECRETS_SERVICES` and
`pathContainsDeclaredSecretFragment` in `app-scope.ts`. The near-miss
enforcement in `annotateAppScopedGrants` now stamps any grant on a KV or
named-secrets service whose path fingerprint references a declared
`{scope, secretName}` entry (validated against SECRET_NAME_RE /
SECRET_SCOPE_RE / reserved-scope filters) but fails the strict exact-
resource proof. The fingerprint is only used for demote-only enforcement;
it never grants annotation.
