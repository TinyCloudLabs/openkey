---
"@openkey/sdk": patch
"@openkey/capability-review": patch
---

Follow-up hardening on the OpenKey authorization consolidation review.

`@openkey/sdk`:

- `authorizeTinyCloud` falls back to `lastAuth.keyId` when the caller
  did not pass an explicit `keyId`, so the widget receives the
  connected-key context instead of rendering `Please connect first.`

`@openkey/capability-review`:

- `classifyRecapEntry` no longer falls back to the signer address as
  the ownership axis when `requesterAddress` is null and
  `requesterVerified` is false. Widget-issued classifications
  fail-closed to `cross-app-data` when the requester identity is
  unverifiable.

The internal `@openkey/api` and `@openkey/web` packages (ignored in the
release config) received matching route, widget-transport, and preview-
approval-token changes described in the internal changelog and covered
by their own tests.
