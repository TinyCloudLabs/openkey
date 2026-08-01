---
"@openkey/sdk": patch
"@openkey/capability-review": patch
---

Continuation-review v2 hardening on the OpenKey authorization consolidation.

`@openkey/sdk`:

- `authorizeTinyCloud` resolves the caller-supplied `keyId` and routes
  by the resolved key's type, not by `lastAuth.keyType` alone. An
  explicitly supplied external `keyId` routes externally; an
  explicitly supplied managed `keyId` routes to the managed path.
  Conflicting pins (`lastAuth` type disagrees with the resolved
  target-key type) are rejected with `KEY_ID_TYPE_MISMATCH`.
- Popup close-message correlation requires exact `requestId` +
  `protocolVersion` on `openkey:close` messages for versioned flows.
  Overlapping second requests are refused; wrong-requestId close
  messages are dropped.

`@openkey/capability-review`:

- `assertBaselineSubset` enforces exact multiset equality on caveats
  for every surviving (resource, ability) pair. Whole-ability and
  whole-resource removal remain allowed. Every other transformation
  surfaces as `candidate-broadens-baseline` with a message citing the
  specific change.

The internal `@openkey/api` and `@openkey/web` packages (ignored in
the release config) received the matching server-side narrowing-splice
helper, the preview-approval token consume path, and the widget-transport
correlation checks. Those are documented in the internal changelog and
covered by their own tests.
