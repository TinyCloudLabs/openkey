---
"@openkey/sdk": patch
"@openkey/capability-review": patch
---

Final Sol continuation-review hardening on the OpenKey authorization
consolidation.

`@openkey/capability-review`:

- `splitResourceUri` strips the `<short-service>` segment and returns a
  WASM-aligned `{ space, path }`. `parse.ts` and `subset.ts` share this
  helper so the parser matches the on-wire structure
  `<space>/<short-service>[/<sub-path>]` used by WASM's
  `parseRecapFromSiwe`.
- `canonicalMultisetEqual` compares caveats by canonical-JSON multiset
  equality: object keys are sorted recursively before comparison,
  duplicates are respected, and array element order is preserved.
  Prior code used `JSON.stringify(caveats)` and rejected structurally
  identical baselines whose keys serialized in a different order.

`@openkey/sdk`:

- `authorizeTinyCloud` resolves the target key before routing and
  rejects pins whose type disagrees with the resolved key. The
  external branch is entered whenever the resolved target key is
  `EXTERNAL`, regardless of what `lastAuth.keyType` is; the managed
  branch is entered whenever the resolved target key is `MANAGED`.
- Iframe resize correlation is exercised through the parent-side
  handler for wrong `requestId`, wrong `protocolVersion`, missing
  correlation, no active request bound, and sequential-request
  rebinding.

What this changeset does not claim:

- Cross-repo import of the js-sdk `signInWithOpenKeyResult` from the
  OpenKey test graph. The wire-format contract is asserted from both
  sides (mirrored validator on the OpenKey side, real consumer on the
  js-sdk side against a byte-for-byte Hono-route-shaped body).
- Any change to the internal `@openkey/api` or `@openkey/web` packages
  (ignored in the release config). Matching server-side narrowing,
  caveat-preservation, widget-transport correlation, and preview-
  approval-token changes are documented in the internal changelog and
  covered by their own tests.
