---
"@openkey/capability-review": patch
---

Merge-readiness consolidation: address Sol's 6 MAJOR and 2 MINOR findings on
the OpenKey authorization consolidation.

Documentation-only changeset entry for `@openkey/capability-review`; the
substantive code changes below live in `@openkey/api` and `@openkey/web`,
which are ignored by the release config, plus in `@openkey/capability-review`
itself where the underlying model and parser changes land.

Capability-review package (`@openkey/capability-review`):

- New `RequestProtocol` variant `"malformed-recap"`. Returned when the
  raw SIWE carries a `urn:recap:` resource token but the decoder
  produces zero entries. Previously such requests silently downgraded to
  `"siwe-plain"` and were signable exact-byte — dropping the caller's
  capability payload. UI routes now block the Approve button when the
  model resolves to `"malformed-recap"`.
- New `MetadataTrustStatus` variant `"origin-bound"`. Ranks between
  `"unsigned"` and `"verified"`: the widget browser-verified the origin
  and the server fetched the app's `.well-known/openkey-manifest.json`
  and matched its canonical SHA-256 to the envelope's declared digest,
  but no cryptographic manifest signature exists. `metadata.ts`
  monotonic-rank check updated to place `origin-bound` at rank 4
  (`unsigned=3`, `verified=5`).
- New `statements.ts` catalog: `buildStatement(grant)` returns a
  deterministic single-sentence statement for known structural shapes
  (bootstrap-kv on apps/spaces paths, bootstrap-sql on account or
  secrets space, secret-read/mutation, encryption create+decrypt, etc.).
  Unknown shapes fall back to the literal service/resource/actions text
  — never invent friendly semantics. `sensitiveCallout(n)` returns the
  exact contract copy `"N exact grants reach secret data or decryption.
  You can review them below."`.
- Literal NUL bytes in `packages/capability-review/src/{ids,parse}.ts`
  and `apps/web/tests/browser/signing-approval-parity.spec.ts` replaced
  with `"\x00"` escape sequences (same runtime value, text-safe
  source). Diffs and review tools now render these files as text.
- `PROTOCOL_HEADLINE`/`PROTOCOL_HINT` in `copy.ts` extended with copy
  for `"malformed-recap"`.

API (`@openkey/api`, not published):

- `authorizationContextIssueInput` now accepts an optional
  `metadataTrust` and `verifiedManifest`. Stored on the context and
  echoed in the response so the widget renders honest provenance.
- `/authorize-sign-prepare` now accepts optional `presentation` and
  `reportedOrigin` body fields. Envelope is size-bounded to ≤16KB
  and dropped on parse failure. When both a caller-declared digest and
  an https `reportedOrigin` are present, the route calls
  `fetchAndBindWellKnownManifest` (new `services/manifest-origin-fetch.ts`)
  which performs an SSRF-guarded GET of `/.well-known/openkey-manifest.json`:
  https-only, no redirects, private-IP-blocked, 5s timeout, 64KB cap.
  A matching canonical SHA-256 upgrades trust to `origin-bound`; any
  failure fails closed to `unsigned`. The trust decision is bound
  into the authorization context and cannot be raised in later steps.

Web (`@openkey/web`, not published):

- `SigningApproval` restructured per contract: sensitive callout pinned
  at top (`N exact grants reach secret data or decryption. You can
  review them below.`), deterministic per-grant statements in the
  default view via `buildStatement`, and a single `<details>` labelled
  `Advanced details` containing requester, verified origin, manifest
  name/appId/digest under an honest trust label, reason (only when
  present), signing identity, categorized exact-grant list with
  Edit/Reset controls, and the full raw message as a
  `user-select: text` `<pre>` with a `Copy text` button that copies
  `model.rawMessage` verbatim. `domainWarning` renders independently
  from `originWarning` — a concrete but mismatched origin no longer
  hides the SIWE-domain mismatch. Approve is blocked when
  `model.protocol === "malformed-recap"`.
- `widget-transport.ts` validates optional `presentation` field on
  incoming sign requests: fail-closed size cap (16KB), plain-object
  guard, and drops any envelope carrying trust/verification override
  keys (`verified`, `trust`, `metadataTrust`, `manifestVerified`,
  etc.).
- `widget/sign/+page.svelte` and `widget/embed/sign/+page.svelte` now
  forward the SDK-supplied `presentation` and the widget's configured
  https `origin` as `reportedOrigin` to `/authorize-sign-prepare`,
  adopt the server-returned `metadataTrust` and `verifiedManifest`,
  and use them to build the review model. Trust decision is
  authoritative from the server prepare response; envelope claims
  cannot upgrade it. A `malformed-recap` model also short-circuits the
  legacy `signMessage` fallback path.
- `delegate/+page.svelte` keeps the frozen baseline for grant
  edit/reset semantics BUT updates `reviewModel.rawMessage` whenever
  `applyPreparedDelegation` receives a new `prepared.siwe`, so the
  displayed exact bytes always match what will actually be signed.

Test discovery:

- Root `bunfig.toml` under `[test].ignore` excludes
  `apps/web/tests/browser/**/*.spec.ts` (Playwright suite) and
  `scripts/authorize-sign-harness.test.ts` (subprocess harness) from
  broad `bun test` walks.
- The harness carries a defence-in-depth top-of-file guard: it exits
  early unless `OPENKEY_RUN_HARNESS=1` is set. The js-sdk cross-repo
  contract test spawns it with that env explicitly.
