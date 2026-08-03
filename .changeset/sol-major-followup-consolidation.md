---
"@openkey/capability-review": patch
---

Address Sol's follow-up MAJOR findings on the authorization consolidation:

Capability-review package (`@openkey/capability-review`):

- **MAJOR-1** — `parseSecretPath` in `app-scope.ts` now recognizes the
  js-sdk production path shape `secrets/scoped/<scope>/<name>` (and its
  `vault/` variant). Previously it accepted only the legacy scope-first
  shape `<scope>/secrets/<name>`, so real production scoped-secret
  grants never matched an app declaration and the app-scope gate never
  fired. A new `normalizeSecretVerb` helper canonicalizes grant
  `get/put/del` and manifest `read/write/delete` synonyms before the
  action-subset check, so declarations expressed in either dialect
  match consistently.
- **MAJOR-3** — `statements.ts` now recognizes the production
  encryption ability `tinycloud.encryption/network.create` (the
  compound verb produced by `verbOf` for
  `tinycloud.encryption/network.create`). Grants that combine
  `network.create` with `decrypt` now correctly select the
  contract-mandated statement `"Create a decryption network and
  decrypt protected data"`; grants that carry only `network.create`
  select `"Create a decryption network"`. Previously the compound
  verb was silently ignored and the widget rendered the literal
  fallback.
- **MAJOR-4** — `RequesterIdentity` gains two new fields per manifest
  field (`manifestName` + `manifestNameProvenance`; `manifestIdProvenance`
  alongside the existing `manifestId`). Provenance is one of
  `"verified" | "origin-bound" | "caller" | "none"`. The shared
  `SigningApproval` disclosure renders each field with its provenance
  tag so an operator can never mistake a caller-echoed
  `displayName`/`manifestId` for an OpenKey-verified value.

Test suites now cover the js-sdk production secret path shapes, the
verb-normalization rule, and the encryption `network.create` variants;
15 new app-scope tests and 5 new encryption-statement tests all pass.

The final trust-path review also makes the manifest protocol executable end
to end: OpenKey now hashes the fetched manifest's sorted-key canonical JSON
using the same representation as js-sdk, accepts the SDK's default-read secret
declaration, and presents an exact origin-bound scoped-secret match as Standard
with its secret name and scope. Global, unsigned, mismatched, or action-expanded
secret grants remain sensitive. The sensitive-access callout now counts only
grants that structurally reach TinyCloud secret data or decrypt protected data;
it includes Secrets SQL while excluding unrelated unknown mutations and
create-only encryption grants.

API (`@openkey/api`, not published):

- **MAJOR-4** — `/authorize-sign-prepare` no longer merges caller-
  supplied envelope `displayName` / `manifestId` into `verifiedManifest`
  while marking trust `origin-bound`. Origin-bind proves the FETCHED
  manifest matched the declared digest; the envelope's identity fields
  remain untrusted. The widget layer supplies envelope fallbacks
  separately with the `caller-supplied, unverified` provenance tag.

Web (`@openkey/web`, not published):

- **MAJOR-2** — `widget/embed/sign/+page.svelte` no longer sets
  `requesterAddressForClassifier = key.address.toLowerCase()` on
  origin-bound trust. `key.address` is the signer, not the requester;
  using it as the classifier's requester address caused every own-space
  grant to be labelled "own-app-data" without the shared cross-app
  attention warning. The iframe route now matches the popup:
  `requesterVerified = false` and `requesterAddress = null` unless an
  independently verified identity is supplied. It also now calls
  `annotateAppScopedGrants` with the server's origin-bound
  `declaredAppScope`, so exactly proven scoped-secret declarations from an
  origin-bound manifest surface with a compact secret/scope label and Standard
  presentation.
- **MAJOR-4** — popup / iframe / CLI routes compute
  `manifestName{,Provenance}` and `manifestIdProvenance` alongside the
  display strings and forward them into `parseCapabilityReview`. Server
  fields count as `verified`/`origin-bound` only when trust actually
  reached that status; anything else labels the field `caller` so the
  shared component tags it "caller-supplied, unverified".
- **MAJOR-5** — the browser-parity Playwright spec now opens the
  `<details>` disclosure before clicking the Edit button (which lives
  inside Advanced details and is not visible by default). The 22-test
  suite is now fully green.
