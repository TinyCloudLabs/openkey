---
"@openkey/capability-review": patch
---

Documentation-only changeset entry for `@openkey/capability-review`;
the substantive code changes below live in `@openkey/web`, which is
ignored by the release config. This entry exists so the release
changelog references the parity contract that
`@openkey/capability-review` consumers (the surface adapters) rely on.

Substantive signing-approval production adapters and browser-driven
parity coverage (Sol MAJOR-1 final continuation, iteration 2).

The three OpenKey signing surface adapters
(`src/lib/components/signing/{cli,popup,iframe}-signing-adapter.svelte`)
were previously thin pass-through wrappers around
`SigningApproval` — every route-specific behavior lived in inline
callbacks on the route. This meant a bug in a route's approve-path
routing (`requestPreview` vs `approveAndSign`), its selection-change
handler (dropping `invalidatePreviewForSelectionEdit`), or its
selection→server-key mapping (`mapReviewSelectionToActionKeys`) could
NOT be caught by parity tests that mounted the adapters.

Changes in `@openkey/web` (not published; ignored in release config):

- Two transport interfaces at
  `src/lib/components/signing/signing-adapter-types.ts`:
  `CliSigningTransport` (delegate/callback + selection remap) and
  `WidgetSigningTransport` (preview vs exact-byte routing +
  selection-edit invalidation).
- Each of the three surface adapters is now substantive: it owns its
  review-selection and editing state and implements the surface-
  specific `onApprove` / `onCancel` / `onSelectionChange` /
  `onEditingChange` wiring. Routes hand each adapter a `transport`
  implementation matching the surface's contract; nothing route-
  specific is inlined at the JSX site any more.
- Widget transports expose whether a server-sealed preview is ready.
  The first approval prepares exact bytes; the second approval stays in
  the same shared content view and consumes those bytes. Popup and iframe
  no longer replace the categorized grants, Advanced details, manifest
  provenance, signing identity, and copyable raw message with a route-
  local final card.
- The three production routes (`/delegate`, `/widget/sign`,
  `/widget/embed/sign`) now mount their respective adapters with the
  new transport-based API. Selection state and completion callbacks
  live inside the adapter; the routes remain responsible for building
  the initial `CapabilityReviewModel` and constructing the transport
  that reaches the surface-specific completion path.

Parity coverage:

- `apps/web/src/lib/signing-approval-parity-mounted.test.ts` mounts
  the EXACT three production adapter components in happy-dom,
  supplies spy transports whose shape matches the production
  transports one-for-one, and drives Space (on checkbox) and Enter/
  Space (on approve/cancel buttons) via real `KeyboardEvent`
  dispatches. Assertions confirm that (a) the shared DOM projection
  is identical across all three surfaces for the same model, and
  (b) the adapter-specific transport call is invoked with the
  correct payload after each real keyboard interaction. Dropping
  `invalidatePreview`, `onSelectionEdited`, `updateSelection`, or a
  surface's approve-path decision fails this suite.
- `apps/web/tests/browser/signing-approval-parity.spec.ts` boots
  Chromium via Playwright, navigates to a dev-only harness route
  (`/__parity_harness`, guarded by `dev` from `$app/environment`),
  and drives every interaction via `page.keyboard.press` — real
  Tab-driven focus movement, real Enter/Space synthesis on buttons,
  native `<details>` open toggling on summary click and keyboard.
  25 tests cover the three surfaces, the widget's
  `canUseAuthorizeSign=false` fallback, its shared final-preview state,
  legacy exact-byte requests, and malformed-request fail-closed behavior.

Legacy `apps/web/src/lib/signing-approval-parity.test.ts` is now a
structural guardrail only: it asserts each production route imports
and mounts the correct named adapter (no direct `<SigningApproval>`
in a route), each adapter mounts the shared component, and each
adapter is typed against the correct transport interface. It no
longer parses source text to rewrite prop expressions — that
approach was banned by the approval contract.

What this changeset does NOT claim:

- Cross-repo integration: the browser parity suite exercises only
  OpenKey's own adapters. The consumer-side wire-format acceptance
  and end-to-end round-trip live in the companion js-sdk changeset.
- The shared component's authority decisions. It receives a
  presentation-only `finalPreview` state so its hint and action label
  accurately describe the sealed-byte approval; token validation and
  signing remain route/server responsibilities.
