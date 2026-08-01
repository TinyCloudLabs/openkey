<script lang="ts">
  // CliSigningAdapter — the substantive production adapter that mounts
  // the shared `SigningApproval` component for the CLI (`/delegate`) surface.
  //
  // This adapter owns:
  //   - the review selection and editing state,
  //   - the `onApprove` / `onCancel` / `onSelectionChange` / `onEditingChange`
  //     wiring that used to live in inline lambdas at the route.
  //
  // The route is responsible only for:
  //   - building the initial `CapabilityReviewModel`,
  //   - providing a `CliSigningTransport` that reaches the CLI-specific
  //     completion path (managed/external delegation, `updatePermissions`
  //     which re-issues `/api/delegate/prepare`, `goBack` navigation).
  //
  // Because the adapter owns the glue, the parity test can mount the real
  // adapter with a fixture model and a spy transport, then dispatch real
  // DOM Space/Enter keyboard events; a wiring bug (e.g. dropping
  // `updateSelection` from the selection handler) surfaces there.

  import type { CapabilityReviewModel } from "@openkey/capability-review";
  import SigningApproval from "$lib/components/signing/signing-approval.svelte";
  import type { CliSigningTransport } from "./signing-adapter-types";

  interface Props {
    /** The parsed authorization model to review. */
    model: CapabilityReviewModel;
    /**
     * Initial review selection (typically `defaultSelection(model)` from the
     * route). This becomes the adapter's starting selection; subsequent
     * user toggles are reflected in the internal state and reported to the
     * transport via `updateSelection`.
     */
    initialSelection: Set<string>;
    /** Transport for CLI-specific completion. */
    transport: CliSigningTransport;
  }

  let { model, initialSelection, transport }: Props = $props();

  // Internal review state. The adapter owns this because it is per-surface
  // presentational state — the route no longer touches it. We intentionally
  // capture only the initial value of `initialSelection` (subsequent
  // toggles land in the adapter's own state, not the route's).
  // svelte-ignore state_referenced_locally
  let selection = $state<Set<string>>(new Set(initialSelection));
  let editing = $state(false);

  function onSelectionChange(next: Set<string>) {
    selection = new Set(next);
    // Bug regression guard: the CLI transport MUST be notified so the
    // route can re-issue `/api/delegate/prepare` with the narrowed action
    // key set. Dropping this call is the class of bug the parity test's
    // spy transport will catch (spies.updateSelection.calls.length === 0).
    void transport.updateSelection(new Set(next));
  }

  function onEditingChange(next: boolean) {
    editing = next;
  }

  function onApprove() {
    // The CLI's approve is the delegate-submission path. The transport
    // handles managed vs external signing and delegation-token capture.
    void transport.approveDelegate();
  }

  function onCancel() {
    transport.goBack();
  }
</script>

<SigningApproval
  {model}
  {selection}
  {editing}
  approving={transport.approving}
  error={transport.error}
  {onApprove}
  {onCancel}
  {onSelectionChange}
  {onEditingChange}
/>
