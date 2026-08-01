<script lang="ts">
  // PopupSigningAdapter — the substantive production adapter for the popup
  // widget (`/widget/sign`) surface.
  //
  // This adapter owns:
  //   - the review selection and editing state,
  //   - the onApprove decision (preview vs exact-byte fallthrough),
  //   - the onCancel wiring (widget cancel response + close),
  //   - the invalidatePreview call when the selection changes.
  //
  // The route is responsible only for:
  //   - building the initial `CapabilityReviewModel`,
  //   - providing a `WidgetSigningTransport` that reaches the widget-specific
  //     completion path (postMessage to the opener, preview fetches, close).
  //
  // The parity test mounts this real adapter with a fixture model and a
  // spy transport, then dispatches real DOM Space/Enter keyboard events.
  // A wiring bug (e.g. dropping `invalidatePreview` from the selection
  // handler) surfaces there as a missing spy call.

  import type { CapabilityReviewModel } from "@openkey/capability-review";
  import SigningApproval from "$lib/components/signing/signing-approval.svelte";
  import type { WidgetSigningTransport } from "./signing-adapter-types";

  interface Props {
    /** The parsed authorization model to review. */
    model: CapabilityReviewModel;
    /**
     * Initial review selection (typically `defaultSelection(model)` from the
     * route). This becomes the adapter's starting selection; subsequent
     * user toggles are reflected in the internal state and reported to the
     * transport via `invalidatePreview`.
     */
    initialSelection: Set<string>;
    /** Transport for widget-specific completion. */
    transport: WidgetSigningTransport;
  }

  let { model, initialSelection, transport }: Props = $props();

  // Adapter-owned presentational state. We intentionally capture only the
  // initial value of `initialSelection`; subsequent toggles are the
  // adapter's own state (mirrored back to the route via `onSelectionEdited`).
  // svelte-ignore state_referenced_locally
  let selection = $state<Set<string>>(new Set(initialSelection));
  let editing = $state(false);

  function onSelectionChange(next: Set<string>) {
    selection = new Set(next);
    // Mirror the up-to-date selection to the route so its completion
    // payload (effectivePermissions, selectedActionKeys) sees the
    // current narrowing.
    transport.onSelectionEdited(new Set(next));
    // Every selection change MUST invalidate any approved preview so the
    // user re-reviews the newly-derived bytes. Dropping this call is the
    // class of bug the parity test's spy transport catches
    // (spies.invalidatePreview.calls.length === 0 after a toggle).
    transport.invalidatePreview();
  }

  function onEditingChange(next: boolean) {
    editing = next;
  }

  function onApprove() {
    // Route the approval through the server-authoritative preview path
    // when the request is eligible; otherwise fall through to the legacy
    // exact-byte sign path.
    if (transport.canUseAuthorizeSign) {
      void transport.requestPreview();
    } else {
      void transport.approveAndSign();
    }
  }

  function onCancel() {
    transport.cancel();
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
