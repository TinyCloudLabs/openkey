<script lang="ts">
  // IframeSigningAdapter — the substantive production adapter for the
  // embedded iframe (`/widget/embed/sign`) surface.
  //
  // Popup and iframe surfaces run the same completion logic (both are
  // widget flows that either fetch a server-signed preview or fall
  // through to exact-byte signing). This adapter therefore mirrors the
  // popup adapter one-for-one — the parity test asserts that with the
  // same model, initialSelection, and transport shape, both adapters
  // render byte-identical DOM and invoke the same transport calls in
  // response to the same real DOM keyboard/click events.

  import type { CapabilityReviewModel } from "@openkey/capability-review";
  import SigningApproval from "$lib/components/signing/signing-approval.svelte";
  import type { WidgetSigningTransport } from "./signing-adapter-types";

  interface Props {
    /** The parsed authorization model to review. */
    model: CapabilityReviewModel;
    /**
     * Initial review selection (typically `defaultSelection(model)` from the
     * route).
     */
    initialSelection: Set<string>;
    /** Transport for widget-specific completion. */
    transport: WidgetSigningTransport;
  }

  let { model, initialSelection, transport }: Props = $props();

  // Adapter-owned presentational state — see popup-signing-adapter.svelte
  // for the same-shape note. `initialSelection` is only read once.
  // svelte-ignore state_referenced_locally
  let selection = $state<Set<string>>(new Set(initialSelection));
  let editing = $state(false);

  function onSelectionChange(next: Set<string>) {
    selection = new Set(next);
    // Mirror the up-to-date selection to the route so its completion
    // payload (effectivePermissions, selectedActionKeys) sees the
    // current narrowing.
    transport.onSelectionEdited(new Set(next));
    transport.invalidatePreview();
  }

  function onEditingChange(next: boolean) {
    editing = next;
  }

  function onApprove() {
    if (transport.canUseAuthorizeSign && !transport.previewReady) {
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
  finalPreview={transport.previewReady}
  {onApprove}
  {onCancel}
  {onSelectionChange}
  {onEditingChange}
/>
