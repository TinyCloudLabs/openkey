<script lang="ts">
  // PopupSigningAdapter — thin production wrapper that mounts the shared
  // SigningApproval component for the popup widget (`/widget/sign`) surface.
  //
  // All three surface adapters (CLI, popup, iframe) are byte-identical
  // wrappers: they exist so the production routes and the parity test can
  // import the SAME real component file and assert it is what actually
  // renders. If a surface ever needs to diverge (e.g. wrap with an extra
  // container), that divergence goes here — never in the parity test's
  // extraction logic.

  import type { CapabilityReviewModel } from "@openkey/capability-review";
  import SigningApproval from "$lib/components/signing/signing-approval.svelte";

  interface Props {
    model: CapabilityReviewModel;
    selection: Set<string>;
    editing: boolean;
    approving?: boolean;
    error?: string | null;
    onApprove: () => void;
    onCancel: () => void;
    onSelectionChange: (next: Set<string>) => void;
    onEditingChange: (next: boolean) => void;
  }

  let {
    model,
    selection,
    editing,
    approving = false,
    error = null,
    onApprove,
    onCancel,
    onSelectionChange,
    onEditingChange,
  }: Props = $props();
</script>

<SigningApproval
  {model}
  {selection}
  {editing}
  {approving}
  {error}
  {onApprove}
  {onCancel}
  {onSelectionChange}
  {onEditingChange}
/>
