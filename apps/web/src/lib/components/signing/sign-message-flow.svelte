<script lang="ts">
  // Shared widget flow controller.
  //
  // Owns:
  //   - creating the widget-transport (bound to the caller's origin)
  //   - parsing the raw request into a CapabilityReviewModel
  //   - maintaining the selection state
  //   - handing off to SigningApproval for rendering
  //   - completing the request via the caller-supplied `sign()` callback
  //   - relaying the result back through the transport
  //
  // Does NOT:
  //   - choose the container mode (popup vs iframe) — the caller does
  //   - resize itself (that is the popup/iframe route's job — resizing
  //     is a transport concern, not a content concern)
  //   - open dialogs (the whole flow IS the dialog)

  import {
    parseCapabilityReview,
    defaultSelection,
    type CapabilityReviewModel,
    type SignerInfo,
  } from "@openkey/capability-review";
  import { createWidgetTransport, type WidgetTransport } from "$lib/widget-transport";
  import SigningApproval from "./signing-approval.svelte";

  interface SignRequestPayload {
    message: string;
    keyId?: string;
  }

  interface SignResult {
    signature: string;
    address: string;
  }

  interface Props {
    /** Configured caller origin (never "*"). */
    origin: string;
    /** Which container we run in. */
    container: "popup" | "iframe";
    /** Signer to render in the review. */
    signer: SignerInfo;
    /**
     * Callback that produces a signature for the (already reviewed) bytes.
     * The `signedMessage` argument is `model.rawMessage` — the exact bytes
     * to be signed. Callers MUST NOT rewrite these bytes.
     */
    sign: (input: {
      keyId?: string;
      signedMessage: string;
      selectedActionIds: string[];
    }) => Promise<SignResult>;
  }

  let { origin, container, signer, sign }: Props = $props();

  let transport = $state<WidgetTransport | null>(null);
  let requestId = $state<string | null>(null);
  let baseline = $state<CapabilityReviewModel | null>(null);
  let selection = $state(new Set<string>());
  let editing = $state(false);
  let approving = $state(false);
  let error = $state<string | null>(null);

  $effect(() => {
    if (typeof window === "undefined") return;
    const t = createWidgetTransport({
      origin,
      container,
      onRequest: (req) => {
        requestId = req.requestId;
        const payload = req.data as unknown as SignRequestPayload;
        const model = parseCapabilityReview({
          message: payload.message,
          signer,
          editable: true,
          metadataTrust: { status: "unsigned", reason: "no manifest supplied" },
          reason: { text: "", source: "none" },
          requester: {
            displayName: origin,
            verifiedOrigin: origin,
            manifestId: null,
            manifestDigest: null,
            domainWarning: false,
            originWarning: false,
          },
        });
        baseline = model;
        selection = defaultSelection(model);
      },
      onClose: () => {
        // Parent asked to cancel.
        window.close();
      },
    });
    transport = t;
    t.emitReady();
    return () => t.destroy();
  });

  async function approve() {
    if (!baseline || !transport || !requestId) return;
    approving = true;
    error = null;
    try {
      const result = await sign({
        signedMessage: baseline.rawMessage,
        selectedActionIds: Array.from(selection),
      });
      transport.respond({
        type: "openkey:sign:response",
        requestId,
        protocolVersion: 1,
        success: true,
        data: {
          signature: result.signature,
          address: result.address,
          signedMessage: baseline.rawMessage,
          selectedActionIds: Array.from(selection),
        },
      });
      approving = false;
    } catch (e) {
      error = e instanceof Error ? e.message : "Signing failed";
      approving = false;
    }
  }

  function cancel() {
    if (!transport || !requestId) return;
    transport.respond({
      type: "openkey:sign:response",
      requestId,
      protocolVersion: 1,
      success: false,
      error: { code: "USER_CANCELLED", message: "User cancelled" },
    });
  }
</script>

{#if baseline}
  <SigningApproval
    model={baseline}
    {selection}
    {editing}
    {approving}
    {error}
    onApprove={approve}
    onCancel={cancel}
    onSelectionChange={(next) => (selection = next)}
    onEditingChange={(next) => (editing = next)}
  />
{:else}
  <p>Waiting for signing request…</p>
{/if}
