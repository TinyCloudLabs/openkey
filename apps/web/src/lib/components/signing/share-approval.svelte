<script module lang="ts">
  export interface ShareReviewPreview {
    requestId: string;
    intentDigest: string;
    shareId: string;
    ownerDid: string;
    sessionDid: string;
    origin: string;
    prepared: { siwe: string };
  }
</script>
<script lang="ts">
  import { checkSiweOrigin, parseCapabilityReview, type CapabilityReviewModel } from '@openkey/capability-review';
  import { parseSIWE } from '$lib/siwe-parser';
  import SigningApproval from './signing-approval.svelte';
  interface Props {
    preview: ShareReviewPreview;
    signer: CapabilityReviewModel['signer'];
    ready: boolean;
    approving?: boolean;
    error?: string | null;
    onApprove: (requestId: string, intentDigest: string) => void;
    onCancel: () => void;
  }
  let { preview, signer, ready, approving = false, error = null, onApprove, onCancel }: Props = $props();
  const host = $derived.by(() => {
    try {
      const parsed = new URL(preview.origin);
      return parsed.protocol === 'https:' && parsed.origin === preview.origin ? parsed.host : null;
    } catch { return null; }
  });
  // The model is always derived from the bytes the server preview will sign.
  const model = $derived.by(() => {
    try {
      return parseCapabilityReview({ message: preview.prepared.siwe, signer, editable: false,
        metadataTrust: { status: 'unsigned', reason: 'no manifest supplied' }, reason: { text: '', source: 'none' },
        requester: { displayName: host ?? '', verifiedOrigin: preview.origin, appId: null,
          manifestName: null, manifestNameProvenance: 'none', manifestId: null,
          manifestIdProvenance: 'none', manifestDigest: null, domainWarning: false, originWarning: false },
      });
    } catch { return null; }
  });
  const valid = $derived.by(() => {
    if (!host || !model || !/^[0-9a-f]{32}$/.test(preview.shareId) ||
      !/^[A-Za-z0-9_-]{43}$/.test(preview.requestId) || !/^[0-9a-f]{64}$/.test(preview.intentDigest) ||
      model.protocol !== 'tinycloud-siwe-recap' || model.immutable?.domain !== host ||
      model.immutable.address.toLowerCase() !== signer.address.toLowerCase() ||
      preview.ownerDid.toLowerCase() !== `did:pkh:eip155:${signer.chainId}:${signer.address}`.toLowerCase()) return false;
    const originCheck = checkSiweOrigin(preview.prepared.siwe, preview.origin);
    if (!originCheck.siwe || !originCheck.ok || parseSIWE(preview.prepared.siwe)?.message.uri !== preview.sessionDid) return false;
    const grants = model.permissions.filter(grant => grant.service === 'tinycloud.encryption' ||
      grant.actions.some(action => action.ability.startsWith('tinycloud.encryption/')));
    const grant = grants[0];
    return grants.length === 1 && grant?.ownedBySelf === true && grant.path === '' &&
      grant.space === `urn:tinycloud:encryption:${preview.ownerDid}:default/share/${preview.shareId}` &&
      grant.actions.length === 1 && grant.actions[0]?.ability === 'tinycloud.encryption/decrypt';
  });
  const selection = $derived(new Set(model?.permissions.flatMap(grant => grant.actions.map(action => action.id)) ?? []));
</script>

{#if valid && host && model}
  <SigningApproval {model} {selection} editing={false} {approving} {error}
    shareCreationHost={host} approveText="Create share" cancelText="Cancel"
    previewPending={!ready} onApprove={() => { if (ready) onApprove(preview.requestId, preview.intentDigest); }} {onCancel}
    onSelectionChange={() => {}} onEditingChange={() => {}} />
{:else}
  <p role="alert">OpenKey could not verify this share request.</p>
  <button type="button" onclick={onCancel}>Cancel</button>
{/if}
