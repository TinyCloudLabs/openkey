<script lang="ts">
  import { checkSiweOrigin, type CapabilityReviewModel } from '@openkey/capability-review';
  import { parseSIWE } from '$lib/siwe-parser';
  import SigningApproval from './signing-approval.svelte';
  interface Props {
    model: CapabilityReviewModel;
    shareId: string;
    ownerDid: string;
    sessionDid: string;
    origin: string;
    ready: boolean;
    approving?: boolean;
    error?: string | null;
    onApprove: () => void;
    onCancel: () => void;
  }
  let { model, shareId, ownerDid, sessionDid, origin, ready, approving = false, error = null, onApprove, onCancel }: Props = $props();
  const host = $derived.by(() => {
    try {
      const parsed = new URL(origin);
      return parsed.protocol === 'https:' && parsed.origin === origin ? parsed.host : null;
    } catch { return null; }
  });
  const valid = $derived.by(() => {
    if (!host || !/^[0-9a-f]{32}$/.test(shareId) || model.protocol !== 'tinycloud-siwe-recap' ||
      model.requester.verifiedOrigin !== origin || model.immutable?.domain !== host ||
      model.immutable.address.toLowerCase() !== model.signer.address.toLowerCase() ||
      ownerDid.toLowerCase() !== `did:pkh:eip155:${model.signer.chainId}:${model.signer.address}`.toLowerCase()) return false;
    const originCheck = checkSiweOrigin(model.rawMessage, origin);
    if (!originCheck.siwe || !originCheck.ok || parseSIWE(model.rawMessage)?.message.uri !== sessionDid) return false;
    const grants = model.permissions.filter(grant => grant.service === 'tinycloud.encryption');
    const grant = grants[0];
    return grants.length === 1 && grant?.ownedBySelf === true && grant.path === '' &&
      grant.space === `urn:tinycloud:encryption:${ownerDid}:default/share/${shareId}` &&
      grant.actions.length === 1 && grant.actions[0]?.ability === 'tinycloud.encryption/decrypt';
  });
  const selection = $derived(new Set(model.permissions.flatMap(grant => grant.actions.map(action => action.id))));
  const fixedModel = $derived({ ...model, permissions: model.permissions.map(grant => ({
    ...grant, actions: grant.actions.map(action => ({ ...action, editable: false })),
  })) });
</script>

{#if valid && host}
  <SigningApproval model={fixedModel} {selection} editing={false} {approving} {error}
    shareCreationHost={host} approveText="Create share" cancelText="Cancel"
    previewPending={!ready} onApprove={() => { if (ready) onApprove(); }} {onCancel}
    onSelectionChange={() => {}} onEditingChange={() => {}} />
{:else}
  <p role="alert">OpenKey could not verify this share request.</p>
  <button type="button" onclick={onCancel}>Cancel</button>
{/if}
