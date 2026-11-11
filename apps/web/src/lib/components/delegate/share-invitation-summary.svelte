<script lang="ts">
  import { invitationDateText, invitationDurationText, type ShareInvitationContext } from '$lib/share-invitation';

  interface Props {
    /** The invitation the signed approval request names, as the API stored it. */
    invitation: ShareInvitationContext;
  }

  let { invitation }: Props = $props();
  // Durations count from when the owner sees the approval, again each time the invitation renders.
  const acceptWithin = $derived(invitationDurationText(invitation.acceptanceExpiresAt, Date.now(), 'the next hour'));
  const openFor = $derived(invitationDurationText(invitation.accessExpiresAt, Date.now(), 'less than an hour'));
</script>

<section class="flex flex-col gap-1 rounded-xl border border-surface-200 bg-surface-50 p-4" aria-label="Invitation">
  <h2 class="text-base font-semibold leading-snug text-surface-900 [overflow-wrap:anywhere]">
    Invite {invitation.recipientEmail} to {invitation.subjectName}
  </h2>
  <p class="text-sm text-surface-900">Accept within {acceptWithin}, by {invitationDateText(invitation.acceptanceExpiresAt)}</p>
  {#if invitation.subjectKind === 'session'}
    <p class="text-xs leading-relaxed text-surface-500">Once accepted, access can continue after this date. If you remove it, access ends within 7 days.</p>
  {:else}
    <p class="text-sm text-surface-900 [overflow-wrap:anywhere]">{invitation.recipientEmail} can open {invitation.subjectName} for {openFor}, until {invitationDateText(invitation.accessExpiresAt)}</p>
  {/if}
</section>
