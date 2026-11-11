<script lang="ts">
  import { invitationDateText, invitationDurationText, type ShareInvitationContext } from '$lib/share-invitation';

  interface Props {
    /** The invitation the signed approval request names, as the API stored it. */
    invitation: ShareInvitationContext;
  }

  let { invitation }: Props = $props();
  // Durations and the expired state count from when the owner sees the approval: the clock is read again whenever
  // the invitation changes.
  const now = $derived.by(() => {
    void invitation;
    return Date.now();
  });
  const acceptanceOver = $derived(Date.parse(invitation.acceptanceExpiresAt) <= now);
  const accessOver = $derived(Date.parse(invitation.accessExpiresAt) <= now);
</script>

<section class="flex flex-col gap-1 rounded-xl border border-surface-200 bg-surface-50 p-4" aria-label="Invitation">
  <h2 class="text-base font-semibold leading-snug text-surface-900 [overflow-wrap:anywhere]">
    Invite {invitation.recipientEmail} to {invitation.subjectName}
  </h2>
  {#if acceptanceOver}
    <p class="text-sm text-surface-900">This invitation expired on {invitationDateText(invitation.acceptanceExpiresAt)}.</p>
  {:else}
    <p class="text-sm text-surface-900">Accept within {invitationDurationText(invitation.acceptanceExpiresAt, now, 'the next hour')}, by {invitationDateText(invitation.acceptanceExpiresAt)}</p>
  {/if}
  {#if invitation.subjectKind === 'session'}
    {#if !acceptanceOver}
      <p class="text-xs leading-relaxed text-surface-500">Once accepted, access can continue after this date. If you remove it, access ends within 7 days.</p>
    {/if}
  {:else if accessOver}
    <p class="text-sm text-surface-900 [overflow-wrap:anywhere]">{invitation.recipientEmail} could open {invitation.subjectName} until {invitationDateText(invitation.accessExpiresAt)}.</p>
  {:else}
    <p class="text-sm text-surface-900 [overflow-wrap:anywhere]">{invitation.recipientEmail} can open {invitation.subjectName} for {invitationDurationText(invitation.accessExpiresAt, now, 'less than an hour')}, until {invitationDateText(invitation.accessExpiresAt)}</p>
  {/if}
</section>
