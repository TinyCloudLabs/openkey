<script lang="ts">
  // What a command-line tool asks for when it names ONE exact app key: the warning, then the "App key" row naming
  // the app host and the exact key. The words are `TICKET_APP_KEY_COPY`; the owner can't narrow the two abilities.
  import {
    FAMILY_LABEL,
    TICKET_APP_KEY_COPY,
    splitStatementCode,
    ticketAppKeyText,
    type TicketAppKeyReview,
  } from '@openkey/capability-review';

  let { review }: { review: TicketAppKeyReview } = $props();
  const lines = $derived([TICKET_APP_KEY_COPY.createLine, TICKET_APP_KEY_COPY.decryptLine].map((line) => ticketAppKeyText(line, review)));
  const keyLine = $derived(ticketAppKeyText(TICKET_APP_KEY_COPY.keyLine, review));
</script>

{#snippet marked(text: string)}{#each splitStatementCode(text) as part}{#if part.code}<code class="font-mono">{part.text}</code>{:else}{part.text}{/if}{/each}{/snippet}

<div data-testid="ticket-app-key" class="space-y-3">
  <p data-testid="ticket-app-key-warning" role="note" class="rounded-lg border border-amber-300 bg-amber-50 p-3 text-amber-900">{ticketAppKeyText(TICKET_APP_KEY_COPY.warning, review)}</p>
  <div data-testid="ticket-app-key-row" class="rounded-lg border p-3 text-sm break-all">
    <p class="text-xs font-semibold tracking-wide text-surface-600 uppercase">{FAMILY_LABEL['app-keys']}</p>
    <p class="font-semibold">{ticketAppKeyText(TICKET_APP_KEY_COPY.rowHeading, review)}</p>
    {#each lines as line}<p>{@render marked(line)}</p>{/each}
    <p class="mt-1 text-xs text-surface-600">{@render marked(keyLine)}</p>
  </div>
</div>
