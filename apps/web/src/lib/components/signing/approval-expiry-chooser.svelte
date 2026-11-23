<script lang="ts">
  // The "how long" choices for an approval (TC-2272, TC-2933): the window, and
  // the renewal lease where one is ticked. It only reports the choices; the
  // server writes the window into the signed message and signs the lease. The
  // line that says how long it lasts, and the renewal box, are in
  // approval-expiry-control.svelte; a screen puts this inside a fold of its own.
  import { EXPIRY_PRESETS, LEASE_PRESETS, MAX_LEASE_MS, expiryLimitNote, leaseLimitNote } from "$lib/approval-expiry";
  import { formatLocalAccessEnd } from "$lib/access-end";
  import DurationChoice from "$lib/components/signing/duration-choice.svelte";
  import type { RenewalChoice } from "$lib/components/signing/signing-adapter-types";

  interface Props {
    /** How long the app asked for; null when it cannot be worked out. */
    requestedMs: number | null;
    /** The user's choice; null keeps what the app asked for. */
    chosenMs: number | null;
    /** The longest the requester allows; null when the user may pick any time. */
    maxMs?: number | null;
    limitNote?: (ms: number) => string;
    disabled?: boolean;
    onChange: (ms: number | null) => void;
    /** Set only when the requester signed a renewal request and can use a lease. */
    renewal?: RenewalChoice | null;
    /** The exact end of the window, shown after the choice; omitted where the screen shows it elsewhere. */
    endsAt?: string | null;
  }

  let { requestedMs, chosenMs, maxMs = null, limitNote = expiryLimitNote, disabled = false, onChange, renewal = null, endsAt = null }: Props = $props();

  const shownMs = $derived(chosenMs ?? requestedMs);
  const leaseMaxMs = $derived(renewal ? Math.min(renewal.maxLeaseMs, MAX_LEASE_MS) : MAX_LEASE_MS);

  function chooseWindow(ms: number) {
    // On device sign-in, the default window changes with the renewal checkbox.
    onChange(ms === requestedMs && !renewal?.deviceSignIn ? null : ms);
  }
</script>

{#if shownMs !== null}
  <div class="expiry-panel">
    <DurationChoice
      id="approval-expiry"
      legend="Expires after"
      detail={endsAt ? formatLocalAccessEnd(endsAt) : null}
      presets={EXPIRY_PRESETS}
      valueMs={shownMs}
      {maxMs}
      {limitNote}
      {disabled}
      onChoose={chooseWindow}
    />
    {#if renewal && renewal.leaseMs !== null}
      <DurationChoice
        id="approval-lease"
        legend="Renews for up to"
        presets={LEASE_PRESETS}
        valueMs={renewal.leaseMs}
        maxMs={leaseMaxMs}
        limitNote={leaseLimitNote}
        {disabled}
        onChoose={(ms) => renewal!.onChange(ms)}
      />
    {/if}
  </div>
{/if}

<style>
  .expiry-panel {
    display: flex;
    flex-direction: column;
    gap: 14px;
    margin-top: 6px;
    padding: 10px 12px;
    font-size: 13px;
    line-height: 1.45;
    color: #475569;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
  }
</style>
