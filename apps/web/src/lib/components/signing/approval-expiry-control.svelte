<script lang="ts">
  // How long the approval lasts, and whether it renews (TC-2272, TC-2933).
  // One line: a renewal checkbox where the requester can use a renewal lease,
  // otherwise "This app's access to your data lasts <window>." The window and the lease
  // are changed in approval-expiry-chooser.svelte: under a closed fold here, or
  // where the screen sets `chooser` false and shows the chooser itself. It only
  // reports the choices; the server writes the window into the signed message
  // and signs the lease.
  import {
    LONG_EXPIRY_MS,
    LONG_EXPIRY_WARNING,
    MAX_LEASE_MS,
    SENSITIVE_RENEWAL_WINDOW_MS,
    accessLastsLine,
    defaultLeaseMs,
    formatDuration,
  } from "$lib/approval-expiry";
  import ApprovalExpiryChooser from "$lib/components/signing/approval-expiry-chooser.svelte";
  import type { RenewalChoice } from "$lib/components/signing/signing-adapter-types";

  interface Props {
    /** How long the app asked for; null when it cannot be worked out. */
    requestedMs: number | null;
    /** The user's choice; null keeps what the app asked for. */
    chosenMs: number | null;
    /**
     * The longest the requester allows (it signed this into its request); null
     * when the user may pick any time. Longer times are refused with a note.
     */
    maxMs?: number | null;
    disabled?: boolean;
    onChange: (ms: number | null) => void;
    /** Set only when the requester signed a renewal request and can use a lease. */
    renewal?: RenewalChoice | null;
    /** The approval includes secrets or decrypt: turning renewal on asks first (spec D7). */
    sensitive?: boolean;
    /** Who is asking, as the screen names them, for the D7 warning. */
    requestedBy?: string;
    /** The exact end of the window, shown inside the open fold after the choice; omitted where the screen shows it elsewhere. */
    endsAt?: string | null;
    /** How many permission rows the line sits under: more than one reads in the plural. */
    permissionCount?: number;
    /**
     * Set while a one-hour start is in effect and the owner has not picked a time (TC-3111): who asked, as the
     * screen names them ("This request" on a link). Null shows no note.
     */
    onceSite?: string | null;
    onceNote?: string | null;
    /** On a signed request for a secret's own key: its start and the most it can be. Null shows no note. */
    lengthNote?: string | null;
    /** Show the "How long it lasts" fold here. False where the screen shows ApprovalExpiryChooser elsewhere. */
    chooser?: boolean;
    /** Who holds the access, as the line names them: an app, or the device of a device sign-in. */
    holder?: "app" | "device";
  }

  let {
    requestedMs,
    chosenMs,
    maxMs = null,
    disabled = false,
    onChange,
    renewal = null,
    sensitive = false,
    requestedBy = "",
    endsAt = null,
    permissionCount = 1,
    onceSite = null,
    onceNote = null,
    lengthNote = null,
    chooser = true,
    holder = "app",
  }: Props = $props();

  let confirming = $state(false);
  let confirmHeading = $state<HTMLHeadingElement | null>(null);
  let checkbox = $state<HTMLInputElement | null>(null);

  const shownMs = $derived(chosenMs ?? requestedMs);
  const accessLine = $derived(shownMs === null ? "" : accessLastsLine(holder, shownMs));
  const leaseMaxMs = $derived(renewal ? Math.min(renewal.maxLeaseMs, MAX_LEASE_MS) : MAX_LEASE_MS);
  const proposedLeaseMs = $derived(renewal ? defaultLeaseMs(leaseMaxMs) : 0);
  const ticked = $derived(renewal !== null && renewal.leaseMs !== null);
  // Spec D6 rule 4: a lease no longer than the window never renews, so the line says it expires.
  const renews = $derived(ticked && shownMs !== null && renewal!.leaseMs! > shownMs);
  const showWarning = $derived(shownMs !== null && shownMs > LONG_EXPIRY_MS);

  function turnOn() {
    renewal!.onChange(proposedLeaseMs);
  }

  function toggle(event: Event) {
    const box = event.currentTarget as HTMLInputElement;
    if (!box.checked) {
      renewal!.onChange(null);
      return;
    }
    if (sensitive) {
      // Intentional friction (spec D7): the box stays unticked until the owner confirms.
      box.checked = false;
      confirming = true;
      queueMicrotask(() => confirmHeading?.focus());
      return;
    }
    turnOn();
  }

  function confirmRenewal() {
    confirming = false;
    // D6 rule 3: renewing secrets or decrypt uses a 7-day window, within what the requester signed.
    // One change, so the preview is prepared once with both the lease and the window.
    const window = maxMs == null ? SENSITIVE_RENEWAL_WINDOW_MS : Math.min(SENSITIVE_RENEWAL_WINDOW_MS, maxMs);
    renewal!.onChange(proposedLeaseMs, window === shownMs ? undefined : window === requestedMs ? null : window);
    queueMicrotask(() => checkbox?.focus());
  }

  function cancelRenewal() {
    confirming = false;
    queueMicrotask(() => checkbox?.focus());
  }

  // A choice made while the approval is being previewed or signed would not be in what gets signed.
  $effect(() => {
    if (disabled) confirming = false;
  });

  function onKeydown(event: KeyboardEvent) {
    if (event.key === "Escape" && confirming) {
      event.stopPropagation();
      cancelRenewal();
    }
  }
</script>

{#if shownMs !== null}
  <div class="expiry" role="group" aria-label="How long this permission lasts" onkeydown={onKeydown}>
    {#if confirming}
      <div class="renewal-confirm" role="alertdialog" aria-labelledby="renewal-confirm-heading" aria-describedby="renewal-confirm-body">
        <h3 class="renewal-confirm-heading" id="renewal-confirm-heading" tabindex="-1" bind:this={confirmHeading}>Renew sensitive access?</h3>
        <p id="renewal-confirm-body">This lets {requestedBy} keep the Sensitive access listed here for up to {formatDuration(proposedLeaseMs)}, without asking you again. You can stop renewal any time under Renewing permissions in Settings.</p>
        <div class="renewal-confirm-actions">
          <button type="button" class="renewal-confirm-no" onclick={cancelRenewal}>Don't renew</button>
          <button type="button" class="renewal-confirm-yes" onclick={confirmRenewal}>Turn on renewal</button>
        </div>
      </div>
    {:else if renewal}
      <label class="renewal-line">
        <input
          type="checkbox"
          class="renewal-box"
          bind:this={checkbox}
          checked={ticked}
          {disabled}
          onchange={toggle}
        />
        <span data-testid="approval-expiry-line">
          {#if renews}
            {permissionCount > 1 ? "These permissions renew" : "This permission renews"} automatically for up to {formatDuration(renewal.leaseMs!)}
          {:else}
            {accessLine}
          {/if}
        </span>
      </label>
    {:else}
      <p class="expiry-line" data-testid="approval-expiry-line">{accessLine}</p>
    {/if}
    {#if onceNote !== null}
      <p class="expiry-once-note" data-testid="approval-expiry-once-note">{onceNote}</p>
    {:else if onceSite !== null && requestedMs !== null}
      <p class="expiry-once-note" data-testid="approval-expiry-once-note">
        {onceSite} asked for {formatDuration(requestedMs)}. Access that can open all your secrets or all your encrypted data starts at {formatDuration(shownMs)}. You can choose longer under How long it lasts.
      </p>
    {/if}
    {#if lengthNote !== null}
      <p class="expiry-once-note" data-testid="approval-expiry-length-note">{lengthNote}</p>
    {/if}
    {#if chooser}
      <details class="expiry-fold">
        <summary>How long it lasts</summary>
        <ApprovalExpiryChooser {requestedMs} {chosenMs} {maxMs} {disabled} {onChange} {renewal} {endsAt} />
      </details>
    {/if}
    {#if showWarning}
      <p class="expiry-warning" role="status">{LONG_EXPIRY_WARNING}</p>
    {/if}
  </div>
{/if}

<style>
  .expiry {
    display: flex;
    flex-direction: column;
    gap: 6px;
    margin: 0;
    font-size: 13px;
    line-height: 1.45;
    color: #475569;
  }
  .expiry-line,
  .expiry-once-note {
    margin: 0;
    overflow-wrap: anywhere;
  }
  /* Spaced under the line like the other paragraphs on the screen (measured at 390px: 10px, as above the line). */
  .expiry-once-note {
    margin-top: 4px;
  }
  .renewal-line {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    min-height: 40px;
    color: #0f172a;
    cursor: pointer;
    overflow-wrap: anywhere;
  }
  .renewal-box {
    flex: none;
    width: 20px;
    height: 20px;
    margin: 0;
    accent-color: #1d4ed8;
  }
  .expiry-fold > summary {
    width: fit-content;
    min-height: 32px;
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    font-weight: 600;
    color: #475569;
    cursor: pointer;
    list-style: none;
  }
  .expiry-fold > summary::-webkit-details-marker {
    display: none;
  }
  /* The same disclosure marker as "Advanced details". */
  .expiry-fold > summary::after {
    content: "▾";
    color: #64748b;
    transition: transform 160ms ease;
  }
  .expiry-fold[open] > summary::after {
    transform: rotate(180deg);
  }
  /* The open fold keeps the closed fold's gap before whatever follows. */
  .expiry-fold[open] {
    margin-bottom: 8px;
  }
  .renewal-confirm {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 12px;
    color: #0f172a;
    background: #fffbeb;
    border: 1px solid #fde68a;
    border-radius: 12px;
  }
  .renewal-confirm-heading {
    margin: 0;
    font-size: 14px;
    font-weight: 600;
  }
  .renewal-confirm p {
    margin: 0;
  }
  .renewal-confirm-actions {
    display: flex;
    flex-wrap: wrap;
    justify-content: flex-end;
    gap: 8px;
  }
  .renewal-confirm-actions button {
    min-height: 40px;
    padding: 0 14px;
    font: inherit;
    font-weight: 600;
    border-radius: 10px;
    cursor: pointer;
  }
  .renewal-confirm-no {
    color: #0f172a;
    background: #fff;
    border: 1px solid #cbd5e1;
  }
  .renewal-confirm-yes {
    color: #fff;
    background: #92400e;
    border: 1px solid #92400e;
  }
  .expiry-warning {
    margin: 0;
    padding: 6px 10px;
    color: #92400e;
    background: #fffbeb;
    border: 1px solid #fde68a;
    border-radius: 10px;
  }
  .expiry :is(button, input, summary, h3):focus-visible {
    outline: 2px solid #1d4ed8;
    outline-offset: 2px;
  }
</style>
