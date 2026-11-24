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
    ONCE_DEFAULT_EXPIRY_MS,
    SENSITIVE_RENEWAL_WINDOW_MS,
    accessLastsLine,
    defaultLeaseMs,
    formatDuration,
    type OnceLongerChoice,
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
     * Set on a one-time approval (secrets or decrypt, TC-4156). `caution` says what the access can open and shows
     * under the length; `longer` is the second option next to 1 hour, null where the app asked for an hour or less.
     * Null shows neither.
     */
    onceChoice?: { longer: OnceLongerChoice | null; caution: string } | null;
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
    onceChoice = null,
    lengthNote = null,
    chooser = true,
    holder = "app",
  }: Props = $props();
  // Names the radio group and the caution that describes it.
  const uid = $props.id();

  let confirming = $state(false);
  let confirmHeading = $state<HTMLHeadingElement | null>(null);
  let checkbox = $state<HTMLInputElement | null>(null);
  let onceGroup = $state<HTMLFieldSetElement | null>(null);
  // Counts the owner's picks, so the radios are checked against what will be signed after every pick.
  let oncePicks = $state(0);

  const shownMs = $derived(chosenMs ?? requestedMs);
  const accessLine = $derived(shownMs === null ? "" : accessLastsLine(renewal?.deviceSignIn ? "device" : holder, shownMs));
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
    const window = Math.min(
      SENSITIVE_RENEWAL_WINDOW_MS,
      maxMs ?? Infinity,
      renewal?.deviceSignIn ? shownMs ?? Infinity : Infinity,
    );
    // TC-3821: the confirm travels with the choice; the server refuses a lease on secrets without it.
    renewal!.onChange(proposedLeaseMs, window === shownMs ? undefined : window === requestedMs ? null : window, true);
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

  // A radio the owner clicked stays checked in the page even when the new length was not prepared (a failed
  // re-prepare leaves the old length as the one that will be signed). Once the preview ends, the radios show
  // the length that will be signed.
  $effect(() => {
    void oncePicks;
    if (disabled || onceGroup === null) return;
    const signedMs = shownMs;
    const lengths = [ONCE_DEFAULT_EXPIRY_MS, onceChoice?.longer?.ms];
    onceGroup.querySelectorAll<HTMLInputElement>('input[type="radio"]').forEach((radio, index) => {
      radio.checked = lengths[index] === signedMs;
    });
  });

  function pickOnce(ms: number) {
    oncePicks += 1;
    onChange(ms);
  }

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
        <p id="renewal-confirm-body">
          {#if renewal?.deviceSignIn}
            This device can keep the sensitive access listed here for up to {formatDuration(proposedLeaseMs)}.
            Each renewal lasts up to 7 days. You can stop renewal under Renewing permissions in Settings.
          {:else}
            This lets {requestedBy} keep the Sensitive access listed here for up to {formatDuration(proposedLeaseMs)}, without asking you again. You can stop renewal any time under Renewing permissions in Settings.
          {/if}
        </p>
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
            {permissionCount > 1 ? "These permissions renew" : "This permission renews"} automatically for up to {formatDuration(renewal.leaseMs!)}{renewal.deviceSignIn ? "." : ""}
          {:else}
            {accessLine}
          {/if}
        </span>
      </label>
    {:else}
      <p class="expiry-line" data-testid="approval-expiry-line">{accessLine}</p>
    {/if}
    {#if onceChoice !== null}
      {#if onceChoice.longer !== null && renewal?.leaseMs == null && (shownMs === ONCE_DEFAULT_EXPIRY_MS || shownMs === onceChoice.longer.ms)}
        <fieldset class="once-choice" bind:this={onceGroup} data-testid="approval-expiry-once-choice" aria-describedby="{uid}-once-caution">
          <legend>How long</legend>
          <label class="once-option">
            <input
              type="radio"
              name="{uid}-once-length"
              checked={shownMs === ONCE_DEFAULT_EXPIRY_MS}
              {disabled}
              onchange={() => pickOnce(ONCE_DEFAULT_EXPIRY_MS)}
            />
            <span>{formatDuration(ONCE_DEFAULT_EXPIRY_MS)}</span>
          </label>
          <label class="once-option">
            <input
              type="radio"
              name="{uid}-once-length"
              checked={shownMs === onceChoice.longer.ms}
              {disabled}
              onchange={() => pickOnce(onceChoice.longer!.ms)}
            />
            <span>{onceChoice.longer.label}</span>
          </label>
        </fieldset>
      {/if}
      <p class="expiry-once-note" id="{uid}-once-caution" data-testid="approval-expiry-once-caution">{onceChoice.caution}</p>
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
  .once-choice {
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
    margin: 0;
    padding: 0;
    border: 0;
  }
  .once-choice > legend {
    padding: 0;
    margin-bottom: 2px;
    font-size: 12px;
    font-weight: 600;
    color: #475569;
  }
  .once-option {
    display: flex;
    align-items: center;
    gap: 10px;
    min-height: 40px;
    color: #0f172a;
    cursor: pointer;
    overflow-wrap: anywhere;
  }
  .once-option > input {
    flex: none;
    width: 20px;
    height: 20px;
    margin: 0;
    accent-color: #1d4ed8;
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
