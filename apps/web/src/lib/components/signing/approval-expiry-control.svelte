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
    RENEWAL_CHECKING_LINE,
    SECRET_BLOCK_COPY,
    splitAroundName,
    SENSITIVE_RENEWAL_WINDOW_MS,
    accessLastsLine,
    defaultLeaseMs,
    formatDuration,
    formatEndAt,
    formatLengthWithEnd,
    type OnceLongerChoice,
    type SecretLongerChoice,
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
    /** The app asked for renewal and the server has not answered yet: the line reads "Checking renewal…" until it does. */
    renewalPending?: boolean;
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
    /**
     * Set where the sensitive block of the sign face is the compact secret block: `caution` is its one line under the
     * row, `longer` the second length next to 1 hour (null where the app asked for an hour or less), and `explicit`
     * is true where the app's own length is reported as that length, not as null (a one-time approval). It replaces the
     * access line and the one-time choice; the renewal checkbox and its "Checking renewal…" line keep the screen.
     */
    compact?: { longer: SecretLongerChoice | null; caution: string; name: string | null; explicit: boolean; endsAt: string | null } | null;
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
    renewalPending = false,
    sensitive = false,
    requestedBy = "",
    endsAt = null,
    permissionCount = 1,
    onceChoice = null,
    compact = null,
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
  // The end shown is the Expiration Time of the message that will be signed (`compact.endsAt`); only a screen that has
  // none counts it from when the screen opened.
  const openedAt = Date.now();
  const compactOn = $derived(compact !== null && shownMs !== null);
  const cautionParts = $derived(compact ? splitAroundName(compact.caution, compact.name) : null);
  // Only when the length shown is one of the two the toggle offers: a length picked under "How long it lasts" shows as the line.
  const compactToggle = $derived(
    compactOn && compact!.longer !== null && (shownMs === ONCE_DEFAULT_EXPIRY_MS || shownMs === compact!.longer.ms) ? compact!.longer : null,
  );
  const compactChoices = $derived(
    compactToggle === null
      ? []
      : [
          { ms: ONCE_DEFAULT_EXPIRY_MS, label: formatDuration(ONCE_DEFAULT_EXPIRY_MS), asked: false },
          compactToggle,
        ].map((choice) => {
          const name = formatDuration(choice.ms) + (choice.asked ? SECRET_BLOCK_COPY.askedSuffix : "");
          return { ...choice, name };
        }),
  );
  const endMs = $derived.by(() => {
    const signed = Date.parse(compact?.endsAt ?? "");
    return Number.isFinite(signed) ? signed : openedAt + (shownMs ?? 0);
  });
  const endText = $derived(shownMs === null ? "" : formatEndAt(endMs, shownMs));
  // The app's own hour has nothing to choose between and no end named; any other length shown as a line was picked by the owner.
  const askedHourLine = $derived(shownMs !== null && shownMs <= ONCE_DEFAULT_EXPIRY_MS && (chosenMs === null || shownMs === ONCE_DEFAULT_EXPIRY_MS));
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
    const lengths = [ONCE_DEFAULT_EXPIRY_MS, compactOn ? compact?.longer?.ms : onceChoice?.longer?.ms];
    onceGroup.querySelectorAll<HTMLInputElement>('input[type="radio"]').forEach((radio, index) => {
      radio.checked = lengths[index] === signedMs;
    });
  });

  function pickOnce(ms: number) {
    oncePicks += 1;
    onChange(ms);
  }

  function pickCompact(ms: number) {
    oncePicks += 1;
    onChange(compact!.explicit || ms !== requestedMs ? ms : null);
  }

  function onKeydown(event: KeyboardEvent) {
    if (event.key === "Escape" && confirming) {
      event.stopPropagation();
      cancelRenewal();
    }
  }
</script>

{#if shownMs !== null}
  <div class="expiry" role="group" aria-label="Access length" onkeydown={onKeydown}>
    {#if compactOn}
      <p class="expiry-once-note" id="{uid}-compact-caution" data-testid="approval-expiry-compact-caution">{#if cautionParts}{cautionParts.before}<span class="secret-name">{cautionParts.run}</span>{cautionParts.after}{:else}{compact!.caution}{/if}</p>
      {#if compactToggle !== null}
        <fieldset class="length-toggle" bind:this={onceGroup} data-testid="approval-expiry-toggle" aria-describedby="{uid}-compact-caution {uid}-compact-end">
          <legend class="sr-only">{SECRET_BLOCK_COPY.groupName}</legend>
          <span class="length-segments">
          {#each compactChoices as choice (choice.ms)}
            <label class="length-option" title={choice.name}>
              <input
                type="radio"
                class="length-radio"
                name="{uid}-compact-length"
                aria-label={choice.name}
                checked={shownMs === choice.ms}
                {disabled}
                onchange={() => pickCompact(choice.ms)}
              />
              <span>{choice.label}</span>
            </label>
          {/each}
          </span>
          <span class="length-end" id="{uid}-compact-end" data-testid="approval-expiry-end" aria-hidden="true">{SECRET_BLOCK_COPY.until(endText)}</span>
        </fieldset>
      {/if}
    {/if}
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
    {:else}
      <!-- One live region holds whichever line is showing, so a screen reader hears the line that settles. -->
      <div class="expiry-live" aria-live="polite">
        {#if compactToggle !== null}
          <p class="sr-only" data-testid="approval-expiry-announcement">{SECRET_BLOCK_COPY.lasts(formatLengthWithEnd(shownMs!, endMs))}</p>
        {:else if compactOn}
          <p class="expiry-line" data-testid="approval-expiry-length-line">{SECRET_BLOCK_COPY.lasts(askedHourLine ? formatDuration(shownMs!) : formatLengthWithEnd(shownMs!, endMs))}</p>
        {/if}
        {#if renewalPending && !renewal}
          <p class="expiry-line" data-testid="approval-expiry-line">{RENEWAL_CHECKING_LINE}</p>
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
              {:else if compactOn}
                {SECRET_BLOCK_COPY.renewLabel(formatDuration(proposedLeaseMs))}
              {:else}
                {accessLine}
              {/if}
            </span>
          </label>
        {:else if !compactOn}
          <p class="expiry-line" data-testid="approval-expiry-line">{accessLine}</p>
        {/if}
      </div>
    {/if}
    {#if !compactOn && onceChoice !== null}
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
    {#if lengthNote !== null && !compactOn}
      <p class="expiry-once-note" data-testid="approval-expiry-length-note">{lengthNote}</p>
    {/if}
    {#if chooser}
      <details class="expiry-fold">
        <summary><span>How long it lasts</span> <span class="fold-current" data-testid="approval-expiry-fold-current">{formatDuration(shownMs!)}</span></summary>
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
  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    margin: -1px;
    padding: 0;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
    border: 0;
  }
  /* A secret's name stays on one line; only a name wider than the card breaks, at any point. */
  .secret-name {
    display: inline-block;
    max-width: 100%;
    overflow-wrap: anywhere;
  }
  /* Two segments on one line; each is at least the 40px tap height used by the other choices on this screen. */
  .length-toggle {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px 12px;
    min-width: 0;
    margin: 4px 0 8px;
    padding: 0;
    border: 0;
  }
  .length-segments {
    display: flex;
    min-width: 0;
  }
  .length-end {
    color: #475569;
    font-size: 0.9375rem;
  }
  .length-option {
    position: relative;
    display: flex;
    flex: 0 1 auto;
    min-width: 0;
    cursor: pointer;
  }
  .length-option > span {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 40px;
    padding: 0 14px;
    font-weight: 600;
    color: #0f172a;
    text-align: center;
    background: #fff;
    border: 1px solid #cbd5e1;
  }
  .length-option:first-of-type > span {
    border-radius: 10px 0 0 10px;
  }
  .length-option:last-of-type > span {
    margin-left: -1px;
    border-radius: 0 10px 10px 0;
  }
  .length-radio {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    margin: 0;
    opacity: 0;
    cursor: pointer;
  }
  .length-radio:checked + span {
    color: #fff;
    background: #1d4ed8;
    border-color: #1d4ed8;
    z-index: 1;
  }
  .length-radio:focus-visible + span {
    outline: 2px solid #1d4ed8;
    outline-offset: 2px;
    z-index: 2;
  }
  .length-radio:disabled + span {
    opacity: 0.6;
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
  .expiry-fold > summary .fold-current {
    font-weight: 400;
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
