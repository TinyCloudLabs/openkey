<script lang="ts">
  // "Approval expires: 7d (Change)" (TC-2272). Shows how long the approval
  // lasts, defaulting to what the app asked for, and lets the user choose
  // another time from a few presets or a typed duration (5600s, 90m, 40d, 1y).
  // It only reports the choice; the server writes it into the signed message.
  import {
    EXPIRY_PRESETS,
    LONG_EXPIRY_MS,
    LONG_EXPIRY_WARNING,
    formatExpiry,
    parseExpiry,
  } from "$lib/approval-expiry";

  interface Props {
    /** How long the app asked for; null when it cannot be worked out. */
    requestedMs: number | null;
    /** The user's choice; null keeps what the app asked for. */
    chosenMs: number | null;
    disabled?: boolean;
    onChange: (ms: number | null) => void;
  }

  let { requestedMs, chosenMs, disabled = false, onChange }: Props = $props();

  let open = $state(false);
  let text = $state("");
  let error = $state("");
  let changeButton = $state<HTMLButtonElement | null>(null);
  let customInput = $state<HTMLInputElement | null>(null);

  const shownMs = $derived(chosenMs ?? requestedMs);
  const typed = $derived(text.trim() === "" ? null : parseExpiry(text));
  const warnMs = $derived(typed?.ok ? typed.ms : shownMs);
  const showWarning = $derived(warnMs !== null && warnMs > LONG_EXPIRY_MS);

  function choose(ms: number) {
    error = "";
    text = "";
    open = false;
    onChange(ms === requestedMs ? null : ms);
    changeButton?.focus();
  }

  function applyTyped() {
    const result = parseExpiry(text);
    if (!result.ok) {
      error = result.message;
      customInput?.focus();
      return;
    }
    choose(result.ms);
  }

  function close() {
    open = false;
    error = "";
    changeButton?.focus();
  }

  function onKeydown(event: KeyboardEvent) {
    if (event.key === "Escape" && open) {
      event.stopPropagation();
      close();
    }
  }
</script>

{#if shownMs !== null}
  <div class="expiry" role="group" aria-label="Approval expiry" onkeydown={onKeydown}>
    <p class="expiry-line">
      <span class="expiry-label">Approval expires:</span>
      <span class="expiry-value" data-testid="approval-expiry-value">{formatExpiry(shownMs)}</span>
      <button
        type="button"
        class="expiry-change"
        bind:this={changeButton}
        aria-expanded={open}
        aria-controls="approval-expiry-panel"
        {disabled}
        onclick={() => (open = !open)}
      >
        (Change)
      </button>
    </p>
    {#if open}
      <div class="expiry-panel" id="approval-expiry-panel">
        <div class="expiry-presets" role="group" aria-label="Preset times">
          {#each EXPIRY_PRESETS as preset (preset.label)}
            <button
              type="button"
              class="expiry-preset"
              aria-pressed={shownMs === preset.ms}
              onclick={() => choose(preset.ms)}
            >
              {preset.label}
            </button>
          {/each}
        </div>
        <form
          class="expiry-custom"
          onsubmit={(event) => {
            event.preventDefault();
            applyTyped();
          }}
        >
          <label class="expiry-custom-label" for="approval-expiry-custom">Or type a time</label>
          <div class="expiry-custom-row">
            <input
              id="approval-expiry-custom"
              class="expiry-input"
              type="text"
              inputmode="text"
              autocomplete="off"
              autocapitalize="off"
              spellcheck="false"
              placeholder="5600s, 90m, 40d, 1y"
              bind:this={customInput}
              bind:value={text}
              oninput={() => (error = "")}
              aria-invalid={error ? "true" : undefined}
              aria-describedby={error ? "approval-expiry-error" : undefined}
            />
            <button type="submit" class="expiry-set">Set</button>
          </div>
          {#if error}
            <p class="expiry-error" id="approval-expiry-error" role="alert">{error}</p>
          {/if}
        </form>
      </div>
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
  .expiry-line {
    margin: 0;
    overflow-wrap: anywhere;
  }
  .expiry-value {
    font-weight: 600;
    color: #0f172a;
  }
  .expiry-change {
    background: none;
    border: 0;
    padding: 6px 4px;
    margin: -6px 0;
    font: inherit;
    color: #1d4ed8;
    cursor: pointer;
    text-decoration: underline;
    min-height: 32px;
  }
  .expiry-change:disabled {
    color: #94a3b8;
    cursor: not-allowed;
  }
  .expiry-panel {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 10px 12px;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
  }
  .expiry-presets {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }
  .expiry-preset,
  .expiry-set {
    min-height: 40px;
    min-width: 56px;
    padding: 0 12px;
    font: inherit;
    font-weight: 600;
    color: #0f172a;
    background: #fff;
    border: 1px solid #cbd5e1;
    border-radius: 10px;
    cursor: pointer;
  }
  .expiry-preset[aria-pressed="true"] {
    border-color: #1d4ed8;
    box-shadow: inset 0 0 0 1px #1d4ed8;
  }
  .expiry-custom {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .expiry-custom-label {
    font-size: 12px;
    font-weight: 600;
  }
  .expiry-custom-row {
    display: flex;
    gap: 8px;
  }
  .expiry-input {
    flex: 1;
    min-width: 0;
    min-height: 40px;
    padding: 0 10px;
    /* 16px keeps iOS from zooming the page when the box is focused. */
    font-size: 16px;
    border: 1px solid #cbd5e1;
    border-radius: 10px;
    box-sizing: border-box;
  }
  .expiry-input[aria-invalid="true"] {
    border-color: #b91c1c;
  }
  .expiry-error {
    margin: 0;
    color: #b91c1c;
  }
  .expiry-warning {
    margin: 0;
    padding: 6px 10px;
    color: #92400e;
    background: #fffbeb;
    border: 1px solid #fde68a;
    border-radius: 10px;
  }
  .expiry :is(button, input):focus-visible {
    outline: 2px solid #1d4ed8;
    outline-offset: 2px;
  }
</style>
