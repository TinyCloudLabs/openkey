<script lang="ts">
  // One "how long" choice inside the approval line's fold (TC-2933): a few
  // presets and a typed time (5600s, 90m, 40d, 1y), refused above `maxMs`.
  import { formatDuration, parseExpiry } from "$lib/approval-expiry";

  interface Props {
    id: string;
    legend: string;
    presets: ReadonlyArray<{ label: string; ms: number }>;
    valueMs: number;
    /** The longest allowed; null when any time may be picked. */
    maxMs: number | null;
    limitNote: (maxMs: number) => string;
    disabled?: boolean;
    onChoose: (ms: number) => void;
    /** Shown after the chosen length, e.g. the exact end date. */
    detail?: string | null;
  }

  let { id, legend, presets, valueMs, maxMs, limitNote, disabled = false, onChoose, detail = null }: Props = $props();

  let text = $state("");
  let error = $state("");
  let input = $state<HTMLInputElement | null>(null);

  const shown = $derived(presets.filter((preset) => maxMs == null || preset.ms <= maxMs));

  function choose(ms: number) {
    error = "";
    text = "";
    onChoose(ms);
  }

  function applyTyped() {
    const result = parseExpiry(text);
    if (!result.ok) {
      error = result.message;
      input?.focus();
      return;
    }
    if (maxMs != null && result.ms > maxMs) {
      error = limitNote(maxMs);
      input?.focus();
      return;
    }
    choose(result.ms);
  }
</script>

<fieldset class="choice" aria-describedby={error ? `${id}-error` : undefined}>
  <legend class="choice-legend">{legend} <span class="choice-value">{formatDuration(valueMs)}</span>{#if detail}<span class="choice-detail">{` · ${detail}`}</span>{/if}</legend>
  <div class="choice-presets">
    {#each shown as preset (preset.label)}
      <button
        type="button"
        class="choice-preset"
        {disabled}
        aria-pressed={valueMs === preset.ms}
        onclick={() => choose(preset.ms)}
      >
        {preset.label}
      </button>
    {/each}
  </div>
  <form
    class="choice-custom"
    onsubmit={(event) => {
      event.preventDefault();
      applyTyped();
    }}
  >
    <label class="choice-custom-label" for={`${id}-custom`}>Or type a time</label>
    <div class="choice-custom-row">
      <input
        id={`${id}-custom`}
        class="choice-input"
        {disabled}
        type="text"
        inputmode="text"
        autocomplete="off"
        autocapitalize="off"
        spellcheck="false"
        placeholder="e.g. 40d"
        bind:this={input}
        bind:value={text}
        oninput={() => (error = "")}
        aria-invalid={error ? "true" : undefined}
        aria-describedby={error ? `${id}-error` : undefined}
      />
      <button type="submit" class="choice-set" {disabled}>Set</button>
    </div>
    {#if error}
      <p class="choice-error" id={`${id}-error`} role="alert">{error}</p>
    {/if}
  </form>
</fieldset>

<style>
  .choice {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin: 0;
    padding: 0;
    border: 0;
    min-width: 0;
  }
  .choice-legend {
    padding: 0;
    margin-bottom: 8px;
    font-size: 12px;
    font-weight: 600;
    color: #334155;
  }
  .choice-value,
  .choice-detail {
    font-weight: 400;
    color: #475569;
  }
  .choice-presets {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }
  .choice-preset,
  .choice-set {
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
  .choice-preset[aria-pressed="true"] {
    border-color: #1d4ed8;
    box-shadow: inset 0 0 0 1px #1d4ed8;
  }
  .choice-custom {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .choice-custom-label {
    font-size: 12px;
  }
  .choice-custom-row {
    display: flex;
    gap: 8px;
  }
  .choice-input {
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
  .choice-input[aria-invalid="true"] {
    border-color: #b91c1c;
  }
  .choice-error {
    margin: 0;
    color: #b91c1c;
  }
  .choice :is(button, input):focus-visible {
    outline: 2px solid #1d4ed8;
    outline-offset: 2px;
  }
</style>
