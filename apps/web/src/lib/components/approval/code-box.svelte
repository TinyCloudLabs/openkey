<script lang="ts">
  // The code page: say where the code goes, show it alone in a big box, and copy it on a click of the box or of
  // the Copy button. A short code counts down from five minutes; when it runs out the page says so instead.
  import { onMount } from 'svelte';
  import { copyText } from '$lib/clipboard';
  import Icon from '$lib/components/approval/icon.svelte';
  import SpaceNote from '$lib/components/approval/space-note.svelte';
  import { focusHeading } from '$lib/components/approval/focus-heading';
  import Button from '$lib/components/ui/button.svelte';
  import CloseTabButton from '$lib/components/ui/close-tab-button.svelte';
  import type { CodeCountdownSnapshot } from '$lib/delegate-code-countdown';
  import type { SpaceReadiness } from '$lib/delegate-space-setup';
  import { CODE, STOP_PARTS, codeDestinationWord, fill, type CodeDestination } from '@openkey/sdk/approval-copy';

  interface Props {
    /** The short code. Empty when OpenKey could not make one: the full code is then the only code. */
    shortCode?: string;
    /** The full code, always there. */
    fullCode: string;
    /** The small line above the heading. */
    eyebrow: string;
    /** The line under the heading. */
    line: string;
    destination?: CodeDestination;
    /** The short code's countdown. Null: no clock to count with. */
    countdown?: CodeCountdownSnapshot | null;
    /** A screen-reader line from the countdown. */
    announcement?: string;
    /** The short code ran out: the page says so and nothing can be copied. */
    expired?: boolean;
    /** The full code is shown in place of the short one. */
    showFull?: boolean;
    /** Status and code of the reply that went wrong, for support. */
    support?: string;
    spaceNote?: SpaceReadiness | null;
  }

  let {
    shortCode = '',
    fullCode,
    eyebrow,
    line,
    destination = 'terminal',
    countdown = null,
    announcement = '',
    expired = false,
    showFull = $bindable(false),
    support = '',
    spaceNote = null,
  }: Props = $props();

  const CODE_LIFETIME_MS = 300_000;
  const COPIED_MS = 2000;

  const where = $derived(codeDestinationWord(destination));
  const full = $derived(!shortCode || showFull);
  const code = $derived(full ? fullCode : shortCode);
  let copied = $state(false);
  let copyFailed = $state(false);
  let copiedTimer: ReturnType<typeof setTimeout> | undefined;
  // A phone has no pointer to click with.
  let touch = $state(false);

  onMount(() => {
    touch = window.matchMedia('(pointer: coarse)').matches;
    return () => clearTimeout(copiedTimer);
  });

  async function copy() {
    clearTimeout(copiedTimer);
    if (!(await copyText(code))) {
      copied = false;
      copyFailed = true;
      return;
    }
    copyFailed = false;
    copied = true;
    copiedTimer = setTimeout(() => { copied = false; }, COPIED_MS);
  }

  function openFull() {
    clearTimeout(copiedTimer);
    copied = false;
    copyFailed = false;
    showFull = true;
  }

  const hint = $derived(
    full ? fill(CODE.hintFull, { n: fullCode.length.toLocaleString('en-US') }) : touch ? CODE.hintShortPhone : CODE.hintShort,
  );
  const meter = $derived(countdown ? Math.min(1, Math.max(0, countdown.remainingMs / CODE_LIFETIME_MS)) : 0);
  const eyebrowClass = 'm-0 mb-2.5 text-[11.5px] font-semibold tracking-[0.09em] text-surface-500 uppercase';
  const headingClass = 'm-0 mb-2.5 text-[25px] leading-[1.17] font-bold tracking-[-0.012em] text-balance text-surface-950';
  const shortCodeClass = 'font-mono text-[34px] leading-[1.1] font-[650] tracking-[0.1em] whitespace-nowrap pl-[0.1em]';
  const fullCodeClass = 'max-h-[92px] overflow-hidden font-mono text-xs leading-[1.55] break-all text-surface-700 [mask-image:linear-gradient(#000_55%,transparent)]';
</script>

{#if expired}
  <p class={eyebrowClass}>{CODE.expired.eyebrow}</p>
  <h1 use:focusHeading class={headingClass}>{CODE.expired.heading}</h1>
  <p class="m-0 mb-3.5 text-pretty">{CODE.expired.line}</p>
  <div class="mt-2 mb-3 grid w-full justify-items-center gap-2.5 rounded-2xl border border-dashed border-surface-300 bg-surface-50 px-3.5 pt-[26px] pb-4" data-code-box>
    <span class="{shortCodeClass} text-surface-400 line-through">{shortCode}</span>
    <span class="text-[12.5px] text-surface-500">{CODE.expired.box}</span>
  </div>
  <CloseTabButton allowBack />
{:else}
  <p class={eyebrowClass}>{eyebrow}</p>
  <h1 use:focusHeading class={headingClass}>{fill(full ? CODE.headingFull : CODE.headingShort, { destination: where })}</h1>
  <p class="m-0 mb-3.5 text-pretty">{line}</p>

  {#if copyFailed}
    <!-- The copy did not work: the code is plain text the person can select. -->
    <div class="mt-2 mb-3 grid w-full gap-2.5 rounded-2xl border border-surface-300 bg-surface-50 px-3.5 py-4 {full ? 'text-left' : 'justify-items-center'}" data-code-box>
      <span class="select-all {full ? 'font-mono text-xs leading-[1.55] break-all text-surface-700' : `${shortCodeClass} text-surface-950`}">{code}</span>
    </div>
  {:else}
    <button
      type="button"
      data-code-box
      class="mt-2 mb-3 grid w-full cursor-pointer gap-2.5 rounded-2xl border transition-colors {copied ? 'border-[#157f3c] bg-green-wash' : 'border-surface-300 bg-surface-50 hover:border-surface-950 hover:bg-white'} {full ? 'justify-items-stretch px-3.5 pt-3.5 pb-3 text-left' : 'justify-items-center px-3.5 pt-[26px] pb-4'}"
      onclick={copy}
    >
      <span class="{full ? fullCodeClass : `${shortCodeClass} text-surface-950`}">{code}</span>
      <span class="inline-flex items-center gap-1.5 justify-self-center text-[12.5px] {copied ? 'font-[650] text-[#157f3c]' : 'text-surface-500'}">
        <Icon name={copied ? 'check' : 'copy'} class="h-3.5 w-3.5" />
        {copied ? fill(CODE.hintCopied, { destination: where }) : hint}
      </span>
    </button>
  {/if}
  {#if copyFailed}
    <p role="alert" class="m-0 mb-3 w-full text-left text-[13px] leading-normal text-[#b42318]">{CODE.copyFailed}</p>
  {/if}

  <div class="w-full">
    {#if !full}
      {#if countdown}
        <div role="timer" aria-live="off" class="mx-0.5 mb-1.5 flex justify-between text-[13px] text-surface-700">
          <span class="tabular-nums">{countdown.text}</span>
          <span>{CODE.worksOnce}</span>
        </div>
        <div class="mb-[18px] h-[3px] overflow-hidden rounded-[3px] bg-surface-200" aria-hidden="true">
          <i class="block h-full bg-surface-950" style:width="{meter * 100}%"></i>
        </div>
      {:else}
        <div class="mx-0.5 mb-[18px] flex justify-between text-[13px] text-surface-700">
          <span>{CODE.timerNoClock}</span>
          <span>{CODE.worksOnce}</span>
        </div>
      {/if}
      <p class="sr-only" role="status" aria-live="polite">{announcement}</p>
    {/if}

    <Button class="w-full" onclick={copy}>
      <Icon name={copied ? 'check' : 'copy'} class="h-4 w-4 {copied ? 'text-[#4ade80]' : ''}" />
      {copied ? CODE.copied : full ? CODE.copyFull : CODE.copy}
    </Button>
    <p class="sr-only" role="status" aria-live="polite">{copied ? CODE.copied : ''}</p>

    <p class="mt-3.5 mb-0 grid grid-cols-[16px_1fr] gap-[9px] text-left text-[13px] leading-[1.45] text-surface-500">
      <Icon name="alert" class="mt-px h-4 w-4" />
      <span>{fill(full ? CODE.warningShort : CODE.warning, { destination: where })}</span>
    </p>

    {#if spaceNote}
      <SpaceNote note={spaceNote} />
    {/if}

    <div class="mt-3.5 flex flex-wrap items-center justify-center gap-x-1.5 text-[13px] leading-normal text-surface-500">
      {#if !full}
        <button type="button" class="cursor-pointer border-0 bg-transparent p-0 font-semibold text-surface-950 underline decoration-surface-300 underline-offset-[3px]" onclick={openFull}>{CODE.useFull}</button>
        <span aria-hidden="true">·</span>
      {/if}
      <CloseTabButton allowBack look="link" />
    </div>
  </div>

  {#if support}
    <p class="mt-6 mb-0 flex w-full flex-wrap items-baseline justify-between gap-2 border-t border-surface-200 pt-3 text-left text-xs text-surface-500">
      <span>{STOP_PARTS.supportLabel}</span>
      <code class="font-mono text-[11.5px] text-surface-700" data-support-line>{support}</code>
    </p>
  {/if}
{/if}
