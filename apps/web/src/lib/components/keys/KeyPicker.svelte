<script lang="ts">
  // TC-1496: the one OpenKey key picker (TC-703 behaviour). With no wallet
  // named and a primary key present it leads with the primary key and keeps
  // every other key behind "Use a different key", with a warning that each key
  // is a separate account owner. Otherwise every key is listed.
  import type { Snippet } from 'svelte';
  import type { EthereumKey } from '$lib/api';
  import { keyPickerLayout } from '$lib/delegate-key-selection';
  import { copyText } from '$lib/clipboard';

  let {
    keys,
    onselect,
    expectedAddress = null,
    overrideMismatch = false,
    selectedId = null,
    compact = false,
    listHeading,
    primaryHeading,
    otherKeysWarning = "Each key is a separate account. Using a different key won't give this app the data in your primary key.",
    showOtherKeys = $bindable(false),
    actions,
  }: {
    keys: EthereumKey[];
    onselect: (key: EthereumKey) => void;
    /** Lower-cased wallet address the request names, if any. */
    expectedAddress?: string | null;
    overrideMismatch?: boolean;
    /** Key to mark as chosen (connect widgets); omit when selection navigates away. */
    selectedId?: string | null;
    compact?: boolean;
    listHeading: string;
    primaryHeading: string;
    otherKeysWarning?: string;
    showOtherKeys?: boolean;
    /** Trailing controls (link wallet, generate key), shown with the full key list. */
    actions?: Snippet;
  } = $props();

  const layout = $derived(keyPickerLayout(keys, expectedAddress));

  let copiedId = $state<string | null>(null);
  let copyStatus = $state('');
</script>

{#snippet keyButton(key: EthereumKey)}
  {@const isExpected = !!expectedAddress && key.address.toLowerCase() === expectedAddress}
  {@const isMismatch = !!expectedAddress && !isExpected}
  {@const isSelected = selectedId === key.id}
  {@const name = key.label || `Key ending ${key.address.slice(-4)}`}
  <div
    class="overflow-hidden rounded-xl border bg-white transition-colors"
    role="group"
    aria-label={name}
    class:border-surface-900={isExpected || isSelected}
    class:bg-surface-50={isExpected || isSelected}
    class:border-surface-200={!isExpected && !isSelected}
    class:hover:border-surface-900={!isMismatch}
    class:opacity-60={isMismatch && !overrideMismatch}
  >
    <button
      type="button"
      class="flex min-h-16 w-full items-center justify-between gap-3 p-4 text-left text-surface-900 transition-colors hover:bg-surface-50 active:bg-surface-100 focus-visible:outline-2 focus-visible:outline-surface-900 disabled:cursor-not-allowed"
      aria-pressed={isSelected}
      title={key.address}
      disabled={isMismatch && !overrideMismatch}
      onclick={() => onselect(key)}
    >
      <span class="min-w-0 flex flex-wrap items-center gap-2 font-medium" class:text-sm={compact}>
        <span class="break-words">{name}</span>
        {#if key.keyType === 'EXTERNAL'}
          <span class="rounded-md bg-surface-100 px-1.5 py-0.5 text-xs font-medium text-surface-500">(External)</span>
        {/if}
        {#if key.isPrimary}
          <span class="rounded-md bg-surface-900 px-1.5 py-0.5 text-xs font-medium text-white">Primary</span>
        {/if}
        {#if isExpected}
          <span class="rounded-md bg-emerald-100 px-1.5 py-0.5 text-xs font-medium text-emerald-700">Requested</span>
        {/if}
      </span>
      <svg class="h-5 w-5 shrink-0 text-surface-700" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" aria-hidden="true">
        <path stroke-linecap="round" stroke-linejoin="round" d={isSelected ? 'M5 12l4 4L19 6' : 'M9 5l7 7-7 7'} />
      </svg>
    </button>
    <div class="flex justify-end px-3 pb-2">
      <button
        type="button"
        class="min-h-11 rounded-lg px-3 text-sm text-surface-600 underline decoration-surface-300 underline-offset-4 hover:bg-surface-50 hover:text-surface-900 focus-visible:outline-2 focus-visible:outline-surface-900"
        title={key.address}
        aria-label="Copy address"
        onclick={async () => {
          const copied = await copyText(key.address);
          copiedId = copied ? key.id : null;
          copyStatus = copied ? 'Address copied.' : 'Could not copy the address.';
        }}
      >
        {copiedId === key.id ? 'Copied' : 'Copy address'}
      </button>
    </div>
  </div>
{/snippet}

{#if layout.kind === 'primary'}
  <div class="flex flex-col gap-3">
    <p class="text-surface-500 text-sm">{primaryHeading}</p>
    {@render keyButton(layout.primary)}
    {#if showOtherKeys}
      <div class="w-full bg-amber-50 border border-amber-200 text-amber-800 px-4 py-3 rounded-xl text-sm" role="note">
        {otherKeysWarning}
      </div>
      {#each layout.others as key (key.id)}
        {@render keyButton(key)}
      {/each}
      {@render actions?.()}
    {:else}
      <button
        type="button"
        class="min-h-11 w-full cursor-pointer rounded-xl border border-surface-300 bg-white px-4 py-3 text-sm font-medium text-surface-900 transition-colors hover:bg-surface-50 focus-visible:outline-2 focus-visible:outline-surface-900"
        onclick={() => (showOtherKeys = true)}
      >
        Use a different key
      </button>
    {/if}
  </div>
{:else}
  <div class="flex flex-col gap-3">
    <p class="text-surface-500 text-sm">{listHeading}</p>
    {#each layout.keys as key (key.id)}
      {@render keyButton(key)}
    {/each}
    {@render actions?.()}
  </div>
{/if}
<p class="sr-only" role="status">{copyStatus}</p>
