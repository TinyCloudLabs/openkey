<script lang="ts">
  // TC-1496: the one OpenKey key picker (TC-703 behaviour). With no wallet
  // named and a primary key present it leads with the primary key and keeps
  // every other key behind "Use a different key", with a warning that each key
  // is a separate account owner. Otherwise every key is listed.
  import type { Snippet } from 'svelte';
  import type { EthereumKey } from '$lib/api';
  import { keyPickerLayout } from '$lib/delegate-key-selection';

  let {
    keys,
    onselect,
    expectedAddress = null,
    overrideMismatch = false,
    selectedId = null,
    compact = false,
    listHeading,
    primaryHeading,
    otherKeysWarning = 'Each key is a separate account owner, with its own data and spaces. Signing in with a different key does not give this app the data in your primary key.',
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

  function formatAddress(address: string): string {
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  }
</script>

{#snippet keyButton(key: EthereumKey)}
  {@const isExpected = !!expectedAddress && key.address.toLowerCase() === expectedAddress}
  {@const isMismatch = !!expectedAddress && !isExpected}
  {@const isSelected = selectedId === key.id}
  <button
    class="flex justify-between items-center bg-white border rounded-xl cursor-pointer transition-all group {compact ? 'p-3.5' : 'p-4'}"
    class:border-surface-900={isExpected || isSelected}
    class:bg-surface-50={isExpected || isSelected}
    class:border-surface-200={!isExpected && !isSelected}
    class:hover:border-surface-900={!isMismatch}
    class:hover:bg-surface-50={!isMismatch}
    class:opacity-60={isMismatch && !overrideMismatch}
    disabled={isMismatch && !overrideMismatch}
    onclick={() => onselect(key)}
  >
    <span class="font-medium flex items-center gap-2" class:text-sm={compact}>
      {key.label || `Key ${key.keyIndex}`}
      {#if key.keyType === 'EXTERNAL'}
        <span class="text-xs font-medium px-1.5 py-0.5 rounded-md bg-surface-100 text-surface-500">(External)</span>
      {/if}
      {#if key.isPrimary}
        <span class="text-xs font-medium px-1.5 py-0.5 rounded-md bg-surface-900 text-white">Primary</span>
      {/if}
      {#if isExpected}
        <span class="text-xs font-medium px-1.5 py-0.5 rounded-md bg-emerald-100 text-emerald-700">Requested</span>
      {/if}
    </span>
    <span class="flex items-center gap-2">
      <code class="font-mono text-surface-400" class:text-sm={!compact} class:text-xs={compact}>{formatAddress(key.address)}</code>
      {#if isSelected}
        <svg class="w-4 h-4 text-surface-900" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" aria-hidden="true">
          <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      {/if}
    </span>
  </button>
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
        class="text-xs text-surface-500 hover:text-surface-900 transition-colors bg-transparent border-none cursor-pointer underline self-start"
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
